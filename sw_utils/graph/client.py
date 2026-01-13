from eth_typing import BlockNumber
from gql import Client, gql
from gql.client import AsyncClientSession
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode

from sw_utils.graph.decorators import retry_gql_errors


class GraphClient:
    def __init__(
        self,
        endpoint: str,
        request_timeout: int = 10,
        retry_timeout: int = 60,
        page_size: int = 100,
    ) -> None:
        self.endpoint = endpoint
        self.request_timeout = request_timeout
        self.retry_timeout = retry_timeout
        self.page_size = page_size

        transport = AIOHTTPTransport(url=endpoint, timeout=self.request_timeout)
        self.gql_client = Client(transport=transport)
        self.session: AsyncClientSession | None = None

    async def setup(self) -> None:
        self.session = await self.gql_client.connect_async(reconnecting=True)

    async def disconnect(self) -> None:
        await self.gql_client.close_async()

    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        if not self.session:
            raise RuntimeError("GraphClient session is not initialized. Call 'setup' first.")
        retry_decorator = retry_gql_errors(delay=self.retry_timeout)
        result = await retry_decorator(self.session.execute)(query, variable_values=params)
        return result

    async def fetch_pages(
        self,
        query: DocumentNode,
        params: dict | None = None,
        page_size: int | None = None,
        cursor_pagination: bool = False,
    ) -> list[dict]:
        """
        Fetches all pages of the query. Returns concatenated result.
        Supports both offset-based and cursor-based pagination.
        """
        if page_size is None:
            page_size = self.page_size

        params = params.copy() if params else {}

        skip = 0
        last_id = ''
        all_items = []
        while True:
            if cursor_pagination:
                params.update({'first': page_size, 'lastID': last_id})
            else:
                params.update({'first': page_size, 'skip': skip})
                skip += page_size
            res = await self.run_query(query, params)
            entity = list(res.keys())[0]
            items = res[entity]
            all_items.extend(items)

            if len(items) < page_size:
                break

            if cursor_pagination:
                last_id = items[-1]['id']
            else:
                skip += page_size

        return all_items

    async def get_last_synced_block(self) -> BlockNumber:
        query = gql(
            """
            query getBlock {
              _meta {
                block {
                  number
                }
              }
            }
        """
        )

        res = await self.run_query(query)
        return BlockNumber(res['_meta']['block']['number'])
