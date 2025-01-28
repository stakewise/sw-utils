from eth_typing import BlockNumber
from gql import Client, gql
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

    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        retry_decorator = retry_gql_errors(delay=self.retry_timeout)
        result = await retry_decorator(self.gql_client.execute_async)(query, variable_values=params)
        return result

    async def fetch_pages(
        self,
        query: DocumentNode,
        params: dict | None = None,
        page_size: int | None = None,
    ) -> list[dict]:
        """
        Fetches all pages of the query. Returns concatenated result.
        """
        if page_size is None:
            page_size = self.page_size

        params = params.copy() if params else {}

        skip = 0  # page offset
        all_items = []

        while True:
            params.update({'first': page_size, 'skip': skip})
            res = await self.run_query(query, params)

            entity = list(res.keys())[0]
            items = res[entity]
            all_items.extend(items)

            if len(items) < page_size:
                break

            skip += page_size

        return all_items

    async def get_finalized_block(self) -> BlockNumber:
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
