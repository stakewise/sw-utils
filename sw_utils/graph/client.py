import logging
from typing import cast

from eth_typing import BlockNumber
from gql import Client, gql
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode

from sw_utils.graph.decorators import can_be_retried_graphql_error, retry_gql_errors

logger = logging.getLogger(__name__)


class GraphClient:
    def __init__(
        self,
        endpoints: list[str],
        request_timeout: int = 10,
        retry_timeout: int = 60,
        page_size: int = 100,
    ) -> None:
        self.endpoints = endpoints
        self.request_timeout = request_timeout
        self.retry_timeout = retry_timeout
        self.page_size = page_size
        self.gql_clients = []
        for endpoint in endpoints:
            transport = AIOHTTPTransport(url=endpoint, timeout=self.request_timeout)
            self.gql_clients.append(Client(transport=transport))

    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        retry_decorator = retry_gql_errors(delay=self.retry_timeout)
        result = await retry_decorator(self.run_query_inner)(query, variable_values=params)
        return result

    async def run_query_inner(self, query: DocumentNode, params: dict | None = None) -> dict:
        for i, gql_client in enumerate(self.gql_clients):
            try:
                return await gql_client.execute_async(query, variable_values=params)
            except Exception as error:
                if not can_be_retried_graphql_error(error):
                    raise error

                if i == len(self.gql_clients) - 1:
                    raise error
                transport = cast(AIOHTTPTransport, gql_client.transport)
                logger.warning('%s: %s', transport.url, repr(error))

        return {}

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
