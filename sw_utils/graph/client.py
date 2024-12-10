from gql import Client
from gql.transport.aiohttp import AIOHTTPTransport
from graphql import DocumentNode

from sw_utils.graph.decorators import retry_gql_errors


class GraphClient:
    def __init__(self, endpoint: str, request_timeout: int = 10, retry_timeout: int = 60):
        self.endpoint = endpoint
        self.request_timeout = request_timeout
        self.retry_timeout = retry_timeout

        transport = AIOHTTPTransport(url=endpoint, timeout=self.request_timeout)
        self.gql_client = Client(transport=transport)

    async def run_query(self, query: DocumentNode, params: dict | None = None) -> dict:
        retry_decorator = retry_gql_errors(delay=self.retry_timeout)
        result = await retry_decorator(self.gql_client.execute_async)(query, variable_values=params)
        return result


async def graph_fetch_pages(
    graph_client: GraphClient,
    query: DocumentNode,
    page_size: int,
    query_name: str,
    params: dict | None = None,
) -> list[dict] | None:
    """
    Fetches all pages of the query. Returns concatenated result.
    """
    skip = 0  # page offset
    all_items = []
    params = params.copy() if params else {}

    while True:
        params.update({'first': page_size, 'skip': skip})
        res = await graph_client.run_query(query, params)

        items = res[query_name]
        all_items.extend(items)

        if len(items) < page_size:
            break

        skip += page_size

    return all_items
