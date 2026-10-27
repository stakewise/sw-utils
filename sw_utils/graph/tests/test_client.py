import logging
from unittest.mock import AsyncMock, patch

import pytest
from gql import GraphQLRequest, gql
from gql.transport.exceptions import TransportServerError
from graphql import parse

from sw_utils.graph.client import GraphClient

QUERY = """
    query exitRequests($first: Int, $skip: Int, $lastID: String) {
      exitRequests(first: $first, skip: $skip, where: {id_gt: $lastID}) {
        id
      }
    }
"""


@pytest.fixture
def sleep_mock():
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock:
        yield mock


def _client(**kwargs) -> GraphClient:
    client = GraphClient(endpoint='https://graph', **kwargs)
    client.session = AsyncMock()
    return client


def _requests(client: GraphClient) -> list[GraphQLRequest]:
    return [c.args[0] for c in client.session.execute.await_args_list]


class TestRunQuery:
    async def test_session_not_initialized(self):
        client = GraphClient(endpoint='https://graph')

        with pytest.raises(RuntimeError):
            await client.run_query(gql(QUERY))

    @pytest.mark.parametrize('query', [gql(QUERY), parse(QUERY)])
    async def test_passes_variables(self, query):
        client = _client()
        client.session.execute.return_value = {'exitRequests': []}

        result = await client.run_query(query, {'first': 10})

        assert result == {'exitRequests': []}
        [request] = _requests(client)
        assert isinstance(request, GraphQLRequest)
        assert request.variable_values == {'first': 10}
        assert request.document.definitions[0].name.value == 'exitRequests'

    async def test_retries_server_error(self, sleep_mock, caplog):
        client = _client()
        client.session.execute.side_effect = [
            TransportServerError('bad gateway', 502),
            {'exitRequests': []},
        ]

        with caplog.at_level(logging.INFO, logger='sw_utils.graph.client'):
            result = await client.run_query(gql(QUERY))

        assert result == {'exitRequests': []}
        assert client.session.execute.await_count == 2
        assert caplog.messages == ['Retrying exitRequests graph query, attempt 2']


class TestFetchPages:
    items = [{'id': str(i)} for i in range(5)]

    @pytest.fixture(autouse=True)
    def _setup(self):
        # fetch_pages reuses the params dict, so variables are copied at request time
        self.variables: list[dict] = []

    def _paginate(self, request: GraphQLRequest) -> dict:
        variables = dict(request.variable_values)
        self.variables.append(variables)
        if 'lastID' in variables:
            items = [i for i in self.items if i['id'] > variables['lastID']]
        else:
            items = self.items[variables['skip'] :]
        return {'exitRequests': items[: variables['first']]}

    async def test_cursor_pagination(self):
        client = _client()
        client.session.execute.side_effect = self._paginate
        params = {'block': 1}

        result = await client.fetch_pages(
            gql(QUERY), params, page_size=2, cursor_pagination=True
        )

        assert result == self.items
        assert self.variables == [
            {'block': 1, 'first': 2, 'lastID': ''},
            {'block': 1, 'first': 2, 'lastID': '1'},
            {'block': 1, 'first': 2, 'lastID': '3'},
        ]
        assert params == {'block': 1}

    async def test_skip_pagination(self):
        client = _client(page_size=2)
        client.session.execute.side_effect = self._paginate

        result = await client.fetch_pages(gql(QUERY))

        assert result == self.items
        assert [v['skip'] for v in self.variables] == [0, 2, 4]

    async def test_full_last_page(self):
        client = _client()
        client.session.execute.side_effect = self._paginate

        result = await client.fetch_pages(gql(QUERY), page_size=5, cursor_pagination=True)

        assert result == self.items
        # a full page requires one more request to confirm there are no more items
        assert client.session.execute.await_count == 2
