import asyncio
from unittest.mock import AsyncMock, call, patch

import pytest
from gql.transport.exceptions import TransportServerError

from sw_utils.graph.decorators import retry_gql_errors


@pytest.fixture
def sleep_mock():
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock:
        yield mock


class TestRetryGqlErrors:
    async def test_retries_until_success(self, sleep_mock):
        func = AsyncMock(
            side_effect=[
                TimeoutError(),
                asyncio.TimeoutError(),
                TransportServerError('bad gateway', 502),
                'ok',
            ],
        )

        result = await retry_gql_errors(delay=60)(func)()

        assert result == 'ok'
        assert func.await_count == 4
        # exponential backoff: 1s, 2s, 4s
        assert sleep_mock.await_args_list == [call(1), call(2), call(4)]

    @pytest.mark.parametrize(
        'error',
        [
            TransportServerError('bad request', 400),
            TransportServerError('no code'),
            ValueError(),
        ],
    )
    async def test_does_not_retry(self, sleep_mock, error):
        func = AsyncMock(side_effect=error)

        with pytest.raises(type(error)):
            await retry_gql_errors(delay=60)(func)()

        assert func.await_count == 1
        sleep_mock.assert_not_awaited()

    async def test_reraises_original_error_after_delay(self, sleep_mock):
        func = AsyncMock(side_effect=TransportServerError('bad gateway', 502))

        with pytest.raises(TransportServerError):
            await retry_gql_errors(delay=0)(func)()

        assert func.await_count == 1
