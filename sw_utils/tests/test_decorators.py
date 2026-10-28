import asyncio
import logging
from unittest.mock import AsyncMock, Mock, call, patch

import aiohttp
import pytest

from sw_utils.decorators import (
    can_be_retried_aiohttp_error,
    retry_aiohttp_errors,
    retry_ipfs_exception,
)
from sw_utils.exceptions import IpfsException


@pytest.fixture
def sleep_mock():
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock:
        yield mock


def _response_error(status: int) -> aiohttp.ClientResponseError:
    return aiohttp.ClientResponseError(request_info=Mock(), history=(), status=status)


@pytest.mark.parametrize(
    'error, expected',
    [
        (asyncio.TimeoutError(), True),
        (aiohttp.ClientConnectionError(), True),
        (_response_error(500), True),
        (_response_error(503), True),
        (_response_error(404), False),
        (_response_error(429), False),
        (ValueError(), False),
    ],
)
def test_can_be_retried_aiohttp_error(error, expected):
    assert can_be_retried_aiohttp_error(error) is expected


class TestRetryAiohttpErrors:
    async def test_retries_until_success(self, sleep_mock):
        func = AsyncMock(
            side_effect=[aiohttp.ClientConnectionError(), _response_error(502), 'ok'],
        )

        result = await retry_aiohttp_errors(delay=60)(func)()

        assert result == 'ok'
        assert func.await_count == 3
        # exponential backoff: 1s, 2s
        assert sleep_mock.await_args_list == [call(1), call(2)]

    async def test_does_not_retry_client_error(self, sleep_mock):
        func = AsyncMock(side_effect=_response_error(404))

        with pytest.raises(aiohttp.ClientResponseError):
            await retry_aiohttp_errors(delay=60)(func)()

        assert func.await_count == 1
        sleep_mock.assert_not_awaited()

    async def test_reraises_original_error_after_delay(self, sleep_mock):
        func = AsyncMock(side_effect=aiohttp.ClientConnectionError())

        with pytest.raises(aiohttp.ClientConnectionError):
            await retry_aiohttp_errors(delay=0)(func)()

        assert func.await_count == 1

    async def test_custom_before(self, sleep_mock):
        func = AsyncMock(side_effect=[aiohttp.ClientConnectionError(), 'ok'])
        attempts = []

        def before(retry_state):
            attempts.append(retry_state.attempt_number)

        await retry_aiohttp_errors(delay=60, before=before)(func)()

        assert attempts == [1, 2]


class TestRetryIpfsException:
    async def test_retries_until_success(self, sleep_mock):
        func = AsyncMock(side_effect=[IpfsException('a'), IpfsException('b'), 'ok'])

        result = await retry_ipfs_exception(delay=60)(func)()

        assert result == 'ok'
        assert func.await_count == 3
        assert sleep_mock.await_args_list == [call(1), call(2)]

    async def test_does_not_retry_other_errors(self, sleep_mock):
        func = AsyncMock(side_effect=ValueError())

        with pytest.raises(ValueError):
            await retry_ipfs_exception(delay=60)(func)()

        assert func.await_count == 1
        sleep_mock.assert_not_awaited()

    async def test_reraises_original_error_after_delay(self, sleep_mock):
        func = AsyncMock(side_effect=IpfsException('a'))

        with pytest.raises(IpfsException):
            await retry_ipfs_exception(delay=0)(func)()

        assert func.await_count == 1


async def test_default_log_before(sleep_mock, caplog):
    calls = 0

    async def fetch():
        nonlocal calls
        calls += 1
        if calls == 1:
            raise IpfsException('a')
        return 'ok'

    with caplog.at_level(logging.INFO, logger='sw_utils.decorators'):
        await retry_ipfs_exception(delay=60)(fetch)()

    assert caplog.messages == ['Retrying fetch, attempt 2']
