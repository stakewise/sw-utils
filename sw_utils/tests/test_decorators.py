from unittest.mock import Mock

import aiohttp
import pytest
from aiohttp import ClientResponseError

from sw_utils.decorators import backoff_aiohttp_errors


class TestBackoffConnectionErrors:
    def test_bad_request_http_error(self):
        call_count = 0

        @backoff_aiohttp_errors(max_tries=2, max_time=2)
        def raise_bad_request_http_error():
            nonlocal call_count
            call_count += 1

            # simulate aiohttp.ClientResponse.raise_for_status
            raise ClientResponseError(
                Mock(),
                (Mock(), ),
                status=400,
                message='',
                headers={},
            )

        with pytest.raises(ClientResponseError):
            raise_bad_request_http_error()

        assert call_count == 1

    def test_timeout_error(self):
        call_count = 0

        @backoff_aiohttp_errors(max_tries=2, max_time=1)
        def raise_timeout_error():
            nonlocal call_count
            call_count += 1

            raise aiohttp.ServerTimeoutError

        with pytest.raises(aiohttp.ServerTimeoutError):
            raise_timeout_error()

        assert call_count == 2
