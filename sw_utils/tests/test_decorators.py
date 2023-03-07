from unittest.mock import Mock

import aiohttp
import pytest
from aiohttp import ClientResponseError

from sw_utils.decorators import backoff_aiohttp_errors, backoff_in_method


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


class TestBackoffInMethod:
    def test_no_exception(self):
        class Example:
            def __init__(self):
                self.call_count = 0
                self.max_tries = 2

            @backoff_in_method(ValueError, max_tries_attr='max_tries')
            def method(self):
                self.call_count += 1

        example = Example()
        example.method()

        assert example.call_count == 1

    def test_basic(self):
        class Example:
            def __init__(self):
                self.call_count = 0
                self.max_tries = 2

            @backoff_in_method(ValueError, max_tries_attr='max_tries')
            def method(self):
                self.call_count += 1
                raise ValueError

        example = Example()

        with pytest.raises(ValueError):
            example.method()

        assert example.call_count == 2

    def test_skip_exception(self):
        class Example:
            def __init__(self):
                self.call_count = 0
                self.max_tries = 2

            @backoff_in_method(ValueError, max_tries_attr='max_tries')
            def method(self):
                self.call_count += 1
                raise RuntimeError

        example = Example()

        with pytest.raises(RuntimeError):
            example.method()

        assert example.call_count == 1
