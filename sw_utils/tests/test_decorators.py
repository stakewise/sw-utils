from unittest.mock import Mock

import aiohttp
import pytest
import requests

from sw_utils.decorators import backoff_aiohttp_errors, backoff_requests_errors


class TestBackoffAiohttpErrors:
    def test_bad_request_http_error(self):
        call_count = 0

        @backoff_aiohttp_errors(max_tries=2, max_time=2)
        def raise_bad_request_http_error():
            nonlocal call_count
            call_count += 1

            # simulate aiohttp.ClientResponse.raise_for_status
            raise aiohttp.ClientResponseError(
                Mock(),
                (Mock(), ),
                status=400,
                message='',
                headers={},
            )

        with pytest.raises(aiohttp.ClientResponseError):
            raise_bad_request_http_error()

        assert call_count == 1

    def test_500_http_error(self):
        call_count = 0

        @backoff_aiohttp_errors(max_tries=2, max_time=2)
        def raise_500_http_error():
            nonlocal call_count
            call_count += 1

            # simulate aiohttp.ClientResponse.raise_for_status
            raise aiohttp.ClientResponseError(
                Mock(),
                (Mock(), ),
                status=500,
                message='',
                headers={},
            )

        with pytest.raises(aiohttp.ClientResponseError):
            raise_500_http_error()

        assert call_count == 2

    def test_recover_500_http_error(self):
        call_count = 0

        @backoff_aiohttp_errors(max_tries=2, max_time=2)
        def recover_500_http_error():
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # simulate aiohttp.ClientResponse.raise_for_status
                raise aiohttp.ClientResponseError(
                    Mock(),
                    (Mock(), ),
                    status=500,
                    message='',
                    headers={},
                )

            return 'Recovered after 500 error'

        recover_500_http_error()

        assert call_count == 2

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


class TestBackoffRequestsErrors:
    def test_bad_request_http_error(self):
        call_count = 0

        @backoff_requests_errors(max_tries=2, max_time=2)
        def raise_bad_request_http_error():
            nonlocal call_count
            call_count += 1

            # simulate requests.Response.raise_for_status()
            response_mock = Mock()
            response_mock.status = 400
            raise requests.HTTPError(
                '400 client error', response=response_mock
            )

        with pytest.raises(requests.HTTPError):
            raise_bad_request_http_error()

        assert call_count == 1

    def test_500_http_error(self):
        call_count = 0

        @backoff_requests_errors(max_tries=2, max_time=2)
        def raise_500_http_error():
            nonlocal call_count
            call_count += 1

            # simulate requests.Response.raise_for_status()
            response_mock = Mock()
            response_mock.status = 500
            raise requests.HTTPError(
                '500 server error', response=response_mock
            )

        with pytest.raises(requests.HTTPError):
            raise_500_http_error()

        assert call_count == 2

    def test_recover_500_http_error(self):
        call_count = 0

        @backoff_requests_errors(max_tries=2, max_time=2)
        def recover_500_http_error():
            nonlocal call_count
            call_count += 1

            if call_count == 1:
                # simulate requests.Response.raise_for_status()
                response_mock = Mock()
                response_mock.status = 500
                raise requests.HTTPError(
                    '500 server error', response=response_mock
                )

            return 'Recovered after 500 error'

        recover_500_http_error()

        assert call_count == 2

    def test_connect_timeout_error(self):
        call_count = 0

        @backoff_requests_errors(max_tries=2, max_time=1)
        def raise_timeout_error():
            nonlocal call_count
            call_count += 1

            raise requests.ConnectTimeout

        with pytest.raises(requests.ConnectTimeout):
            raise_timeout_error()

        assert call_count == 2

    def test_read_timeout_error(self):
        call_count = 0

        @backoff_requests_errors(max_tries=2, max_time=1)
        def raise_timeout_error():
            nonlocal call_count
            call_count += 1

            raise requests.ReadTimeout

        with pytest.raises(requests.ReadTimeout):
            raise_timeout_error()

        assert call_count == 2
