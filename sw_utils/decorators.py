import asyncio
import functools
import logging

import aiohttp
import backoff
import requests

logger = logging.getLogger(__name__)


class RecoverableServerError(Exception):
    """
    Wrapper around ClientResponseError for HTTP 500 errors.
    Only for internal use inside sw-utils library.
    Do not raise `RecoverableServerError` in application code.
    """
    def __init__(self, origin: requests.HTTPError | aiohttp.ClientResponseError):
        self.origin = origin
        if isinstance(origin, requests.HTTPError):
            self.status_code = origin.response.status_code
            self.uri = origin.response.url
        elif isinstance(origin, aiohttp.ClientResponseError):
            self.status_code = origin.status
            self.uri = origin.request_info

        super().__init__()

    def __str__(self):
        return (f'RecoverableServerError (status_code: {self.status_code}, '
            f'uri: {self.uri}): {self.origin}')


def wrap_aiohttp_500_errors(f):
    """
    Allows to distinguish between HTTP 400 and HTTP 500 errors.
    Both are represented by `aiohttp.ClientResponseError`.
    """
    @functools.wraps(f)
    async def wrapper(*args, **kwargs):
        try:
            return await f(*args, **kwargs)
        except aiohttp.ClientResponseError as e:
            if e.status >= 500:
                raise RecoverableServerError(e) from e
            raise
    return wrapper


def backoff_aiohttp_errors(
        max_tries: int | None = None,
        max_time: int | None = None,
        **kwargs
):
    """
    Can be used for:
    * retrying web3 api calls
    * retrying aiohttp calls to services

    DO NOT use `backoff_aiohttp_errors` for handling errors in IpfsFetchClient
    or IpfsMultiUploadClient.
    Catch `sw_utils/ipfs.py#IpfsException` instead.

    Retry:
      * connection errors
      * HTTP 500 errors
    Do not retry:
      * HTTP 400 errors
      * regular Python errors
    """

    backoff_decorator = backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientConnectionError, RecoverableServerError, asyncio.TimeoutError),
        max_tries=max_tries,
        max_time=max_time,
        **kwargs
    )

    def decorator(f):
        @functools.wraps(f)
        async def wrapper(*args, **kwargs):
            try:
                return await backoff_decorator(wrap_aiohttp_500_errors(f))(*args, **kwargs)
            except RecoverableServerError as e:
                raise e.origin

        return wrapper
    return decorator


def wrap_requests_500_errors(f):
    """
    Allows to distinguish between HTTP 400 and HTTP 500 errors.
    Both are represented by `requests.HTTPError`.
    """
    if asyncio.iscoroutinefunction(f):
        @functools.wraps(f)
        async def async_wrapper(*args, **kwargs):
            try:
                return await f(*args, **kwargs)
            except requests.HTTPError as e:
                if e.response.status >= 500:
                    raise RecoverableServerError(e) from e
                raise
        return async_wrapper

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except requests.HTTPError as e:
            if e.response.status >= 500:
                raise RecoverableServerError(e) from e
            raise
    return wrapper


def backoff_requests_errors(
        max_tries: int | None = None,
        max_time: int | None = None,
        **kwargs
):
    """
    DO NOT use `backoff_requests_errors` for handling errors in IpfsFetchClient
    or IpfsMultiUploadClient.
    Catch `sw_utils/ipfs.py#IpfsException` instead.

    Retry:
      * connection errors
      * HTTP 500 errors
    Do not retry:
      * HTTP 400 errors
      * regular Python errors
    """

    backoff_decorator = backoff.on_exception(
        backoff.expo,
        (requests.ConnectionError, requests.Timeout, RecoverableServerError),
        max_tries=max_tries,
        max_time=max_time,
        **kwargs
    )

    def decorator(f):
        if asyncio.iscoroutinefunction(f):
            @functools.wraps(f)
            async def async_wrapper(*args, **kwargs):
                try:
                    return await backoff_decorator(wrap_requests_500_errors(f))(*args, **kwargs)
                except RecoverableServerError as e:
                    raise e.origin
            return async_wrapper

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return backoff_decorator(wrap_requests_500_errors(f))(*args, **kwargs)
            except RecoverableServerError as e:
                raise e.origin
        return wrapper

    return decorator
