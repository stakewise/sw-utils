import functools

import aiohttp
import backoff
import requests


class RecoverableServerError(Exception):
    """
    Wrapper around ClientResponseError for HTTP 500 errors.
    Only for internal use inside sw-utils library.
    Do not raise `RecoverableServerError` in application code.
    """
    def __init__(self, origin: Exception):
        self.origin = origin
        super().__init__()


def wrap_aiohttp_500_errors(f):
    """
    Allows to distinguish between HTTP 400 and HTTP 500 errors.
    Both are represented by `aiohttp.ClientResponseError`.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
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
    Retry:
      * connection errors
      * HTTP 500 errors
    Do not retry:
      * HTTP 400 errors
      * regular Python errors
    """

    backoff_decorator = backoff.on_exception(
        backoff.expo,
        (aiohttp.ClientConnectionError, RecoverableServerError),
        max_tries=max_tries,
        max_time=max_time,
        **kwargs
    )

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return backoff_decorator(wrap_aiohttp_500_errors(f))(*args, **kwargs)
            except RecoverableServerError as e:
                raise e.origin

        return wrapper
    return decorator


def wrap_requests_500_errors(f):
    """
    Allows to distinguish between HTTP 400 and HTTP 500 errors.
    Both are represented by `requests.HTTPError`.
    """
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
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                return backoff_decorator(wrap_requests_500_errors(f))(*args, **kwargs)
            except RecoverableServerError as e:
                raise e.origin

        return wrapper
    return decorator
