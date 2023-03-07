from functools import wraps
from typing import Type

import aiohttp
import backoff

aiohttp_errors = (
    aiohttp.ClientConnectionError,
    aiohttp.ClientConnectorError,
    aiohttp.ServerConnectionError,
)


def backoff_aiohttp_errors(
        max_tries: int | None = None,
        max_time: int | None = None,
        **kwargs
):
    """
    Motivation: retry only connection errors.
    Do not retry on getting HTTP 400 or 500 errors.
    Do not retry on regular Python errors.
    """
    return backoff.on_exception(
        backoff.expo,
        aiohttp_errors,
        max_tries=max_tries,
        max_time=max_time,
        **kwargs
    )


def backoff_in_method(
        exception: Type[Exception] | tuple[Type[Exception], ...],
        max_tries_attr: str = None,
        max_time_attr: str = None
):
    """
    `backoff_in_method` allows to configure backoff/retry params on class level.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            max_tries = None
            if max_tries_attr:
                max_tries = getattr(self, max_tries_attr, None)

            max_time = None
            if max_time_attr:
                max_time = getattr(self, max_time_attr, None)

            return backoff.on_exception(
                backoff.expo,
                exception,
                max_tries=max_tries,
                max_time=max_time
            )(f)(self, *args, **kwargs)

        return wrapper

    return decorator
