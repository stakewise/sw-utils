import asyncio
from typing import Any, Callable, Optional

from gql.transport.exceptions import TransportServerError
from tenacity import (
    retry,
    retry_if_exception,
    retry_if_exception_type,
    stop_after_delay,
    wait_exponential,
)

from sw_utils.decorators import default_log_before


def retry_gql_errors(delay: int, before: Optional[Callable] = None) -> Any:
    # built-in TimeoutError may raise when establishing connection
    # asyncio.TimeoutError may raise when connection is ready, request is sent,
    # and we are waiting for response
    return retry(
        retry=(
            retry_if_exception_type((TimeoutError, asyncio.TimeoutError))
            | retry_if_exception(_is_server_error)
        ),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
    )


def _is_server_error(exception: BaseException) -> bool:
    """
    `TransportServerError` is raised by `gql` when http status is either 4xx or 5xx.
    We consider it a server error if the status code is 500 or higher.
    """
    return (
        isinstance(exception, TransportServerError)
        and isinstance(exception.code, int)
        and exception.code >= 500
    )
