import asyncio
from typing import Any, Callable, Optional

from gql.transport.exceptions import TransportError
from tenacity import retry, retry_if_exception_type, stop_after_delay, wait_exponential

from sw_utils.decorators import default_log_before


def retry_gql_errors(delay: int, before: Optional[Callable] = None) -> Any:
    # built-in TimeoutError may raise when establishing connection
    # asyncio.TimeoutError may raise when connection is ready, request is sent,
    # and we are waiting for response
    # TransportError raises when server returns status 500
    return retry(
        retry=retry_if_exception_type((TimeoutError, TransportError, asyncio.TimeoutError)),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
    )
