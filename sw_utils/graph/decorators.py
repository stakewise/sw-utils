import asyncio
from typing import Any, Callable, Optional

from gql.transport.exceptions import TransportServerError
from tenacity import retry, retry_if_exception, stop_after_delay, wait_exponential

from sw_utils.decorators import default_log_before


def retry_gql_errors(delay: int, before: Optional[Callable] = None) -> Any:
    return retry(
        retry=retry_if_exception(can_be_retried_graphql_error),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
    )


def can_be_retried_graphql_error(e: BaseException) -> bool:
    # built-in TimeoutError may raise when establishing connection
    # asyncio.TimeoutError may raise when connection is ready, request is sent,
    # and we are waiting for response
    if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        return True

    if isinstance(e, TransportServerError) and isinstance(e.code, int) and e.code >= 500:
        return True

    return False
