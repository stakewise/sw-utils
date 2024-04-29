import asyncio
import logging
from functools import wraps
from typing import Any, Callable, Optional

import aiohttp
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception,
    retry_if_exception_type,
    stop_after_delay,
    wait_exponential,
)

from sw_utils.exceptions import IpfsException

default_logger = logging.getLogger(__name__)


def safe(func: Callable) -> Callable:
    if asyncio.iscoroutinefunction(func):

        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except BaseException as e:
                default_logger.exception(e)
                return None

    else:

        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except BaseException as e:
                default_logger.exception(e)
                return None

    return wrapper


def default_log_before(retry_state: 'RetryCallState') -> None:
    if retry_state.attempt_number <= 1:
        return
    msg = 'Retrying %s, attempt %s'
    args = (retry_state.fn.__name__, retry_state.attempt_number)  # type: ignore
    default_logger.log(logging.INFO, msg, *args)


def default_after(future: Any) -> NoReturn:
    raise future.outcome.exception()


def can_be_retried_aiohttp_error(e: BaseException) -> bool:
    if isinstance(e, (asyncio.TimeoutError, aiohttp.ClientConnectionError)):
        return True

    if isinstance(e, aiohttp.ClientResponseError) and e.status >= 500:
        return True

    return False


def retry_aiohttp_errors(
    delay: int = 60,
    before: Optional[Callable] = None,
    after: Optional[Callable] = None,
) -> Any:
    return retry(
        retry=retry_if_exception(can_be_retried_aiohttp_error),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
        after=after or default_after,
    )


def retry_ipfs_exception(
    delay: int = 60,
    before: Optional[Callable] = None,
    after: Optional[Callable] = None,
) -> Any:
    return retry(
        retry=retry_if_exception_type(IpfsException),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=before or default_log_before,
        after=after or default_after,
    )
