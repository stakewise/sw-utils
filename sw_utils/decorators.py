import asyncio
import logging
import typing

import aiohttp
from tenacity import retry, retry_if_exception, stop_after_delay, wait_exponential

default_logger = logging.getLogger(__name__)


if typing.TYPE_CHECKING:
    from tenacity import RetryCallState


def custom_before_log(logger, log_level):
    def custom_log_it(retry_state: 'RetryCallState') -> None:
        if retry_state.attempt_number <= 1:
            return
        msg = 'Retrying %s, attempt %s'
        args = (retry_state.fn.__name__, retry_state.attempt_number)  # type: ignore
        logger.log(log_level, msg, *args)

    return custom_log_it


def can_be_retried_aiohttp_error(e: BaseException) -> bool:
    if isinstance(e, (asyncio.TimeoutError, aiohttp.ClientConnectionError)):
        return True

    if isinstance(e, aiohttp.ClientResponseError) and e.status >= 500:
        return True

    return False


def retry_aiohttp_errors(delay: int = 60, log_func=custom_before_log):
    return retry(
        retry=retry_if_exception(can_be_retried_aiohttp_error),
        wait=wait_exponential(multiplier=1, min=1, max=delay // 2),
        stop=stop_after_delay(delay),
        before=log_func(default_logger, logging.INFO),
    )
