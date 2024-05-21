import asyncio
import logging
import signal
from typing import Any
from urllib.parse import urlparse, urlunparse, urlencode

logger = logging.getLogger(__name__)


class InterruptHandler:
    """
    Tracks SIGINT and SIGTERM signals.
    Usage:
    with InterruptHandler() as interrupt_handler:
        while not interrupt_handler.exit:
        ...
    """

    exit = False

    def __enter__(self) -> 'InterruptHandler':
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.signal(signal.SIGINT, self.exit_default)
        signal.signal(signal.SIGTERM, self.exit_default)

    def exit_gracefully(self, signum: int, *args: Any, **kwargs: Any) -> None:
        # pylint: disable=unused-argument
        if self.exit:
            raise KeyboardInterrupt
        logger.info('Received interrupt signal %s, exiting...', signum)
        self.exit = True

    def exit_default(self, signum: int, *args: Any, **kwargs: Any) -> None:
        # pylint: disable=unused-argument
        raise KeyboardInterrupt

    async def sleep(self, seconds: int | float) -> None:
        """
        Interruptible version of `asyncio.sleep()`
        """
        while not self.exit and seconds > 0:
            await asyncio.sleep(min(seconds, 1))
            seconds -= 1


def urljoin(base, *args):
    """
    Better version of `urllib.parse.urljoin`
    Allows multiple arguments.
    Consistent behavior with or without ending slashes.
    Preserves query parameters in the base URL.
    """
    url_parts = list(urlparse(base))
    path = '/'.join(map(lambda x: str(x).strip('/'), args))
    if url_parts[2]:
        url_parts[2] = '/'.join([url_parts[2].strip('/'), path.strip('/')])
    else:
        url_parts[2] = path
    return urlunparse(url_parts)
