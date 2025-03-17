import asyncio
import logging
import signal
from typing import Any, Iterator, TypeVar, overload
from urllib.parse import urlparse, urlunparse

from hexbytes import HexBytes

logger = logging.getLogger(__name__)

T = TypeVar('T')


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

    def __exit__(self, exc_type, exc_val, exc_tb):  # type: ignore
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


@overload
def chunkify(items: HexBytes, size: int) -> Iterator[HexBytes]:
    ...


@overload
def chunkify(items: bytes, size: int) -> Iterator[bytes]:
    ...


@overload
def chunkify(items: range, size: int) -> Iterator[range]:
    ...


@overload
def chunkify(items: list[T], size: int) -> Iterator[list[T]]:
    ...


def chunkify(items, size):  # type: ignore[no-untyped-def]
    for i in range(0, len(items), size):
        yield items[i : i + size]


def urljoin(base: str, *args: str) -> str:
    """
    Better version of `urllib.parse.urljoin`
    Allows multiple arguments.
    Consistent behavior with or without ending slashes.
    Preserves query parameters in the base URL.
    """
    appended_path = _join_paths(*args)
    if not appended_path:
        return base

    url_parts = urlparse(base)
    new_path = _join_paths(url_parts.path, appended_path)
    return urlunparse(url_parts._replace(path=new_path))


def _join_paths(*args: str) -> str:
    return '/'.join(str(x).strip('/') for x in args)
