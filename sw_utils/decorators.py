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
