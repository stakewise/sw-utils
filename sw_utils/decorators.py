import aiohttp
import backoff

connection_errors = (
    aiohttp.ClientConnectionError,
    aiohttp.ClientConnectorError,
    aiohttp.ServerConnectionError,
)


def backoff_aiohttp_connection_errors(
        max_tries: int | None = None,
        max_time: int | None = None,
        **kwargs
):
    return backoff.on_exception(
        backoff.expo,
        connection_errors,
        max_tries=max_tries,
        max_time=max_time,
        **kwargs
    )
