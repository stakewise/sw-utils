import asyncio
import logging

import aiohttp
import requests

logger = logging.getLogger(__name__)


class RecoverableServerError(Exception):
    """
    Wrapper around ClientResponseError for HTTP 500 errors.
    Only for internal use inside sw-utils library.
    Do not raise `RecoverableServerError` in application code.
    """

    def __init__(self, origin: requests.HTTPError | aiohttp.ClientResponseError):
        self.origin = origin
        if isinstance(origin, requests.HTTPError):
            self.status_code = origin.response.status_code
            self.uri = origin.response.url
        elif isinstance(origin, aiohttp.ClientResponseError):
            self.status_code = origin.status
            self.uri = origin.request_info

        super().__init__()

    def __str__(self):
        return (
            f'RecoverableServerError (status_code: {self.status_code}, '
            f'uri: {self.uri}): {self.origin}'
        )


AiohttpRecoveredErrors = (
    aiohttp.ClientConnectionError,
    RecoverableServerError,
    asyncio.TimeoutError,
)
RequestsRecoveredErrors = (
    requests.ConnectionError,
    requests.Timeout,
    RecoverableServerError,
)
