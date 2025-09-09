import logging
from typing import Any

from aiohttp import ClientTimeout
from eth_typing import URI
from web3._utils.http import DEFAULT_HTTP_TIMEOUT
from web3._utils.http_session_manager import HTTPSessionManager

logger = logging.getLogger(__name__)


class ExtendedHTTPSessionManager(HTTPSessionManager):
    async def async_json_make_get_request(
        self, endpoint_uri: URI, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        kwargs.setdefault('timeout', ClientTimeout(DEFAULT_HTTP_TIMEOUT))
        session = await self.async_cache_and_return_session(
            endpoint_uri, request_timeout=kwargs['timeout']
        )
        async with session:
            async with session.get(endpoint_uri, *args, **kwargs) as response:
                response.raise_for_status()
                return await response.json()

    async def async_make_post_request(
        self, endpoint_uri: URI, data: bytes | dict[str, Any], **kwargs: Any
    ) -> bytes:
        kwargs.setdefault('timeout', ClientTimeout(DEFAULT_HTTP_TIMEOUT))
        session = await self.async_cache_and_return_session(
            endpoint_uri, request_timeout=kwargs['timeout']
        )
        kwargs['data'] = data

        async with session:
            async with session.post(endpoint_uri, **kwargs) as response:
                response.raise_for_status()
                return await response.read()

    async def async_json_make_post_request(
        self, endpoint_uri: URI, *args: Any, **kwargs: Any
    ) -> dict[str, Any]:
        kwargs.setdefault('timeout', ClientTimeout(DEFAULT_HTTP_TIMEOUT))
        session = await self.async_cache_and_return_session(
            endpoint_uri, request_timeout=kwargs['timeout']
        )
        async with session:
            async with session.post(endpoint_uri, **kwargs) as response:
                response.raise_for_status()
                return await response.json()
