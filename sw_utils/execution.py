import logging
from typing import Any, List, Optional

import backoff
from eth_typing import URI
from web3 import AsyncWeb3
from web3.middleware import async_geth_poa_middleware
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.types import RPCEndpoint, RPCResponse

from sw_utils.retries import AiohttpRecoveredErrors, wrap_aiohttp_500_errors

logger = logging.getLogger(__name__)


class ProtocolNotSupported(Exception):
    """Supported protocols: http, https"""


class ExtendedAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Provider with support for fallback endpoints.
    """

    _providers: List[AsyncHTTPProvider] = []

    def __init__(
        self,
        endpoint_urls: List[str],
        request_kwargs: Optional[Any] = None,
        retry_timeout: int = 0,
    ):
        logger.info({'msg': 'Initialize MultiHTTPProvider'})
        self._hosts_uri = endpoint_urls
        self._providers = []
        self.retry_timeout = retry_timeout

        if endpoint_urls:
            self.endpoint_uri = URI(endpoint_urls[0])

        for host_uri in endpoint_urls:
            if host_uri.startswith('http'):
                self._providers.append(
                    AsyncHTTPProvider(host_uri, request_kwargs))
            else:
                protocol = host_uri.split('://')[0]
                raise ProtocolNotSupported(
                    f'Protocol "{protocol}" is not supported.')

        super().__init__()

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        if self.retry_timeout:
            backoff_decorator = backoff.on_exception(
                backoff.expo,
                AiohttpRecoveredErrors,
                max_time=self.retry_timeout,
            )
            return await backoff_decorator(
                wrap_aiohttp_500_errors(self.make_providers_request)
            )(method, params)
        return await self.make_providers_request(method, params)

    async def make_providers_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        for i, provider in enumerate(self._providers):
            try:
                response = await provider.make_request(method, params)
                return response
            except AiohttpRecoveredErrors as error:
                logger.exception(error)
                if i == len(self._providers) - 1:
                    raise error
        return {}


def get_execution_client(
        endpoint: str, is_poa: bool = False, timeout: int = 60, retry_timeout: int = 0
) -> AsyncWeb3:
    client = AsyncWeb3(
        ExtendedAsyncHTTPProvider(
            endpoint_urls=endpoint.split(','),
            request_kwargs={'timeout': timeout},
            retry_timeout=retry_timeout),
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client
