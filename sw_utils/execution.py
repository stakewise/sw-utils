import logging
from typing import Any

from eth_typing import URI
from web3 import AsyncWeb3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.types import RPCEndpoint, RPCResponse

from sw_utils.exceptions import AiohttpRecoveredErrors

logger = logging.getLogger(__name__)


class ProtocolNotSupported(Exception):
    """Supported protocols: http, https"""


class ExtendedAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Provider with support for fallback endpoints.
    """

    _providers: list[AsyncHTTPProvider] = []

    def __init__(
        self,
        endpoint_urls: list[str],
        request_kwargs: Any | None = None,
    ):
        logger.debug({'msg': 'Initialize MultiHTTPProvider'})
        self._endpoint_urls = endpoint_urls
        self._providers = []

        if endpoint_urls:
            self.endpoint_uri = URI(endpoint_urls[0])

        for host_uri in endpoint_urls:
            if host_uri.startswith('http'):
                self._providers.append(AsyncHTTPProvider(host_uri, request_kwargs))
            else:
                protocol = host_uri.split('://')[0]
                raise ProtocolNotSupported(f'Protocol "{protocol}" is not supported.')

        super().__init__()

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        for i, provider in enumerate(self._providers):
            try:
                response = await provider.make_request(method, params)
                return response
            except AiohttpRecoveredErrors as error:
                if i == len(self._providers) - 1:
                    raise error
                logger.error(error)

        return {}


def get_execution_client(endpoints: list[str], is_poa=False, timeout=60) -> AsyncWeb3:
    provider = ExtendedAsyncHTTPProvider(
        endpoint_urls=endpoints, request_kwargs={'timeout': timeout}
    )
    client = AsyncWeb3(
        provider,
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client
