import logging
from typing import Any, List, Optional

from eth_typing import URI
from web3 import Web3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.types import RPCEndpoint, RPCResponse

logger = logging.getLogger(__name__)


def get_execution_client(endpoint: str, is_poa=False, timeout=60) -> Web3:
    client = Web3(
        ExtendedAsyncHTTPProvider(endpoint.split(','), request_kwargs={'timeout': timeout}),
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client


class ProtocolNotSupported(Exception):
    """Supported protocols: http, https"""


class NoActiveProviderError(Exception):
    pass


class ExtendedAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Provider with support for fallback endpoints.
    """

    _providers: List[AsyncHTTPProvider] = []

    def __init__(  # pylint: disable=too-many-arguments
        self,
        endpoint_urls: List[str],
        request_kwargs: Optional[Any] = None,
    ):
        logger.info({'msg': 'Initialize MultiHTTPProvider'})
        self._hosts_uri = endpoint_urls
        self._providers = []

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
        response: RPCResponse = {}
        for i, provider in enumerate(self._providers):
            try:
                response = await provider.make_request(method, params)
                return response
            except Exception as error:  # pylint: disable=W0703
                logger.error(
                    {
                        'msg': f'Execution provider not responding at {provider.endpoint_uri}.',
                        'error': str(error),
                        'provider': provider.endpoint_uri,
                    }
                )
                if i == len(self._providers) - 1:
                    msg = f'No active execution provider available for method {method}.'
                    logger.error({'msg': msg})
                    raise NoActiveProviderError(msg) from error
        return response
