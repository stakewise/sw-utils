import logging

from typing import Any, List, Union, Optional
from eth_typing import URI
from web3 import Web3, HTTPProvider
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.net import AsyncNet
from web3.types import RPCEndpoint, RPCResponse

logger = logging.getLogger(__name__)


def get_execution_client(endpoint: str, is_poa=False, timeout=60) -> Web3:
    client = Web3(
        ExtendedAsyncHTTPProvider(endpoint.split(","), request_kwargs={'timeout': timeout}),
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client


class NoActiveProviderError(Exception):
    """Base exception if all endpoints are offline"""


class ProtocolNotSupported(Exception):
    """Supported protocols: http, https"""


class ExtendedAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Provider with support for fallback endpoints.
    """

    _providers: List[HTTPProvider] = []

    def __init__(  # pylint: disable=too-many-arguments
        self,
        endpoint_urls: List[Union[URI, str]],
        request_kwargs: Optional[Any] = None,
    ):
        logger.info({"msg": "Initialize MultiHTTPProvider"})
        self._hosts_uri = endpoint_urls
        self._providers = []

        if endpoint_urls:
            self.endpoint_uri = endpoint_urls[0]

        for host_uri in endpoint_urls:
            if host_uri.startswith("http"):
                self._providers.append(
                    AsyncHTTPProvider(host_uri, request_kwargs))
            else:
                protocol = host_uri.split("://")[0]
                raise ProtocolNotSupported(
                    f'Protocol "{protocol}" is not supported.')

        super().__init__()

    async def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        for i, provider in enumerate(self._providers):
            try:
                response = await provider.make_request(method, params)
                break
            except Exception as error:  # pylint: disable=W0703
                if i == len(self._providers)-1:
                    msg = "No active provider available."
                    logger.error({"msg": msg})
                    raise NoActiveProviderError(msg) from error

                logger.warning(
                    {
                        "msg": "Provider not responding.",
                        "error": str(error),
                        "provider": provider.endpoint_uri,
                    }
                )

        return response
