import logging

from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet

logger = logging.getLogger(__name__)


def get_execution_client(endpoint: str, is_poa=False, timeout=60) -> AsyncWeb3:
    provider = AsyncHTTPProvider(endpoint, request_kwargs={'timeout': timeout})
    client = AsyncWeb3(
        provider,
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client
