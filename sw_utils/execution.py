import logging

from web3 import Web3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet

from sw_utils.common import Singleton

logger = logging.getLogger(__name__)


class ExecutionClient(metaclass=Singleton):
    clients: dict[str, Web3] = {}

    def get_client(self, endpoint: str, is_poa=False) -> Web3:
        if self.clients.get(endpoint):
            return self.clients[endpoint]

        client = Web3(
            Web3.AsyncHTTPProvider(endpoint),
            modules={'eth': (AsyncEth,), 'net': AsyncNet},
            middlewares=[],
        )
        logger.warning('Web3 HTTP endpoint=%s', endpoint)

        if is_poa:
            client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
            logger.warning('Injected POA middleware')

        self.clients[endpoint] = client
        return client
