import contextlib
import logging
import warnings
from typing import TYPE_CHECKING, Any

from eth_typing import URI
from web3 import AsyncWeb3
from web3._utils.fee_utils import async_fee_history_priority_fee
from web3.eth import AsyncEth
from web3.exceptions import MethodUnavailable
from web3.middleware import async_geth_poa_middleware
from web3.net import AsyncNet
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.types import RPCEndpoint, RPCResponse, Wei

from sw_utils.decorators import retry_aiohttp_errors
from sw_utils.exceptions import AiohttpRecoveredErrors

logger = logging.getLogger(__name__)


if TYPE_CHECKING:
    from tenacity import RetryCallState


class ProtocolNotSupported(Exception):
    """Supported protocols: http, https"""


class ExtendedAsyncHTTPProvider(AsyncHTTPProvider):
    """
    Provider with support for fallback endpoints.
    """

    _providers: list[AsyncHTTPProvider] = []
    _locker_provider: AsyncHTTPProvider | None = None

    def __init__(
        self,
        endpoint_urls: list[str],
        request_kwargs: Any | None = None,
        retry_timeout: int = 0,
    ):
        self._endpoint_urls = endpoint_urls
        self._providers = []
        self.retry_timeout = retry_timeout

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

        if self.retry_timeout:

            def custom_before_log(retry_logger, log_level):
                def custom_log_it(retry_state: 'RetryCallState') -> None:
                    if retry_state.attempt_number <= 1:
                        return
                    msg = 'Retrying execution method %s, attempt %s'
                    args = (method, retry_state.attempt_number)
                    retry_logger.log(log_level, msg, *args)

                return custom_log_it

            retry_decorator = retry_aiohttp_errors(
                self.retry_timeout,
                log_func=custom_before_log,
            )
            return await retry_decorator(self.make_request_inner)(method, params)

        return await self.make_request_inner(method, params)

    async def make_request_inner(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        if self._locker_provider:
            return await self._locker_provider.make_request(method, params)
        for i, provider in enumerate(self._providers):
            try:
                response = await provider.make_request(method, params)
                return response
            except AiohttpRecoveredErrors as error:
                if i == len(self._providers) - 1:
                    raise error
                logger.error('%s: %s', provider.endpoint_uri, repr(error))

        return {}

    @contextlib.contextmanager
    def lock_endpoint(self, endpoint_uri: URI | str):
        uri_providers = [prov for prov in self._providers if prov.endpoint_uri == endpoint_uri]
        if not uri_providers:
            raise ValueError(f'Invalid uri provider for execution client: {uri_providers}')
        self._locker_provider = uri_providers[0]
        try:
            yield
        finally:
            self._locker_provider = None

    def set_retry_timeout(self, retry_timeout: int):
        self.retry_timeout = retry_timeout


# pylint: disable=abstract-method
class ExtendedAsyncEth(AsyncEth):
    """
    todo: remove when PR gets merged
    https://github.com/ethereum/web3.py/pull/3084
    """

    @property
    async def max_priority_fee(self) -> Wei:
        """
        Try to use eth_maxPriorityFeePerGas but, since this is not part
        of the spec and is only supported by some clients, fall back to
        an eth_feeHistory calculation with min and max caps.
        """
        try:
            return await self._max_priority_fee()
        except (ValueError, MethodUnavailable):
            warnings.warn(
                'There was an issue with the method eth_maxPriorityFeePerGas. '
                'Calculating using eth_feeHistory.'
            )
            return await async_fee_history_priority_fee(self)


def get_execution_client(
    endpoints: list[str], is_poa=False, timeout=60, retry_timeout=0
) -> AsyncWeb3:
    provider = ExtendedAsyncHTTPProvider(
        endpoint_urls=endpoints, request_kwargs={'timeout': timeout}, retry_timeout=retry_timeout
    )
    client = AsyncWeb3(
        provider,
        modules={'eth': (ExtendedAsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.info('Injected POA middleware')
    return client
