import contextlib
import logging
from binascii import unhexlify
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Iterator

import jwt
from eth_typing import URI
from web3 import AsyncWeb3
from web3.eth import AsyncEth
from web3.middleware import async_geth_poa_middleware, async_simple_cache_middleware
from web3.net import AsyncNet
from web3.providers.async_rpc import AsyncHTTPProvider
from web3.types import AsyncMiddleware, RPCEndpoint, RPCResponse

from sw_utils.decorators import can_be_retried_aiohttp_error, retry_aiohttp_errors

logger = logging.getLogger(__name__)


JWT_EXPIRATION_HOURS = 8760


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

    # Turn off `async_http_retry_request_middleware`
    _middlewares: tuple[AsyncMiddleware, ...] = ()

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

            def custom_before_log(retry_state: 'RetryCallState') -> None:
                if retry_state.attempt_number <= 1:
                    return
                msg = 'Retrying execution method %s, attempt %s'
                args = (method, retry_state.attempt_number)
                logger.log(logging.INFO, msg, *args)

            retry_decorator = retry_aiohttp_errors(
                self.retry_timeout,
                before=custom_before_log,
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
            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if i == len(self._providers) - 1:
                    raise error

                logger.warning('%s: %s', provider.endpoint_uri, repr(error))

        return {}

    @contextlib.contextmanager
    def lock_endpoint(self, endpoint_uri: URI | str) -> Iterator:
        uri_providers = [prov for prov in self._providers if prov.endpoint_uri == endpoint_uri]
        if not uri_providers:
            raise ValueError(f'Invalid uri provider for execution client: {uri_providers}')
        self._locker_provider = uri_providers[0]
        try:
            yield
        finally:
            self._locker_provider = None

    @contextlib.contextmanager
    def disable_retries(self) -> Iterator:
        cache = self.retry_timeout
        self.retry_timeout = 0
        try:
            yield
        finally:
            self.retry_timeout = cache

    def set_retry_timeout(self, retry_timeout: int) -> None:
        self.retry_timeout = retry_timeout


# pylint: disable-next=too-many-arguments
def get_execution_client(
    endpoints: list[str],
    is_poa: bool = False,
    timeout: int = 60,
    retry_timeout: int = 0,
    use_cache: bool = True,
    jwt_secret: str | None = None,
) -> AsyncWeb3:
    headers = {
        'Content-Type': 'application/json',
    }

    if jwt_secret:
        token = _create_jwt_auth_token(jwt_secret)
        headers['Authorization'] = f'Bearer {token}'
        logger.debug('JWT Authentication enabled')

    provider = ExtendedAsyncHTTPProvider(
        endpoint_urls=endpoints,
        request_kwargs={'timeout': timeout, 'headers': headers},
        retry_timeout=retry_timeout,
    )
    client = AsyncWeb3(
        provider,
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

    if is_poa:
        client.middleware_onion.inject(async_geth_poa_middleware, layer=0)
        logger.debug('Injected POA middleware')

    if use_cache:
        client.middleware_onion.add(async_simple_cache_middleware)

    return client


def _create_jwt_auth_token(jwt_secret: str) -> str:
    """Generate a JWT token using the provided secret.

    Args:
    jwt_secret (str): The JWT secret in hexadecimal format.

    Returns:
    str: A JWT token.

    Raises:
    ValueError: If there is an issue with the JWT secret format or token signing.
    """
    try:
        secret = unhexlify(jwt_secret.strip())
    except Exception as e:
        raise ValueError('Invalid JWT secret format') from e

    expiration_time = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    claims = {
        'exp': expiration_time,
        'iat': datetime.now(timezone.utc),
        'nbf': datetime.now(timezone.utc),
    }

    try:
        token = jwt.encode(claims, secret, algorithm='HS256')
        return token
    except Exception as e:
        raise ValueError('Error signing the JWT') from e
