import logging
from binascii import unhexlify
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

import jwt
from eth_typing import URI
from web3 import AsyncWeb3, Web3
from web3._utils.async_transactions import _max_fee_per_gas
from web3.eth import AsyncEth
from web3.net import AsyncNet
from web3.providers import AsyncHTTPProvider
from web3.types import RPCEndpoint, RPCResponse, TxParams, Wei

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

    def __init__(
        self,
        endpoint_urls: list[str],
        request_kwargs: Any | None = None,
        retry_timeout: int = 0,
        use_cache: bool = False,
    ):
        self._endpoint_urls = endpoint_urls
        self._providers = []
        self.retry_timeout = retry_timeout

        if endpoint_urls:
            self.endpoint_uri = URI(endpoint_urls[0])  # type: ignore

        for host_uri in endpoint_urls:
            if host_uri.startswith('http'):
                provider = AsyncHTTPProvider(
                    host_uri,
                    request_kwargs,
                    exception_retry_configuration=None,  # disable built-in retries
                    cache_allowed_requests=use_cache,
                )
                self._providers.append(provider)
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
        for i, provider in enumerate(self._providers):
            is_last_iteration = i == len(self._providers) - 1
            try:
                response = await provider.make_request(method, params)
                # Can receive "out of gas" error for some nodes.
                # https://github.com/NethermindEth/nethermind/issues/9801
                if (
                    ExtendedAsyncHTTPProvider._is_out_of_gas_error(response)
                    and not is_last_iteration
                ):
                    continue
                return response
            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if is_last_iteration:
                    raise error

                logger.warning('%s: %s', provider.endpoint_uri, repr(error))

        return {}

    def set_retry_timeout(self, retry_timeout: int) -> None:
        self.retry_timeout = retry_timeout

    @staticmethod
    def _is_out_of_gas_error(response: RPCResponse) -> bool:
        error = response.get('error')
        if not error or not isinstance(error, dict):
            return False
        code = error.get('code')
        if code != -32000:
            return False
        message = error.get('message')
        if message != 'Gas estimation failed due to out of gas':
            return False
        return True

    async def connect(self) -> None:
        """Hide pylint warning, method is used for persistent connection providers."""
        raise NotImplementedError('Persistent connection providers must implement this method')

    async def disconnect(self) -> None:
        """
        Close aiohttp sessions in nested providers.
        Got `Unclosed client session` otherwise.
        https://github.com/ethereum/web3.py/issues/3524
        """
        for provider in self._providers:
            # pylint: disable-next=protected-access
            cache = provider._request_session_manager.session_cache
            for _, session in cache.items():
                await session.close()
            cache.clear()


# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def get_execution_client(
    endpoints: list[str],
    timeout: int = 60,
    retry_timeout: int = 0,
    use_cache: bool = False,
    jwt_secret: str | None = None,
    user_agent: str | None = None,
) -> AsyncWeb3:
    headers = {
        'Content-Type': 'application/json',
    }
    if user_agent:
        headers['User-Agent'] = user_agent

    if jwt_secret:
        token = _create_jwt_auth_token(jwt_secret)
        headers['Authorization'] = f'Bearer {token}'
        logger.debug('JWT Authentication enabled')

    provider = ExtendedAsyncHTTPProvider(
        endpoint_urls=endpoints,
        request_kwargs={'timeout': timeout, 'headers': headers},
        retry_timeout=retry_timeout,
        use_cache=use_cache,
    )
    client = AsyncWeb3(
        provider,
        modules={'eth': (AsyncEth,), 'net': AsyncNet},
    )

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


class GasManager:
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        execution_client: AsyncWeb3,
        priority_fee_num_blocks: int = 10,
        priority_fee_percentile: float = 80,
        max_fee_per_gas: Wei = Web3.to_wei(100, 'gwei'),
        min_effective_priority_fee_per_gas: Wei = Wei(0),
    ) -> None:
        self.execution_client = execution_client
        self.max_fee_per_gas = max_fee_per_gas
        self.priority_fee_num_blocks = priority_fee_num_blocks
        self.priority_fee_percentile = priority_fee_percentile
        self.min_effective_priority_fee_per_gas = min_effective_priority_fee_per_gas

    async def check_gas_price(self, high_priority: bool = False) -> bool:
        if high_priority:
            tx_params = await self.get_high_priority_tx_params()
            max_fee_per_gas = Wei(int(tx_params['maxFeePerGas']))
        else:
            # fallback to logic from web3
            max_priority_fee = await self.execution_client.eth.max_priority_fee
            max_fee_per_gas = await _max_fee_per_gas(
                self.execution_client, {}, {'maxPriorityFeePerGas': max_priority_fee}
            )
        if max_fee_per_gas >= self.max_fee_per_gas:
            logging.warning(
                'Current gas price (%s gwei) is too high. '
                'Will try to submit transaction on the next block if the gas '
                'price is acceptable.',
                Web3.from_wei(max_fee_per_gas, 'gwei'),
            )
            return False

        return True

    async def get_high_priority_tx_params(self) -> TxParams:
        """
        `maxPriorityFeePerGas <= maxFeePerGas` must be fulfilled
        Because of that when increasing `maxPriorityFeePerGas` I have to adjust `maxFeePerGas`.
        See https://eips.ethereum.org/EIPS/eip-1559 for details.
        """
        tx_params: TxParams = {}

        max_priority_fee_per_gas = await self._calc_high_priority_fee()

        # Reference: `_max_fee_per_gas` in web3/_utils/async_transactions.py
        block = await self.execution_client.eth.get_block('latest')
        max_fee_per_gas = Wei(max_priority_fee_per_gas + (2 * block['baseFeePerGas']))

        tx_params['maxPriorityFeePerGas'] = max_priority_fee_per_gas
        tx_params['maxFeePerGas'] = max_fee_per_gas
        logger.debug('tx_params %s', tx_params)

        return tx_params

    async def _calc_high_priority_fee(self) -> Wei:
        """
        reference: "high" priority value from https://etherscan.io/gastracker
        """
        num_blocks = self.priority_fee_num_blocks
        percentile = self.priority_fee_percentile
        history = await self.execution_client.eth.fee_history(num_blocks, 'pending', [percentile])
        validator_rewards = [r[0] for r in history['reward']]
        mean_reward = int(sum(validator_rewards) / len(validator_rewards))

        # prettify `mean_reward`
        # same as `round(value, 1)` if value was in gwei
        if mean_reward > Web3.to_wei(1, 'gwei'):
            mean_reward = round(mean_reward, -8)

        if self.min_effective_priority_fee_per_gas:
            return Wei(max(self.min_effective_priority_fee_per_gas, mean_reward))
        return Wei(mean_reward)
