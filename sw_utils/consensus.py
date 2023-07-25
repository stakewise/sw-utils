import logging
from enum import Enum
from typing import TYPE_CHECKING, Any

import aiohttp
from aiohttp import ClientResponseError
from eth_typing import URI, BlockNumber, HexStr
from web3 import Web3
from web3._utils.request import async_json_make_get_request
from web3.beacon import AsyncBeacon
from web3.beacon.api_endpoints import GET_VOLUNTARY_EXITS
from web3.types import Timestamp

from sw_utils.common import urljoin
from sw_utils.decorators import retry_aiohttp_errors
from sw_utils.exceptions import AiohttpRecoveredErrors
from sw_utils.typings import ChainHead, ConsensusFork

logger = logging.getLogger(__name__)


GET_VALIDATORS = '/eth/v1/beacon/states/{0}/validators{1}'


class ValidatorStatus(Enum):
    """Validator statuses in consensus layer"""

    PENDING_INITIALIZED = 'pending_initialized'
    PENDING_QUEUED = 'pending_queued'
    ACTIVE_ONGOING = 'active_ongoing'
    ACTIVE_EXITING = 'active_exiting'
    ACTIVE_SLASHED = 'active_slashed'
    EXITED_UNSLASHED = 'exited_unslashed'
    EXITED_SLASHED = 'exited_slashed'
    WITHDRAWAL_POSSIBLE = 'withdrawal_possible'
    WITHDRAWAL_DONE = 'withdrawal_done'


PENDING_STATUSES = [ValidatorStatus.PENDING_INITIALIZED, ValidatorStatus.PENDING_QUEUED]
ACTIVE_STATUSES = [
    ValidatorStatus.ACTIVE_ONGOING,
    ValidatorStatus.ACTIVE_EXITING,
    ValidatorStatus.ACTIVE_SLASHED,
]
EXITED_STATUSES = [
    ValidatorStatus.EXITED_UNSLASHED,
    ValidatorStatus.EXITED_SLASHED,
    ValidatorStatus.WITHDRAWAL_POSSIBLE,
    ValidatorStatus.WITHDRAWAL_DONE,
]

if TYPE_CHECKING:
    from tenacity import RetryCallState


class ExtendedAsyncBeacon(AsyncBeacon):
    """
    Extended AsyncBeacon Provider with extra features:
    - support for fallback endpoints
    - single session requests
    - post requests to consensus nodes
    """

    def __init__(
        self,
        base_urls: list[str],
        timeout: int = 60,
        session: aiohttp.ClientSession = None,
        retry_timeout: int = 0,
    ) -> None:
        self.base_urls = base_urls
        self.timeout = timeout
        self.session = session
        self.retry_timeout = retry_timeout
        super().__init__('')  # hack origin base_url param

    async def get_validators_by_ids(self, validator_ids: list[str], state_id: str = 'head') -> dict:
        endpoint = GET_VALIDATORS.format(state_id, f"?id={'&id='.join(validator_ids)}")
        return await self._async_make_get_request(endpoint)

    async def submit_voluntary_exit(
        self, epoch: int, validator_index: int, signature: HexStr
    ) -> None:
        data = {
            'message': {'epoch': str(epoch), 'validator_index': str(validator_index)},
            'signature': signature,
        }
        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, GET_VOLUNTARY_EXITS))

                async with aiohttp.ClientSession() as session:
                    async with session.post(uri, json=data) as response:
                        response.raise_for_status()
                        return

            except AiohttpRecoveredErrors as error:
                if i == len(self.base_urls) - 1:
                    raise error
                logger.error('%s: %s', url, repr(error))

    async def get_chain_finalized_head(self, slots_per_epoch: int) -> ChainHead:
        """Fetches the fork safe chain head."""
        checkpoints = await self.get_finality_checkpoint()
        epoch: int = int(checkpoints['data']['finalized']['epoch'])
        last_slot_id: int = (epoch * slots_per_epoch) + slots_per_epoch - 1
        for i in range(slots_per_epoch):
            try:
                slot = await self.get_block(str(last_slot_id - i))
            except ClientResponseError as e:
                if hasattr(e, 'status') and e.status == 404:
                    # slot was not proposed, try the previous one
                    continue
                raise e

            execution_payload = slot['data']['message']['body']['execution_payload']
            return ChainHead(
                epoch=epoch,
                consensus_block=last_slot_id - i,
                execution_block=BlockNumber(int(execution_payload['block_number'])),
                execution_ts=Timestamp(int(execution_payload['timestamp'])),
            )

        raise RuntimeError(f'Failed to fetch slot for epoch {epoch}')

    async def get_consensus_fork(self, state_id: str = 'head') -> ConsensusFork:
        """Fetches current fork data."""
        fork_data = (await self.get_fork_data(state_id))['data']
        return ConsensusFork(
            version=Web3.to_bytes(hexstr=fork_data['current_version']),
            epoch=int(fork_data['epoch']),
        )

    async def _async_make_get_request(self, endpoint_uri: str) -> dict[str, Any]:
        if self.retry_timeout:

            def custom_before_log(retry_logger, log_level):
                def custom_log_it(retry_state: 'RetryCallState') -> None:
                    if retry_state.attempt_number <= 1:
                        return
                    msg = 'Retrying consensus uri %s(), attempt %s'
                    args = (endpoint_uri, retry_state.attempt_number)
                    retry_logger.log(log_level, msg, *args)

                return custom_log_it

            retry_decorator = retry_aiohttp_errors(
                self.retry_timeout,
                log_func=custom_before_log,
            )
            return await retry_decorator(self._async_make_get_request_inner)(endpoint_uri)

        return await self._async_make_get_request_inner(endpoint_uri)

    async def _async_make_get_request_inner(self, endpoint_uri: str) -> dict[str, Any]:
        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, endpoint_uri))
                if self.session:
                    return await self._make_session_get_request(uri)
                return await async_json_make_get_request(uri, timeout=self.timeout)

            except AiohttpRecoveredErrors as error:
                if i == len(self.base_urls) - 1:
                    raise error
                logger.error('%s: %s', url, repr(error))

        return {}

    async def _make_session_get_request(self, uri):
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        logger.debug('GET %s', uri)

        async with self.session.get(uri, timeout=timeout) as response:
            response.raise_for_status()
            data = await response.json()
            return data

    def set_retry_timeout(self, retry_timeout: int):
        self.retry_timeout = retry_timeout


def get_consensus_client(
    endpoints: list[str],
    timeout: int = 60,
    session: aiohttp.ClientSession = None,
    retry_timeout: int = 0,
) -> ExtendedAsyncBeacon:
    return ExtendedAsyncBeacon(
        base_urls=endpoints, timeout=timeout, session=session, retry_timeout=retry_timeout
    )
