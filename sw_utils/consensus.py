import logging
from enum import Enum
from typing import TYPE_CHECKING, Any, Sequence

import aiohttp
from aiohttp import ClientResponseError
from eth_typing import URI, BlockNumber, HexStr
from web3 import AsyncWeb3, Web3
from web3._utils.request import async_json_make_get_request
from web3.beacon import AsyncBeacon
from web3.beacon.api_endpoints import GET_VOLUNTARY_EXITS
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from sw_utils.common import urljoin
from sw_utils.decorators import can_be_retried_aiohttp_error, retry_aiohttp_errors
from sw_utils.typings import ChainHead, ConsensusFork

logger = logging.getLogger(__name__)


GET_VALIDATORS = '/eth/v1/beacon/states/{0}/validators'
GET_ATTESTATION_REWARDS = 'eth/v1/beacon/rewards/attestations/{0}'
GET_SYNC_COMMITTEE_REWARDS = 'eth/v1/beacon/rewards/sync_committee/{0}'


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
    - post requests to consensus nodes
    - methods for Pectra: pending deposits, pending partial withdrawals
    """

    def __init__(
        self,
        base_urls: list[str],
        timeout: int = 60,
        retry_timeout: int = 0,
        log_uri_max_len: int | None = None,
    ) -> None:
        self.base_urls = base_urls
        self.timeout = timeout
        self.retry_timeout = retry_timeout
        self.log_uri_max_len = log_uri_max_len or 100
        super().__init__('')  # hack origin base_url param

    async def get_validators_by_ids(
        self, validator_ids: Sequence[str], state_id: str = 'head'
    ) -> dict:
        endpoint = GET_VALIDATORS.format(state_id)
        return await self._async_make_post_request(
            endpoint_uri=endpoint, data={'ids': validator_ids}
        )

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

            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if i == len(self.base_urls) - 1:
                    raise error
                logger.warning('%s: %s', url, repr(error))

    async def get_attestation_rewards(self, epoch: int, validators: list[str]) -> dict:
        endpoint = GET_ATTESTATION_REWARDS.format(epoch)
        return await self._async_make_post_request(endpoint_uri=endpoint, data=validators)

    async def get_sync_committee_rewards(self, epoch: int, validators: list[str]) -> dict:
        endpoint = GET_SYNC_COMMITTEE_REWARDS.format(epoch)
        return await self._async_make_post_request(endpoint_uri=endpoint, data=validators)

    async def get_consensus_fork(self, state_id: str = 'head') -> ConsensusFork:
        """Fetches current fork data."""
        fork_data = (await self.get_fork_data(state_id))['data']
        return ConsensusFork(
            version=Web3.to_bytes(hexstr=fork_data['current_version']),
            epoch=int(fork_data['epoch']),
        )

    async def get_pending_deposits(self, state_id: int | str = 'head') -> list[dict]:
        """Fetches pending deposits."""
        endpoint_uri = f'/eth/v1/beacon/states/{state_id}/pending_deposits'
        response = await self._async_make_get_request(endpoint_uri)
        return response['data']

    async def get_pending_partial_withdrawals(self, state_id: int | str = 'head') -> list[dict]:
        """Fetches pending deposits."""
        endpoint_uri = f'/eth/v1/beacon/states/{state_id}/pending_partial_withdrawals'
        response = await self._async_make_get_request(endpoint_uri)
        return response['data']

    async def _async_make_get_request(self, endpoint_uri: str) -> dict[str, Any]:
        if self.retry_timeout:

            def custom_before_log(retry_state: 'RetryCallState') -> None:
                if retry_state.attempt_number <= 1:
                    return
                msg = 'Retrying consensus uri %s, attempt %s'
                args = (self._format_uri(endpoint_uri), retry_state.attempt_number)
                logger.log(logging.INFO, msg, *args)

            retry_decorator = retry_aiohttp_errors(
                self.retry_timeout,
                before=custom_before_log,
            )
            return await retry_decorator(self._async_make_get_request_inner)(endpoint_uri)

        return await self._async_make_get_request_inner(endpoint_uri)

    async def _async_make_post_request(
        self, endpoint_uri: str, data: list | dict
    ) -> dict[str, Any]:
        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, endpoint_uri))

                async with aiohttp.ClientSession() as session:
                    async with session.post(uri, json=data) as response:
                        response.raise_for_status()
                        return await response.json()

            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if i == len(self.base_urls) - 1:
                    raise error
                logger.warning('%s: %s', url, repr(error))

        return {}

    def _format_uri(self, uri: str) -> str:
        max_len = self.log_uri_max_len

        if len(uri) <= max_len:
            return uri

        return f'{uri[:max_len]}...'

    async def _async_make_get_request_inner(self, endpoint_uri: str) -> dict[str, Any]:
        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, endpoint_uri))
                return await async_json_make_get_request(uri, timeout=self.timeout)

            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if i == len(self.base_urls) - 1:
                    raise error
                logger.warning('%s: %s', url, repr(error))

        return {}

    def set_retry_timeout(self, retry_timeout: int) -> None:
        self.retry_timeout = retry_timeout


def get_consensus_client(
    endpoints: list[str],
    timeout: int = 60,
    retry_timeout: int = 0,
    log_uri_max_len: int | None = None,
) -> ExtendedAsyncBeacon:
    return ExtendedAsyncBeacon(
        base_urls=endpoints,
        timeout=timeout,
        retry_timeout=retry_timeout,
        log_uri_max_len=log_uri_max_len,
    )


async def get_chain_finalized_head(
    consensus_client: ExtendedAsyncBeacon,
    slots_per_epoch: int,
) -> ChainHead:
    """Fetches the fork finalized chain head."""
    block_data = await consensus_client.get_block('finalized')
    slot = int(block_data['data']['message']['slot'])

    return ChainHead(
        epoch=slot // slots_per_epoch,
        slot=slot,
        block_number=BlockNumber(
            int(block_data['data']['message']['body']['execution_payload']['block_number'])
        ),
        execution_ts=Timestamp(
            int(block_data['data']['message']['body']['execution_payload']['timestamp'])
        ),
    )


async def get_chain_justified_head(
    consensus_client: ExtendedAsyncBeacon,
    slots_per_epoch: int,
) -> ChainHead:
    """Fetches the fork safe chain head."""
    checkpoints = await consensus_client.get_finality_checkpoint()
    epoch: int = int(checkpoints['data']['current_justified']['epoch'])
    last_slot_id: int = epoch * slots_per_epoch
    for i in range(slots_per_epoch):
        try:
            slot = await consensus_client.get_block(str(last_slot_id - i))
        except ClientResponseError as e:
            if hasattr(e, 'status') and e.status == 404:
                # slot was not proposed, try the previous one
                continue
            raise e

        execution_payload = slot['data']['message']['body']['execution_payload']
        return ChainHead(
            epoch=epoch,
            slot=last_slot_id - i,
            block_number=BlockNumber(int(execution_payload['block_number'])),
            execution_ts=Timestamp(int(execution_payload['timestamp'])),
        )

    raise RuntimeError(f'Failed to fetch slot for epoch {epoch}')


async def get_chain_epoch_head(
    epoch: int,
    slots_per_epoch: int,
    execution_client: AsyncWeb3,
    consensus_client: ExtendedAsyncBeacon,
) -> ChainHead:
    """Fetches the epoch chain head."""
    slot_id: int = epoch * slots_per_epoch
    for i in range(slots_per_epoch):
        try:
            slot = await consensus_client.get_block(str(slot_id - i))
        except ClientResponseError as e:
            if hasattr(e, 'status') and e.status == 404:
                # slot was not proposed, try the previous one
                continue
            raise e
        try:
            execution_payload = slot['data']['message']['body']['execution_payload']
            return ChainHead(
                epoch=epoch,
                slot=slot_id - i,
                block_number=BlockNumber(int(execution_payload['block_number'])),
                execution_ts=Timestamp(int(execution_payload['timestamp'])),
            )
        except KeyError:  # pre shapella slot
            block_hash = slot['data']['message']['body']['eth1_data']['block_hash']
            try:
                block = await execution_client.eth.get_block(block_hash)
            except BlockNotFound:
                continue

            return ChainHead(
                epoch=epoch,
                slot=slot_id - i,
                block_number=BlockNumber(int(block['number'])),
                execution_ts=Timestamp(int(block['timestamp'])),
            )

    raise RuntimeError(f'Failed to fetch slot for epoch {epoch}')
