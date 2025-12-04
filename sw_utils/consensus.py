import logging
from enum import Enum
from typing import TYPE_CHECKING, Any, Sequence

from aiohttp import ClientResponseError, ClientTimeout
from eth_typing import URI, BlockNumber, HexStr
from web3 import AsyncWeb3, Web3
from web3.beacon import AsyncBeacon
from web3.beacon.api_endpoints import GET_VALIDATORS, GET_VOLUNTARY_EXITS
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from sw_utils.common import urljoin
from sw_utils.decorators import can_be_retried_aiohttp_error, retry_aiohttp_errors
from sw_utils.typings import ChainHead, ConsensusFork

logger = logging.getLogger(__name__)


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

    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def __init__(
        self,
        base_urls: list[str],
        timeout: int = 60,
        retry_timeout: int = 0,
        log_uri_max_len: int | None = None,
        user_agent: str | None = None,
    ) -> None:
        self.base_urls = base_urls
        self.timeout = timeout
        self.retry_timeout = retry_timeout
        self.log_uri_max_len = log_uri_max_len or 100
        self.user_agent = user_agent
        super().__init__('')  # hack origin base_url param

    async def get_validators_by_ids(
        self, validator_ids: Sequence[str], state_id: str = 'head'
    ) -> dict:
        """
        Makes POST request, filters by validator ids.
        """
        return await self._post_validators(state_id=state_id, validator_ids=validator_ids)

    async def get_validators_by_statuses(
        self, statuses: Sequence[ValidatorStatus], state_id: str = 'head'
    ) -> dict:
        """
        Makes POST request, filters by statuses.
        """
        return await self._post_validators(state_id=state_id, statuses=statuses)

    async def submit_voluntary_exit(
        self, epoch: int, validator_index: int, signature: HexStr
    ) -> None:
        data = {
            'message': {'epoch': str(epoch), 'validator_index': str(validator_index)},
            'signature': signature,
        }
        await self._async_make_post_request(endpoint_uri=GET_VOLUNTARY_EXITS, body=data)

    async def get_sync_committee_rewards(self, epoch: int, validators: list[str]) -> dict:
        endpoint = GET_SYNC_COMMITTEE_REWARDS.format(epoch)
        return await self._async_make_post_request(endpoint_uri=endpoint, body=validators)

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

    async def get_pending_consolidations(self, state_id: int | str = 'head') -> list[dict]:
        """Fetches pending consolidations."""
        endpoint_uri = f'/eth/v1/beacon/states/{state_id}/pending_consolidations'
        response = await self._async_make_get_request(endpoint_uri)
        return response['data']

    async def disconnect(self) -> None:
        """
        Close aiohttp sessions for provider.
        Got `Unclosed client session` otherwise.
        https://github.com/ethereum/web3.py/issues/3524
        """
        cache = self._request_session_manager.session_cache
        for _, session in cache.items():
            await session.close()
        cache.clear()

    async def _post_validators(
        self,
        state_id: str = 'head',
        validator_ids: Sequence[str] | None = None,
        statuses: Sequence[ValidatorStatus] | None = None,
    ) -> dict:
        """
        Makes POST request, filters by validator ids and statuses.
        """
        endpoint = GET_VALIDATORS.format(state_id)
        body = {}

        if validator_ids:
            body['ids'] = validator_ids

        if statuses:
            body['statuses'] = [s.value for s in statuses]

        return await self._async_make_post_request(endpoint_uri=endpoint, body=body)

    async def _async_make_get_request(
        self, endpoint_uri: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
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
            return await retry_decorator(self._async_make_get_request_inner)(endpoint_uri, params)

        return await self._async_make_get_request_inner(endpoint_uri, params)

    async def _async_make_post_request(
        self, endpoint_uri: str, body: list | dict
    ) -> dict[str, Any]:
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
            return await retry_decorator(self._async_make_post_request_inner)(endpoint_uri, body)

        return await self._async_make_post_request_inner(endpoint_uri, body)

    def _format_uri(self, uri: str) -> str:
        max_len = self.log_uri_max_len

        if len(uri) <= max_len:
            return uri

        return f'{uri[:max_len]}...'

    async def _async_make_get_request_inner(
        self, endpoint_uri: str, params: dict[str, str] | None = None
    ) -> dict[str, Any]:
        headers = {}
        if self.user_agent:
            headers['User-Agent'] = self.user_agent

        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, endpoint_uri))
                return await self._request_session_manager.async_json_make_get_request(
                    uri, params=params, timeout=ClientTimeout(self.request_timeout), headers=headers
                )

            except Exception as error:
                if not can_be_retried_aiohttp_error(error):
                    raise error

                if i == len(self.base_urls) - 1:
                    raise error
                logger.warning('%s: %s', url, repr(error))

        return {}

    async def _async_make_post_request_inner(
        self, endpoint_uri: str, body: list | dict
    ) -> dict[str, Any]:
        headers = {}
        if self.user_agent:
            headers['User-Agent'] = self.user_agent

        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(urljoin(url, endpoint_uri))
                return await self._request_session_manager.async_json_make_post_request(
                    uri, json=body, timeout=ClientTimeout(self.request_timeout), headers=headers
                )

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
    user_agent: str | None = None,
) -> ExtendedAsyncBeacon:
    return ExtendedAsyncBeacon(
        base_urls=endpoints,
        timeout=timeout,
        retry_timeout=retry_timeout,
        log_uri_max_len=log_uri_max_len,
        user_agent=user_agent,
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


async def get_chain_latest_head(
    consensus_client: ExtendedAsyncBeacon,
    slots_per_epoch: int,
) -> ChainHead:
    """Fetches the fork latest chain head."""
    block_data = await consensus_client.get_block('head')
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
