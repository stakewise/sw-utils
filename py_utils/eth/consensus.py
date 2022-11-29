import logging
from enum import Enum

import backoff
from eth_typing import HexStr
from web3.beacon import AsyncBeacon

from py_utils.common.utils import Singleton

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


class ExtendedAsyncBeacon(AsyncBeacon):
    async def get_validators_by_ids(
        self, validator_ids: str, state_id: str = 'head'
    ) -> dict:
        return await self._async_make_get_request(GET_VALIDATORS.format(state_id, validator_ids))


class ConsensusClient(metaclass=Singleton):
    clients: dict[str, ExtendedAsyncBeacon] = {}

    async def get_client(self, endpoint: str) -> ExtendedAsyncBeacon:
        if self.clients.get(endpoint):
            return self.clients[endpoint]

        logger.info('Create Consensus client with endpoint=%s', endpoint)

        self.clients[endpoint] = ExtendedAsyncBeacon(base_url=endpoint)
        return self.clients[endpoint]


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_genesis(client: AsyncBeacon) -> dict:
    """Fetches genesis."""
    request = await client.get_genesis()
    return request['data']


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_finality_checkpoints(client: AsyncBeacon, state_id: str = 'head') -> dict:
    """Fetches finality checkpoints."""
    request = await client.get_finality_checkpoint(state_id)
    return request['data']


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_validator(
    client: AsyncBeacon,
    validator_id: str,
    state_id: str = 'head',
) -> dict:
    """Fetches validators."""
    if not validator_id:
        return {}
    request = await client.get_validator(
        validator_id=validator_id,
        state_id=state_id,
    )
    return request['data']


@backoff.on_exception(backoff.expo, Exception, max_time=300)
async def get_validators(
    client: ExtendedAsyncBeacon,
    public_keys: list[HexStr],
    state_id: str = 'head',
) -> list[dict]:
    """Fetches validators."""
    if not public_keys:
        return []
    request = await client.get_validators_by_ids(
        validator_ids=f"?id={'&id='.join(public_keys)}",
        state_id=state_id,
    )
    return request['data']
