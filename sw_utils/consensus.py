import logging
from enum import Enum

from web3.beacon import AsyncBeacon

from sw_utils.common import Singleton

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
        self, validator_ids: list[str], state_id: str = 'head'
    ) -> dict:
        endpoint = GET_VALIDATORS.format(state_id, f"?id={'&id='.join(validator_ids)}")
        return await self._async_make_get_request(endpoint)


class ConsensusClient(metaclass=Singleton):
    clients: dict[str, ExtendedAsyncBeacon] = {}

    async def get_client(self, endpoint: str) -> ExtendedAsyncBeacon:
        if self.clients.get(endpoint):
            return self.clients[endpoint]

        logger.info('Create Consensus client with endpoint=%s', endpoint)

        self.clients[endpoint] = ExtendedAsyncBeacon(base_url=endpoint)
        return self.clients[endpoint]
