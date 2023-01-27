from enum import Enum
from typing import Any, Dict

from eth_typing import URI
from web3._utils.request import async_json_make_get_request
from web3.beacon import AsyncBeacon

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


class ExtendedAsyncBeacon(AsyncBeacon):
    def __init__(
        self,
        base_url: str,
        timeout: int = 60
    ) -> None:
        super().__init__(base_url)
        self.timeout = timeout

    async def get_validators_by_ids(
        self, validator_ids: list[str], state_id: str = 'head'
    ) -> dict:
        endpoint = GET_VALIDATORS.format(state_id, f"?id={'&id='.join(validator_ids)}")
        return await self._async_make_get_request(endpoint)

    async def _async_make_get_request(self, endpoint_uri: str) -> Dict[str, Any]:
        uri = URI(self.base_url + endpoint_uri)
        return await async_json_make_get_request(uri, timeout=self.timeout)


def get_consensus_client(endpoint: str) -> ExtendedAsyncBeacon:
    return ExtendedAsyncBeacon(base_url=endpoint)
