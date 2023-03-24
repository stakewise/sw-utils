import logging
from enum import Enum
from typing import Any, Dict, List

from eth_typing import URI
from web3._utils.request import async_json_make_get_request
from web3.beacon import AsyncBeacon

from .execution import NoActiveProviderError

GET_VALIDATORS = '/eth/v1/beacon/states/{0}/validators{1}'

logger = logging.getLogger(__name__)


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


PENDING_STATUSES = [ValidatorStatus.PENDING_INITIALIZED,
                    ValidatorStatus.PENDING_QUEUED]
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
    """
    Provider with support for fallback endpoints.
    """



    def __init__(
        self,
        base_urls: List[str],
        timeout: int = 60
    ) -> None:
        self.base_urls = base_urls
        self.timeout = timeout

    async def get_validators_by_ids(
        self, validator_ids: list[str], state_id: str = 'head'
    ) -> dict:
        endpoint = GET_VALIDATORS.format(
            state_id, f"?id={'&id='.join(validator_ids)}")
        return await self._async_make_get_request(endpoint)

    async def _async_make_get_request(self, endpoint_uri: str) -> Dict[str, Any]:
        for i, url in enumerate(self.base_urls):
            try:
                uri = URI(url + endpoint_uri)
                response = await async_json_make_get_request(uri, timeout=self.timeout)
                break
            except Exception as error:  # pylint: disable=W0703
                if i == len(self.base_urls)-1:
                    msg = "No active provider available."
                    logger.error({"msg": msg})
                    raise NoActiveProviderError(msg) from error

                logger.warning(
                    {
                        "msg": "Provider not responding.",
                        "error": str(error),
                        "provider": url,
                    }
                )

        return response


def get_consensus_client(endpoint: str, timeout: int = 60) -> ExtendedAsyncBeacon:
    return ExtendedAsyncBeacon(base_urls=endpoint.split(","), timeout=timeout)
