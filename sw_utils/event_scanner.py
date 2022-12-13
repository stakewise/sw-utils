import logging
from abc import ABC, abstractmethod
from asyncio import sleep
from typing import Any, Dict, List, Optional, Tuple

from eth_typing import BlockNumber
from web3.contract import AsyncContract
from web3.types import EventData

logger = logging.getLogger(__name__)


class EventScannerState(ABC):
    """
    Application state that remembers what blocks we have scanned in the case of crash.
    """
    contract: AsyncContract
    contract_event: str

    @staticmethod
    @abstractmethod
    async def get_from_block() -> BlockNumber:
        """
        This function takes the latest entry from the database and returns
        the block at which the corresponding event was synced.

        :return: The block number to start scanning from
        """

    @staticmethod
    @abstractmethod
    async def process_events(events: List[EventData]) -> None:
        """Process incoming events.
        This function takes raw events from Web3, transforms them to application's internal
        format, then saves it in a database.

        :param events: List of the event data
        """


class EventScanner:
    min_scan_chunk_size = 10
    max_scan_chunk_size = 1_000_000
    chunk_size_multiplier = 2
    max_request_retries = 30
    request_retry_seconds = 3

    def __init__(
        self,
        state: EventScannerState,
        argument_filters: Optional[Dict[str, Any]] = None,
    ):
        self.state = state
        self.argument_filters = argument_filters
        self._contract_call = lambda from_block, to_block: getattr(
            state.contract.events, state.contract_event
        ).getLogs(argument_filters=argument_filters, fromBlock=from_block, toBlock=to_block)

    async def process_new_events(self, to_block: BlockNumber) -> None:
        current_from_block = await self.state.get_from_block()
        if current_from_block >= to_block:
            return

        # Scan in chunks, commit between
        chunk_size = self.max_scan_chunk_size

        while current_from_block < to_block:
            estimated_end_block = min(to_block, BlockNumber(current_from_block + chunk_size))
            current_to_block, new_events = await self._scan_chunk(
                current_from_block, estimated_end_block
            )
            await self.state.process_events(new_events)

            if new_events:
                logger.info(
                    'Scanned %s events: %d/%d blocks',
                    self.state.contract_event,
                    current_to_block,
                    to_block
                )

            # Try to guess how many blocks to fetch over `eth_getLogs` API next time
            chunk_size = self._estimate_next_chunk_size(chunk_size)

            # Set where the next chunk starts
            current_from_block = BlockNumber(current_to_block + 1)

    async def _scan_chunk(
        self, from_block: BlockNumber, to_block: BlockNumber
    ) -> Tuple[BlockNumber, List[EventData]]:
        """
        Read and process events between block numbers.
        Dynamically decrease the size of the chunk if the case JSON-RPC server pukes out.
        :return: tuple(actual end block number, events)
        """
        retries = self.max_request_retries
        for i in range(retries):
            try:
                return to_block, await self._contract_call(from_block, to_block)
            except Exception as e:
                if i < retries - 1:
                    # Decrease the `eth_getBlocks` range
                    to_block = BlockNumber(from_block + ((to_block - from_block) // 2))
                    # Let the JSON-RPC to recover e.g. from restart
                    await sleep(self.request_retry_seconds)
                    continue

                raise e

        raise RuntimeError(f'Failed to sync chunk: from block={from_block}, to block={to_block}')

    def _estimate_next_chunk_size(self, current_chuck_size: int) -> int:
        current_chuck_size *= self.chunk_size_multiplier
        current_chuck_size = max(self.min_scan_chunk_size, current_chuck_size)
        current_chuck_size = min(self.max_scan_chunk_size, current_chuck_size)
        return current_chuck_size
