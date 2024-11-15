import logging
from abc import ABC, abstractmethod
from asyncio import sleep
from typing import Any

from eth_typing import BlockNumber
from web3.contract import AsyncContract
from web3.types import EventData

logger = logging.getLogger(__name__)


class EventProcessor(ABC):
    """
    Processor of the events.
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
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
        """Process incoming events.
        This function takes raw events from Web3, transforms them to application's internal
        format, then saves it in a database.

        :param events: List of the event data
        :param to_block: the last block number of the scanned chunk
        """


class EventScanner:
    min_scan_chunk_size = 10
    max_scan_chunk_size = 1_000_000
    chunk_size_multiplier = 2
    max_request_retries = 30
    request_retry_seconds = 3

    def __init__(
        self,
        processor: EventProcessor,
        argument_filters: dict[str, Any] | None = None,
        chunk_size: int | None = None,
    ):
        self.processor = processor
        self.argument_filters = argument_filters
        self._contract_call = lambda from_block, to_block: getattr(
            processor.contract.events, processor.contract_event
        ).get_logs(argument_filters=argument_filters, fromBlock=from_block, toBlock=to_block)
        # todo: remove type ignore after move Contract wrapper to sw-utils
        self.provider = self.processor.contract.contract.w3.provider  # type: ignore
        # Scan in chunks, commit between
        self.chunk_size = chunk_size or self.max_scan_chunk_size // 2

    async def process_new_events(self, to_block: BlockNumber) -> None:
        current_from_block = await self.processor.get_from_block()
        if current_from_block >= to_block:
            return

        while current_from_block < to_block:
            current_to_block, new_events = await self._scan_chunk(current_from_block, to_block)
            await self.processor.process_events(new_events, to_block=current_to_block)

            if new_events:
                logger.info(
                    'Scanned %s event: count=%d, block=%d/%d/%d',
                    self.processor.contract_event,
                    len(new_events),
                    current_from_block,
                    current_to_block,
                    to_block,
                )

            # Try to increase blocks range for the next time
            self._estimate_next_chunk_size()
            # Set where the next chunk starts
            current_from_block = BlockNumber(current_to_block + 1)

    async def _scan_chunk(
        self, from_block: BlockNumber, last_block: BlockNumber
    ) -> tuple[BlockNumber, list[EventData]]:
        """
        Read and process events between block numbers.
        Dynamically decrease the size of the chunk if the case JSON-RPC server pukes out.
        :return: tuple(actual end block number, events)
        """
        retries = self.max_request_retries
        for i in range(retries):
            to_block = min(last_block, BlockNumber(from_block + self.chunk_size))
            try:
                with self.provider.disable_retries():
                    return to_block, await self._contract_call(from_block, to_block)
            except Exception as e:
                if i < retries - 1:
                    # Decrease the `eth_getBlocks` range
                    self.chunk_size = self.chunk_size // 2
                    to_block = BlockNumber(from_block + self.chunk_size)
                    # Let the JSON-RPC to recover e.g. from restart
                    await sleep(self.request_retry_seconds)
                    continue

                raise e

        raise RuntimeError(f'Failed to sync chunk: from block={from_block}, to block={last_block}')

    def _estimate_next_chunk_size(self) -> None:
        self.chunk_size *= self.chunk_size_multiplier
        self.chunk_size = max(self.min_scan_chunk_size, self.chunk_size)
        self.chunk_size = min(self.max_scan_chunk_size, self.chunk_size)
