import random
from unittest import mock

import pytest
from attr import dataclass
from eth_typing import BlockNumber
from web3.types import EventData

from sw_utils.event_scanner import EventProcessor, EventScanner


class MockedEventProcessor(EventProcessor):
    contract_event = 'event'

    @staticmethod
    async def get_from_block() -> BlockNumber:
        return BlockNumber(777)

    @staticmethod
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
        pass


async def fetch_events(a, b):
    return []


async def fetch_events_broken(a, b):
    raise ConnectionError


class TestEventScanner:
    async def test_basic(self):
        default_chunk_size = 500000
        p = MockedEventProcessor()
        scanner = EventScanner(processor=p)
        scanner._contract_call = fetch_events
        assert scanner.chunk_size == default_chunk_size

        scanner._contract_call = fetch_events_broken
        scanner.request_retry_seconds = 0
        scanner.max_request_retries = 1
        with pytest.raises(ConnectionError):
            await scanner.process_new_events(888)
        assert scanner.chunk_size == default_chunk_size

        scanner.max_request_retries = 2
        with pytest.raises(ConnectionError):
            await scanner.process_new_events(888)
        assert scanner.chunk_size == default_chunk_size // 2

        scanner.max_request_retries = 3
        with pytest.raises(ConnectionError):
            await scanner.process_new_events(888)
        assert scanner.chunk_size == default_chunk_size // 8


@dataclass
class EventScannerDB:
    last_processed_block: BlockNumber | None = None
    event_blocks: list[int] = []

    def clear(self):
        self.last_processed_block = None
        self.event_blocks = []


db = EventScannerDB()


class SimpleEventProcessor(EventProcessor):
    contract_event = 'event'

    @staticmethod
    async def get_from_block() -> BlockNumber:
        return 700

    @staticmethod
    async def process_events(events: list[EventData], to_block: BlockNumber) -> None:
        db.event_blocks.extend([event['blockNumber'] for event in events])
        db.last_processed_block = to_block


class TestEventScannerFuzzing:
    """
    Assume that event.get_logs() will raise Exception with 50% probability.
    Check that all events are scanned and processed.
    """

    async def test_fuzzing(self):
        for _ in range(100):
            try:
                await self._run_single_test()
            finally:
                db.clear()

    async def _run_single_test(self):
        p = SimpleEventProcessor()
        from_block = await p.get_from_block()

        with mock.patch.object(EventScanner, 'max_scan_chunk_size', 1000):
            scanner = EventScanner(processor=p)
            event = MockedAsyncEvent()
            scanner._contract_call = event.fetch_events
            scanner.request_retry_seconds = 0
            to_block = 10_000

            await scanner.process_new_events(to_block=to_block)

            assert db.event_blocks == list(range(from_block, to_block + 1))
            assert db.last_processed_block == to_block


class MockedAsyncEvent:
    async def fetch_events(self, from_block, to_block) -> list[EventData]:
        """
        Raises Exception with 50% probability.
        Returns list of events otherwise.
        Single event per block.
        """
        is_fail = random.randint(0, 1)
        if is_fail:
            raise ConnectionError
        return [
            self._get_mocked_event_data(block_number)
            for block_number in range(from_block, to_block + 1)
        ]

    def _get_mocked_event_data(self, block_number) -> EventData:
        return {
            'address': '0x0',
            'args': {},
            'blockHash': '0x0',
            'blockNumber': block_number,
            'event': 'event',
            'logIndex': 0,
            'transactionHash': '0x0',
            'transactionIndex': 0,
        }
