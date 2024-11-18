import pytest
from eth_typing import BlockNumber
from web3.types import EventData

from sw_utils.event_scanner import EventProcessor, EventScanner


class MockedEventProcessor(EventProcessor):
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


class TestExitSignatureCrud:
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
