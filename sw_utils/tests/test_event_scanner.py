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
        s = EventScanner(processor=p)
        s._contract_call = fetch_events
        assert s.chunk_size == default_chunk_size

        s._contract_call = fetch_events_broken
        s.max_request_retries = 1
        with pytest.raises(ConnectionError):
            await s.process_new_events(888)
            assert s.chunk_size == default_chunk_size / 2

            await s.process_new_events(888)
            assert s.chunk_size == default_chunk_size / 4
