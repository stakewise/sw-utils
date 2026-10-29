from unittest.mock import AsyncMock

import pytest
from web3.exceptions import BlockNotFound

from sw_utils.tests.gloas_data import load_json


@pytest.fixture
def sepolia_execution_blocks() -> dict[str, dict]:
    return load_json('sepolia_execution_blocks.json')


@pytest.fixture
def execution_client(sepolia_execution_blocks: dict[str, dict]) -> AsyncMock:
    """Resolves Sepolia EL blocks by hash or number, raises BlockNotFound for others."""
    blocks_by_hash = {block['hash']: block for block in sepolia_execution_blocks.values()}

    async def get_block(block_identifier: str | int) -> dict:
        if isinstance(block_identifier, int):
            block = sepolia_execution_blocks.get(str(block_identifier))
        else:
            block = blocks_by_hash.get(block_identifier)
        if block is None:
            raise BlockNotFound(f'Block {block_identifier} not found')
        return block

    client = AsyncMock()
    client.eth = AsyncMock()
    client.eth.get_block = AsyncMock(side_effect=get_block)
    return client
