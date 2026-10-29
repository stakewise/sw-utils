from unittest.mock import AsyncMock

import pytest
from eth_typing import BlockNumber
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from sw_utils.exceptions import ExecutionBehindConsensusError
from sw_utils.execution import get_payload_expected_withdrawals
from sw_utils.tests.gloas_data import (
    AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER,
    AFTER_EMPTY_PARENT_SLOT,
    FULU_BLOCK_NUMBER,
    FULU_SLOT,
    HOODI_CONFIG,
    SELF_BUILD_EXECUTION_BLOCK_NUMBER,
    SELF_BUILD_SLOT,
    SEPOLIA,
    WITHDRAWALS_EXECUTION_BLOCK_NUMBER,
    slot_ts,
)
from sw_utils.typings import ChainHead


class TestGetPayloadExpectedWithdrawals:
    async def test_pre_gloas_returns_empty_list(self, execution_client: AsyncMock) -> None:
        chain_head = ChainHead(
            epoch=FULU_SLOT // HOODI_CONFIG.SLOTS_PER_EPOCH,
            slot=FULU_SLOT,
            slot_ts=Timestamp(slot_ts(HOODI_CONFIG, FULU_SLOT)),
            is_gloas=False,
            latest_block_number=BlockNumber(FULU_BLOCK_NUMBER),
        )
        withdrawals = await get_payload_expected_withdrawals(execution_client, chain_head)

        assert withdrawals == []
        execution_client.eth.get_block.assert_not_called()

    async def test_gloas_returns_withdrawals_of_next_block(
        self, execution_client: AsyncMock, sepolia_execution_blocks: dict[str, dict]
    ) -> None:
        chain_head = ChainHead(
            epoch=SELF_BUILD_SLOT // SEPOLIA.SLOTS_PER_EPOCH,
            slot=SELF_BUILD_SLOT,
            slot_ts=Timestamp(slot_ts(SEPOLIA, SELF_BUILD_SLOT)),
            is_gloas=True,
            latest_block_number=BlockNumber(SELF_BUILD_EXECUTION_BLOCK_NUMBER),
        )
        withdrawals = await get_payload_expected_withdrawals(execution_client, chain_head)

        expected = sepolia_execution_blocks[str(WITHDRAWALS_EXECUTION_BLOCK_NUMBER)]['withdrawals']
        assert withdrawals == expected
        assert len(withdrawals) == 16
        # builder withdrawal: validator index has the builder flag bit set
        assert any(withdrawal['validatorIndex'] >= 2**40 for withdrawal in withdrawals)
        execution_client.eth.get_block.assert_awaited_once_with(WITHDRAWALS_EXECUTION_BLOCK_NUMBER)

    async def test_gloas_missing_next_block(self, execution_client: AsyncMock) -> None:
        chain_head = ChainHead(
            epoch=AFTER_EMPTY_PARENT_SLOT // SEPOLIA.SLOTS_PER_EPOCH,
            slot=AFTER_EMPTY_PARENT_SLOT,
            slot_ts=Timestamp(slot_ts(SEPOLIA, AFTER_EMPTY_PARENT_SLOT)),
            is_gloas=True,
            latest_block_number=BlockNumber(AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER),
        )

        with pytest.raises(ExecutionBehindConsensusError) as exc_info:
            await get_payload_expected_withdrawals(execution_client, chain_head)

        assert isinstance(exc_info.value, BlockNotFound)
        assert str(AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER + 1) in str(exc_info.value)
