from unittest.mock import AsyncMock

import pytest
from eth_typing import BlockNumber
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from sw_utils.exceptions import ExecutionBehindConsensusError
from sw_utils.execution import get_payload_expected_withdrawals
from sw_utils.networks import MAINNET, NETWORKS
from sw_utils.tests.glamsterdam_data import (
    AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER,
    AFTER_EMPTY_PARENT_SLOT,
    FULU_BLOCK_NUMBER,
    FULU_SLOT,
    GLAMSTERDAM_CONFIG,
    HOODI_CONFIG,
    SELF_BUILD_EXECUTION_BLOCK_NUMBER,
    SELF_BUILD_SLOT,
    consensus_ts,
)
from sw_utils.typings import ChainHead

MAINNET_CONFIG = NETWORKS[MAINNET]

# The only EL block with fixture withdrawals: follows `SELF_BUILD_EXECUTION_BLOCK_NUMBER`.
WITHDRAWALS_EXECUTION_BLOCK_NUMBER = 11962173


class TestGetPayloadExpectedWithdrawals:
    async def test_pre_glamsterdam_returns_empty_list(self, execution_client: AsyncMock) -> None:
        chain_head = ChainHead(
            epoch=FULU_SLOT // HOODI_CONFIG.SLOTS_PER_EPOCH,
            slot=FULU_SLOT,
            block_number=BlockNumber(FULU_BLOCK_NUMBER),
            consensus_ts=Timestamp(consensus_ts(HOODI_CONFIG, FULU_SLOT)),
        )
        assert chain_head.slot < HOODI_CONFIG.GLAMSTERDAM_SLOT

        withdrawals = await get_payload_expected_withdrawals(
            execution_client, chain_head, HOODI_CONFIG
        )

        assert withdrawals == []
        execution_client.eth.get_block.assert_not_called()

    async def test_unscheduled_glamsterdam_returns_empty_list(
        self, execution_client: AsyncMock
    ) -> None:
        chain_head = ChainHead(
            epoch=1, slot=32, block_number=BlockNumber(5), consensus_ts=Timestamp(1700000000)
        )

        withdrawals = await get_payload_expected_withdrawals(
            execution_client, chain_head, MAINNET_CONFIG
        )

        assert withdrawals == []
        execution_client.eth.get_block.assert_not_called()

    async def test_glamsterdam_returns_withdrawals_of_next_block(
        self, execution_client: AsyncMock, glamsterdam_execution_blocks: dict[str, dict]
    ) -> None:
        chain_head = ChainHead(
            epoch=SELF_BUILD_SLOT // GLAMSTERDAM_CONFIG.SLOTS_PER_EPOCH,
            slot=SELF_BUILD_SLOT,
            block_number=BlockNumber(SELF_BUILD_EXECUTION_BLOCK_NUMBER),
            consensus_ts=Timestamp(consensus_ts(GLAMSTERDAM_CONFIG, SELF_BUILD_SLOT)),
        )
        assert chain_head.slot >= GLAMSTERDAM_CONFIG.GLAMSTERDAM_SLOT

        withdrawals = await get_payload_expected_withdrawals(
            execution_client, chain_head, GLAMSTERDAM_CONFIG
        )

        expected = glamsterdam_execution_blocks[str(WITHDRAWALS_EXECUTION_BLOCK_NUMBER)][
            'withdrawals'
        ]
        assert withdrawals == expected
        assert len(withdrawals) == 16
        # builder withdrawal: validator index has the builder flag bit set
        assert any(withdrawal['validatorIndex'] >= 2**40 for withdrawal in withdrawals)
        execution_client.eth.get_block.assert_awaited_once_with(WITHDRAWALS_EXECUTION_BLOCK_NUMBER)

    async def test_glamsterdam_missing_next_block(self, execution_client: AsyncMock) -> None:
        chain_head = ChainHead(
            epoch=AFTER_EMPTY_PARENT_SLOT // GLAMSTERDAM_CONFIG.SLOTS_PER_EPOCH,
            slot=AFTER_EMPTY_PARENT_SLOT,
            block_number=BlockNumber(AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER),
            consensus_ts=Timestamp(consensus_ts(GLAMSTERDAM_CONFIG, AFTER_EMPTY_PARENT_SLOT)),
        )

        with pytest.raises(ExecutionBehindConsensusError) as exc_info:
            await get_payload_expected_withdrawals(execution_client, chain_head, GLAMSTERDAM_CONFIG)

        assert isinstance(exc_info.value, BlockNotFound)
        assert str(AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER + 1) in str(exc_info.value)
