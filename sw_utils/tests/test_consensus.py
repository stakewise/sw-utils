import copy
import dataclasses
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientResponseError
from eth_typing import BlockNumber
from web3.exceptions import BlockNotFound
from web3.types import Timestamp

from sw_utils.consensus import (
    BUILDER_INDEX_FLAG,
    BUILDER_INDEX_SELF_BUILD,
    get_chain_epoch_head,
    get_chain_finalized_head,
    get_chain_justified_head,
    get_chain_latest_head,
    get_chain_slot_head,
    is_builder_index,
)
from sw_utils.exceptions import ExecutionBehindConsensusError
from sw_utils.tests.gloas_data import (
    AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER,
    AFTER_EMPTY_PARENT_SLOT,
    BUILDER_SLOT,
    FULU_BLOCK_NUMBER,
    FULU_SLOT,
    HOODI_CONFIG,
    SELF_BUILD_EXECUTION_BLOCK_NUMBER,
    SELF_BUILD_SLOT,
    SEPOLIA,
    WITHDRAWALS_EXECUTION_BLOCK_NUMBER,
    consensus_ts,
    load_json,
)
from sw_utils.typings import ChainHead

BEACON_BLOCK_FILES = {
    FULU_SLOT: 'beacon_block_hoodi_fulu_4234080.json',
    SELF_BUILD_SLOT: 'beacon_block_sepolia_gloas_self_build_11404096.json',
    BUILDER_SLOT: 'beacon_block_sepolia_gloas_builder_11403711.json',
    AFTER_EMPTY_PARENT_SLOT: 'beacon_block_sepolia_gloas_after_empty_parent_11403712.json',
}
NETWORK_BY_SLOT = {
    FULU_SLOT: HOODI_CONFIG,
    SELF_BUILD_SLOT: SEPOLIA,
    BUILDER_SLOT: SEPOLIA,
    AFTER_EMPTY_PARENT_SLOT: SEPOLIA,
}
EXPECTED_BLOCK_NUMBER_BY_SLOT = {
    FULU_SLOT: FULU_BLOCK_NUMBER,
    SELF_BUILD_SLOT: SELF_BUILD_EXECUTION_BLOCK_NUMBER,
    BUILDER_SLOT: AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER,
    AFTER_EMPTY_PARENT_SLOT: AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER,
}
GLOAS_SLOTS = [SELF_BUILD_SLOT, BUILDER_SLOT, AFTER_EMPTY_PARENT_SLOT]
# Epoch heads walk back from the first slot of the epoch, so only epoch boundary slots can be
# found directly.
EPOCH_START_SLOTS = [slot for slot in BEACON_BLOCK_FILES if slot % 32 == 0]
GLOAS_EPOCH_START_SLOTS = [slot for slot in GLOAS_SLOTS if slot % 32 == 0]


def _load_beacon_block(slot: int) -> dict:
    return load_json(BEACON_BLOCK_FILES[slot])


def _not_found_error() -> ClientResponseError:
    return ClientResponseError(request_info=MagicMock(), history=(), status=404)


@pytest.fixture
def empty_execution_client() -> AsyncMock:
    client = AsyncMock()
    client.eth = AsyncMock()
    client.eth.get_block = AsyncMock(side_effect=BlockNotFound('Block not found'))
    return client


def _consensus_client_with_blocks(blocks_by_slot: dict[int, dict], epoch: int = 0) -> AsyncMock:
    """Serves `blocks_by_slot` by slot number, 404 for the rest. Alias block ids map to the
    block of the highest slot."""
    latest_block = blocks_by_slot[max(blocks_by_slot)]

    async def get_block(block_id: str) -> dict:
        if block_id in ('head', 'finalized'):
            return latest_block
        block = blocks_by_slot.get(int(block_id))
        if block is None:
            raise _not_found_error()
        return block

    client = AsyncMock()
    client.get_block = AsyncMock(side_effect=get_block)
    client.get_finality_checkpoint = AsyncMock(
        return_value={'data': {'current_justified': {'epoch': str(epoch)}}}
    )
    return client


class TestChainHeadFunctions:
    @pytest.mark.parametrize('slot', list(BEACON_BLOCK_FILES))
    @pytest.mark.parametrize('head_function', [get_chain_finalized_head, get_chain_latest_head])
    async def test_finalized_and_latest_head(
        self, head_function: Any, slot: int, execution_client: AsyncMock
    ) -> None:
        network_config = NETWORK_BY_SLOT[slot]
        consensus_client = _consensus_client_with_blocks({slot: _load_beacon_block(slot)})

        chain_head = await head_function(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=network_config,
        )

        assert chain_head == ChainHead(
            epoch=slot // network_config.SLOTS_PER_EPOCH,
            slot=slot,
            block_number=BlockNumber(EXPECTED_BLOCK_NUMBER_BY_SLOT[slot]),
            consensus_ts=Timestamp(consensus_ts(network_config, slot)),
        )

    @pytest.mark.parametrize('slot', EPOCH_START_SLOTS)
    async def test_justified_head(self, slot: int, execution_client: AsyncMock) -> None:
        network_config = NETWORK_BY_SLOT[slot]
        epoch = slot // network_config.SLOTS_PER_EPOCH
        consensus_client = _consensus_client_with_blocks(
            {slot: _load_beacon_block(slot)}, epoch=epoch
        )

        chain_head = await get_chain_justified_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=network_config,
        )

        assert chain_head.epoch == epoch
        assert chain_head.slot == slot
        assert chain_head.block_number == EXPECTED_BLOCK_NUMBER_BY_SLOT[slot]
        assert chain_head.consensus_ts == consensus_ts(network_config, slot)

    @pytest.mark.parametrize('slot', EPOCH_START_SLOTS)
    async def test_epoch_head(self, slot: int, execution_client: AsyncMock) -> None:
        network_config = NETWORK_BY_SLOT[slot]
        epoch = slot // network_config.SLOTS_PER_EPOCH
        consensus_client = _consensus_client_with_blocks({slot: _load_beacon_block(slot)})

        chain_head = await get_chain_epoch_head(
            epoch,
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=network_config,
        )

        assert chain_head.epoch == epoch
        assert chain_head.slot == slot
        assert chain_head.block_number == EXPECTED_BLOCK_NUMBER_BY_SLOT[slot]
        assert chain_head.consensus_ts == consensus_ts(network_config, slot)

    async def test_justified_head_skips_missed_slots(self, execution_client: AsyncMock) -> None:
        # the first slot of the epoch has no block, the closest previous one is used
        epoch = AFTER_EMPTY_PARENT_SLOT // SEPOLIA.SLOTS_PER_EPOCH
        assert epoch * SEPOLIA.SLOTS_PER_EPOCH == AFTER_EMPTY_PARENT_SLOT
        consensus_client = _consensus_client_with_blocks(
            {BUILDER_SLOT: _load_beacon_block(BUILDER_SLOT)}, epoch=epoch
        )

        chain_head = await get_chain_justified_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=SEPOLIA,
        )

        assert chain_head.epoch == epoch
        assert chain_head.slot == BUILDER_SLOT
        assert chain_head.block_number == AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER
        requested_slots = [call.args[0] for call in consensus_client.get_block.call_args_list]
        assert requested_slots == [str(AFTER_EMPTY_PARENT_SLOT), str(BUILDER_SLOT)]

    async def test_epoch_head_skips_missed_slots(self, execution_client: AsyncMock) -> None:
        epoch = AFTER_EMPTY_PARENT_SLOT // SEPOLIA.SLOTS_PER_EPOCH
        consensus_client = _consensus_client_with_blocks(
            {BUILDER_SLOT: _load_beacon_block(BUILDER_SLOT)}
        )

        chain_head = await get_chain_epoch_head(
            epoch,
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=SEPOLIA,
        )

        assert chain_head.epoch == epoch
        assert chain_head.slot == BUILDER_SLOT
        requested_slots = [call.args[0] for call in consensus_client.get_block.call_args_list]
        assert requested_slots == [str(AFTER_EMPTY_PARENT_SLOT), str(BUILDER_SLOT)]

    @pytest.mark.parametrize('head_function', [get_chain_justified_head, get_chain_epoch_head])
    async def test_no_block_in_epoch(self, head_function: Any, execution_client: AsyncMock) -> None:
        consensus_client = _consensus_client_with_blocks({1: {}})
        consensus_client.get_finality_checkpoint.return_value = {
            'data': {'current_justified': {'epoch': '10'}}
        }

        with pytest.raises(RuntimeError, match='Failed to fetch slot for epoch 10'):
            if head_function is get_chain_epoch_head:
                await head_function(
                    10,
                    consensus_client=consensus_client,
                    execution_client=execution_client,
                    network_config=SEPOLIA,
                )
            else:
                await head_function(
                    consensus_client=consensus_client,
                    execution_client=execution_client,
                    network_config=SEPOLIA,
                )

        assert consensus_client.get_block.call_count == SEPOLIA.SLOTS_PER_EPOCH

    async def test_non_404_error_is_propagated(self, execution_client: AsyncMock) -> None:
        consensus_client = AsyncMock()
        error = ClientResponseError(request_info=MagicMock(), history=(), status=500)
        consensus_client.get_block = AsyncMock(side_effect=error)

        with pytest.raises(ClientResponseError):
            await get_chain_epoch_head(
                10,
                consensus_client=consensus_client,
                execution_client=execution_client,
                network_config=SEPOLIA,
            )

    @pytest.mark.parametrize('slot', list(BEACON_BLOCK_FILES))
    async def test_consensus_ts_is_derived_from_slot(
        self, slot: int, execution_client: AsyncMock
    ) -> None:
        network_config = NETWORK_BY_SLOT[slot]
        consensus_client = _consensus_client_with_blocks({slot: _load_beacon_block(slot)})

        chain_head = await get_chain_latest_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=network_config,
        )

        assert chain_head.consensus_ts == (
            network_config.GENESIS_TIMESTAMP + slot * network_config.SECONDS_PER_SLOT
        )

    async def test_fulu_block_does_not_call_execution_client(
        self, execution_client: AsyncMock
    ) -> None:
        consensus_client = _consensus_client_with_blocks({FULU_SLOT: _load_beacon_block(FULU_SLOT)})

        await get_chain_finalized_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=HOODI_CONFIG,
        )

        execution_client.eth.get_block.assert_not_called()

    async def test_fulu_consensus_ts_equals_payload_timestamp(
        self, execution_client: AsyncMock
    ) -> None:
        block = _load_beacon_block(FULU_SLOT)
        consensus_client = _consensus_client_with_blocks({FULU_SLOT: block})

        chain_head = await get_chain_finalized_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=HOODI_CONFIG,
        )

        payload_timestamp = int(block['data']['message']['body']['execution_payload']['timestamp'])
        assert chain_head.consensus_ts == payload_timestamp

    @pytest.mark.parametrize('slot', GLOAS_SLOTS)
    async def test_gloas_block_resolves_parent_block_hash(
        self, slot: int, execution_client: AsyncMock
    ) -> None:
        block = _load_beacon_block(slot)
        parent_block_hash = block['data']['message']['body']['signed_execution_payload_bid'][
            'message'
        ]['parent_block_hash']
        consensus_client = _consensus_client_with_blocks({slot: block})

        await get_chain_finalized_head(
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=SEPOLIA,
        )

        execution_client.eth.get_block.assert_awaited_once_with(parent_block_hash)

    async def test_gloas_empty_parent_payload_is_skipped(self, execution_client: AsyncMock) -> None:
        # the payload of BUILDER_SLOT was not delivered, so both slots resolve to the same EL block
        builder_head = await get_chain_finalized_head(
            consensus_client=_consensus_client_with_blocks(
                {BUILDER_SLOT: _load_beacon_block(BUILDER_SLOT)}
            ),
            execution_client=execution_client,
            network_config=SEPOLIA,
        )
        next_head = await get_chain_finalized_head(
            consensus_client=_consensus_client_with_blocks(
                {AFTER_EMPTY_PARENT_SLOT: _load_beacon_block(AFTER_EMPTY_PARENT_SLOT)}
            ),
            execution_client=execution_client,
            network_config=SEPOLIA,
        )

        assert builder_head.slot + 1 == next_head.slot
        assert builder_head.block_number == next_head.block_number
        assert next_head.block_number == AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER

    @pytest.mark.parametrize('slot', GLOAS_EPOCH_START_SLOTS)
    @pytest.mark.parametrize(
        'head_function',
        [get_chain_finalized_head, get_chain_justified_head, get_chain_latest_head],
    )
    async def test_gloas_execution_behind_consensus(
        self, head_function: Any, slot: int, empty_execution_client: AsyncMock
    ) -> None:
        block = _load_beacon_block(slot)
        parent_block_hash = block['data']['message']['body']['signed_execution_payload_bid'][
            'message'
        ]['parent_block_hash']
        epoch = slot // SEPOLIA.SLOTS_PER_EPOCH
        consensus_client = _consensus_client_with_blocks({slot: block}, epoch=epoch)

        with pytest.raises(ExecutionBehindConsensusError) as exc_info:
            await head_function(
                consensus_client=consensus_client,
                execution_client=empty_execution_client,
                network_config=SEPOLIA,
            )

        assert isinstance(exc_info.value, BlockNotFound)
        assert parent_block_hash in str(exc_info.value)
        assert str(slot) in str(exc_info.value)

    async def test_gloas_epoch_head_execution_behind_consensus(
        self, empty_execution_client: AsyncMock
    ) -> None:
        consensus_client = _consensus_client_with_blocks(
            {SELF_BUILD_SLOT: _load_beacon_block(SELF_BUILD_SLOT)}
        )
        epoch = SELF_BUILD_SLOT // SEPOLIA.SLOTS_PER_EPOCH

        with pytest.raises(BlockNotFound):
            await get_chain_epoch_head(
                epoch,
                consensus_client=consensus_client,
                execution_client=empty_execution_client,
                network_config=SEPOLIA,
            )

    @pytest.mark.parametrize('slot', GLOAS_EPOCH_START_SLOTS)
    async def test_gloas_epoch_head_ignores_eth1_data(
        self, slot: int, execution_client: AsyncMock
    ) -> None:
        # Gloas blocks have no `execution_payload`, the frozen `eth1_data.block_hash`
        # must never be used to find the execution block.
        block = _load_beacon_block(slot)
        eth1_block_hash = block['data']['message']['body']['eth1_data']['block_hash']
        parent_block_hash = block['data']['message']['body']['signed_execution_payload_bid'][
            'message'
        ]['parent_block_hash']
        assert 'execution_payload' not in block['data']['message']['body']
        assert eth1_block_hash != parent_block_hash
        consensus_client = _consensus_client_with_blocks({slot: block})

        chain_head = await get_chain_epoch_head(
            slot // SEPOLIA.SLOTS_PER_EPOCH,
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=SEPOLIA,
        )

        assert chain_head.block_number == EXPECTED_BLOCK_NUMBER_BY_SLOT[slot]
        execution_client.eth.get_block.assert_awaited_once_with(parent_block_hash)

    @pytest.mark.parametrize(
        'head_function',
        [get_chain_finalized_head, get_chain_justified_head, get_chain_latest_head],
    )
    async def test_unsupported_block_body_is_rejected(
        self, head_function: Any, execution_client: AsyncMock
    ) -> None:
        pre_merge_block = copy.deepcopy(_load_beacon_block(FULU_SLOT))
        body = pre_merge_block['data']['message']['body']
        del body['execution_payload']
        slot = int(pre_merge_block['data']['message']['slot'])
        assert 'signed_execution_payload_bid' not in body
        consensus_client = _consensus_client_with_blocks(
            {slot: pre_merge_block}, epoch=slot // HOODI_CONFIG.SLOTS_PER_EPOCH
        )

        with pytest.raises(
            ValueError, match=f'Unsupported beacon block body at slot {slot} \\(version='
        ):
            await head_function(
                consensus_client=consensus_client,
                execution_client=execution_client,
                network_config=HOODI_CONFIG,
            )

        execution_client.eth.get_block.assert_not_called()


class TestChainHead:
    def test_execution_ts_is_not_a_constructor_argument(self) -> None:
        with pytest.raises(TypeError):
            ChainHead(  # type: ignore[call-arg]  # pylint: disable=unexpected-keyword-arg
                epoch=1,
                slot=32,
                block_number=BlockNumber(5),
                execution_ts=Timestamp(1700000000),
            )

    def test_asdict_contains_only_fields(self) -> None:
        chain_head = ChainHead(
            epoch=1, slot=32, block_number=BlockNumber(5), consensus_ts=Timestamp(1700000000)
        )

        data = dataclasses.asdict(chain_head)

        assert data == {'epoch': 1, 'slot': 32, 'block_number': 5, 'consensus_ts': 1700000000}
        assert ChainHead(**data) == chain_head


class TestGetChainSlotHead:
    @pytest.mark.parametrize('slot', list(BEACON_BLOCK_FILES))
    async def test_slot_head(self, slot: int, execution_client: AsyncMock) -> None:
        network_config = NETWORK_BY_SLOT[slot]
        consensus_client = _consensus_client_with_blocks({slot: _load_beacon_block(slot)})

        chain_head = await get_chain_slot_head(
            slot,
            consensus_client=consensus_client,
            execution_client=execution_client,
            network_config=network_config,
        )

        assert chain_head == ChainHead(
            epoch=slot // network_config.SLOTS_PER_EPOCH,
            slot=slot,
            block_number=BlockNumber(EXPECTED_BLOCK_NUMBER_BY_SLOT[slot]),
            consensus_ts=Timestamp(consensus_ts(network_config, slot)),
        )
        consensus_client.get_block.assert_awaited_once_with(str(slot))

    async def test_missed_slot(self, execution_client: AsyncMock) -> None:
        consensus_client = _consensus_client_with_blocks(
            {SELF_BUILD_SLOT: _load_beacon_block(SELF_BUILD_SLOT)}
        )

        with pytest.raises(ClientResponseError) as exc_info:
            await get_chain_slot_head(
                SELF_BUILD_SLOT + 1,
                consensus_client=consensus_client,
                execution_client=execution_client,
                network_config=SEPOLIA,
            )

        assert exc_info.value.status == 404
        execution_client.eth.get_block.assert_not_called()


class TestIsBuilderIndex:
    @pytest.mark.parametrize(
        'validator_index, expected',
        [
            (0, False),
            (1_234_567, False),
            (BUILDER_INDEX_FLAG - 1, False),
            (BUILDER_INDEX_FLAG, True),
            (BUILDER_INDEX_FLAG | 42, True),
        ],
    )
    def test_is_builder_index(self, validator_index: int, expected: bool) -> None:
        assert is_builder_index(validator_index) is expected

    def test_fixture_builder_withdrawals(self, sepolia_execution_blocks: dict[str, dict]) -> None:
        withdrawals = sepolia_execution_blocks[str(WITHDRAWALS_EXECUTION_BLOCK_NUMBER)][
            'withdrawals'
        ]

        builder_withdrawals = [w for w in withdrawals if is_builder_index(w['validatorIndex'])]

        assert builder_withdrawals
        assert all(w['validatorIndex'] >= 2**40 for w in builder_withdrawals)

    def test_self_build_bid(self) -> None:
        bid = _load_beacon_block(SELF_BUILD_SLOT)['data']['message']['body'][
            'signed_execution_payload_bid'
        ]['message']
        assert int(bid['builder_index']) == BUILDER_INDEX_SELF_BUILD
        assert int(bid['value']) == 0
