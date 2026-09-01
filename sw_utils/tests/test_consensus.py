from unittest import mock
from unittest.mock import AsyncMock

import pytest
from aiohttp import ClientResponseError
from web3.exceptions import BlockNotFound

from sw_utils.consensus import (
    get_chain_epoch_head,
    get_chain_finalized_head,
    get_chain_justified_head,
    get_chain_latest_head,
)
from sw_utils.tests import faker

MAINNET_SLOTS_PER_EPOCH = 32
GNOSIS_SLOTS_PER_EPOCH = 16

NOT_FOUND_ERROR = ClientResponseError(status=404, request_info=None, history=None)


def _block_response(slot: int, block_number: int | None = None, timestamp: int | None = None):
    return {
        'data': {
            'message': {
                'slot': str(slot),
                'body': {
                    'execution_payload': {
                        'block_number': str(block_number or faker.random_int(1, 10_000)),
                        'timestamp': str(timestamp or faker.random_int(1, 10_000)),
                    }
                },
            }
        }
    }


def _pre_shapella_block_response(slot: int, block_hash: str | None = None):
    return {
        'data': {
            'message': {
                'slot': str(slot),
                'body': {'eth1_data': {'block_hash': block_hash or faker.eth_proof()}},
            }
        }
    }


def _finality_checkpoint_response(justified_epoch: int):
    return {
        'data': {
            'previous_justified': {'epoch': str(justified_epoch - 1)},
            'current_justified': {'epoch': str(justified_epoch)},
            'finalized': {'epoch': str(justified_epoch - 1)},
        }
    }


class TestGetChainEpochHead:
    async def test_first_slot_proposed(self):
        """Common case: the epoch's first slot was proposed, returned unchanged."""
        epoch, slots_per_epoch = 10, MAINNET_SLOTS_PER_EPOCH
        first_slot = epoch * slots_per_epoch
        block_data = _block_response(first_slot, block_number=777, timestamp=888)

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(return_value=block_data)
        execution_client = mock.Mock()

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.epoch == epoch
        assert head.slot == first_slot
        assert head.block_number == 777
        assert head.execution_ts == 888
        consensus_client.get_block.assert_awaited_once_with(str(first_slot))

    async def test_first_slots_missed_returns_slot_inside_requested_epoch(self):
        """Regression guard: when the epoch's first slots are missed, the returned slot
        must still lie inside the requested epoch, keeping epoch == slot // slots_per_epoch."""
        epoch, slots_per_epoch = 10, MAINNET_SLOTS_PER_EPOCH
        first_slot = epoch * slots_per_epoch
        missed_slots = {first_slot, first_slot + 1, first_slot + 2}
        proposed_slot = first_slot + 3
        block_data = _block_response(proposed_slot)

        async def get_block(slot_id: str):
            if int(slot_id) in missed_slots:
                raise NOT_FOUND_ERROR
            return block_data

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(side_effect=get_block)
        execution_client = mock.Mock()

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.slot == proposed_slot
        assert head.slot >= first_slot
        assert head.epoch == epoch
        assert head.epoch == head.slot // slots_per_epoch

    async def test_gnosis_shaped_first_slots_missed(self):
        epoch, slots_per_epoch = 100, GNOSIS_SLOTS_PER_EPOCH
        first_slot = epoch * slots_per_epoch
        missed_slots = {first_slot, first_slot + 1}
        proposed_slot = first_slot + 2
        block_data = _block_response(proposed_slot)

        async def get_block(slot_id: str):
            if int(slot_id) in missed_slots:
                raise NOT_FOUND_ERROR
            return block_data

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(side_effect=get_block)
        execution_client = mock.Mock()

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.slot == proposed_slot
        assert head.epoch == epoch
        assert head.epoch == head.slot // slots_per_epoch

    async def test_all_slots_missed_raises(self):
        epoch, slots_per_epoch = 10, MAINNET_SLOTS_PER_EPOCH

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(side_effect=NOT_FOUND_ERROR)
        execution_client = mock.Mock()

        with pytest.raises(RuntimeError, match=f'Failed to fetch slot for epoch {epoch}'):
            await get_chain_epoch_head(epoch, slots_per_epoch, execution_client, consensus_client)

    async def test_pre_shapella_eth1_data_fallback(self):
        epoch, slots_per_epoch = 5, MAINNET_SLOTS_PER_EPOCH
        first_slot = epoch * slots_per_epoch
        pre_shapella_data = _pre_shapella_block_response(first_slot)

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(return_value=pre_shapella_data)

        execution_client = mock.Mock()
        execution_client.eth.get_block = AsyncMock(return_value={'number': 555, 'timestamp': 666})

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.epoch == epoch
        assert head.slot == first_slot
        assert head.block_number == 555
        assert head.execution_ts == 666
        execution_client.eth.get_block.assert_awaited_once_with(
            pre_shapella_data['data']['message']['body']['eth1_data']['block_hash']
        )

    async def test_pre_shapella_block_not_found_continues_to_next_slot(self):
        epoch, slots_per_epoch = 5, MAINNET_SLOTS_PER_EPOCH
        first_slot = epoch * slots_per_epoch
        pre_shapella_data = _pre_shapella_block_response(first_slot)
        next_slot_data = _block_response(first_slot + 1, block_number=42, timestamp=43)

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(side_effect=[pre_shapella_data, next_slot_data])

        execution_client = mock.Mock()
        execution_client.eth.get_block = AsyncMock(side_effect=BlockNotFound('block not found'))

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.slot == first_slot + 1
        assert head.block_number == 42
        assert head.execution_ts == 43


class TestGetChainJustifiedHead:
    async def test_missed_boundary_slot_derives_epoch_from_found_slot(self):
        """When the justified epoch's first slot is missed, .epoch must report the epoch
        the found slot actually belongs to, not the pinned justified checkpoint epoch."""
        justified_epoch, slots_per_epoch = 5, MAINNET_SLOTS_PER_EPOCH
        boundary_slot = justified_epoch * slots_per_epoch
        found_slot = boundary_slot - 1
        block_data = _block_response(found_slot)

        async def get_block(slot_id: str):
            if int(slot_id) == boundary_slot:
                raise NOT_FOUND_ERROR
            return block_data

        consensus_client = mock.Mock()
        consensus_client.get_finality_checkpoint = AsyncMock(
            return_value=_finality_checkpoint_response(justified_epoch)
        )
        consensus_client.get_block = AsyncMock(side_effect=get_block)

        head = await get_chain_justified_head(consensus_client, slots_per_epoch)

        assert head.slot == found_slot
        assert head.epoch == found_slot // slots_per_epoch
        assert head.epoch == justified_epoch - 1


class TestChainHeadEpochSlotInvariant:
    async def test_finalized_head(self):
        slots_per_epoch = MAINNET_SLOTS_PER_EPOCH
        slot = 12345
        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(return_value=_block_response(slot))

        head = await get_chain_finalized_head(consensus_client, slots_per_epoch)

        assert head.epoch == head.slot // slots_per_epoch

    async def test_latest_head(self):
        slots_per_epoch = MAINNET_SLOTS_PER_EPOCH
        slot = 54321
        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(return_value=_block_response(slot))

        head = await get_chain_latest_head(consensus_client, slots_per_epoch)

        assert head.epoch == head.slot // slots_per_epoch

    @pytest.mark.parametrize('slots_per_epoch', [MAINNET_SLOTS_PER_EPOCH, GNOSIS_SLOTS_PER_EPOCH])
    async def test_epoch_head(self, slots_per_epoch: int):
        epoch = 7
        first_slot = epoch * slots_per_epoch
        missed_slots = {first_slot}
        block_data = _block_response(first_slot + 1)

        async def get_block(slot_id: str):
            if int(slot_id) in missed_slots:
                raise NOT_FOUND_ERROR
            return block_data

        consensus_client = mock.Mock()
        consensus_client.get_block = AsyncMock(side_effect=get_block)
        execution_client = mock.Mock()

        head = await get_chain_epoch_head(
            epoch, slots_per_epoch, execution_client, consensus_client
        )

        assert head.epoch == head.slot // slots_per_epoch

    @pytest.mark.parametrize('slots_per_epoch', [MAINNET_SLOTS_PER_EPOCH, GNOSIS_SLOTS_PER_EPOCH])
    async def test_justified_head(self, slots_per_epoch: int):
        justified_epoch = 9
        boundary_slot = justified_epoch * slots_per_epoch
        block_data = _block_response(boundary_slot)

        consensus_client = mock.Mock()
        consensus_client.get_finality_checkpoint = AsyncMock(
            return_value=_finality_checkpoint_response(justified_epoch)
        )
        consensus_client.get_block = AsyncMock(return_value=block_data)

        head = await get_chain_justified_head(consensus_client, slots_per_epoch)

        assert head.epoch == head.slot // slots_per_epoch
