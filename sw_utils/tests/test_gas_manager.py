from unittest.mock import AsyncMock, patch

import pytest
from web3 import Web3
from web3.types import Wei

from sw_utils.execution import GasManager


@pytest.fixture()
def mock_execution_client() -> AsyncMock:
    client = AsyncMock()
    client.eth = AsyncMock()
    return client


@pytest.fixture()
def gas_manager(mock_execution_client: AsyncMock) -> GasManager:
    return GasManager(
        execution_client=mock_execution_client,
        priority_fee_num_blocks=10,
        priority_fee_percentile=80,
        max_fee_per_gas=Web3.to_wei(100, 'gwei'),
    )


class TestGasManagerInit:
    def test_default_values(self, mock_execution_client: AsyncMock) -> None:
        gm = GasManager(execution_client=mock_execution_client)
        assert gm.max_fee_per_gas == Web3.to_wei(100, 'gwei')
        assert gm.priority_fee_num_blocks == 10
        assert gm.priority_fee_percentile == 80
        assert gm.min_effective_priority_fee_per_gas == Wei(0)

    def test_custom_values(self, mock_execution_client: AsyncMock) -> None:
        gm = GasManager(
            execution_client=mock_execution_client,
            priority_fee_num_blocks=20,
            priority_fee_percentile=90,
            max_fee_per_gas=Web3.to_wei(50, 'gwei'),
            min_effective_priority_fee_per_gas=Web3.to_wei(2, 'gwei'),
        )
        assert gm.priority_fee_num_blocks == 20
        assert gm.priority_fee_percentile == 90
        assert gm.max_fee_per_gas == Web3.to_wei(50, 'gwei')
        assert gm.min_effective_priority_fee_per_gas == Web3.to_wei(2, 'gwei')


class TestCheckGasPrice:
    async def test_low_priority_acceptable(self, gas_manager: GasManager) -> None:
        """Gas price below max returns True."""
        gas_manager.execution_client.eth.max_priority_fee = _make_awaitable(
            Wei(Web3.to_wei(1, 'gwei'))
        )
        with patch(
            'sw_utils.execution._max_fee_per_gas',
            new_callable=AsyncMock,
            return_value=Web3.to_wei(10, 'gwei'),
        ):
            result = await gas_manager.check_gas_price(high_priority=False)
        assert result is True

    async def test_low_priority_too_expensive(self, gas_manager: GasManager) -> None:
        """Gas price at or above max returns False."""
        gas_manager.execution_client.eth.max_priority_fee = _make_awaitable(
            Wei(Web3.to_wei(1, 'gwei'))
        )
        with patch(
            'sw_utils.execution._max_fee_per_gas',
            new_callable=AsyncMock,
            return_value=Web3.to_wei(100, 'gwei'),
        ):
            result = await gas_manager.check_gas_price(high_priority=False)
        assert result is False

    async def test_low_priority_boundary(self, gas_manager: GasManager) -> None:
        """Gas price 1 wei below max returns True."""
        gas_manager.execution_client.eth.max_priority_fee = _make_awaitable(
            Wei(Web3.to_wei(1, 'gwei'))
        )
        with patch(
            'sw_utils.execution._max_fee_per_gas',
            new_callable=AsyncMock,
            return_value=Wei(Web3.to_wei(100, 'gwei') - 1),
        ):
            result = await gas_manager.check_gas_price(high_priority=False)
        assert result is True

    async def test_high_priority_acceptable(self, gas_manager: GasManager) -> None:
        """High priority gas price below max returns True."""
        gas_manager.execution_client.eth.fee_history = AsyncMock(
            return_value={
                'reward': [[Web3.to_wei(2, 'gwei')]] * 10,
            }
        )
        gas_manager.execution_client.eth.get_block = AsyncMock(
            return_value={'baseFeePerGas': Web3.to_wei(10, 'gwei')}
        )

        result = await gas_manager.check_gas_price(high_priority=True)
        assert result is True

    async def test_high_priority_too_expensive(self, gas_manager: GasManager) -> None:
        """High priority gas price at or above max returns False."""
        gas_manager.execution_client.eth.fee_history = AsyncMock(
            return_value={
                'reward': [[Web3.to_wei(30, 'gwei')]] * 10,
            }
        )
        gas_manager.execution_client.eth.get_block = AsyncMock(
            return_value={'baseFeePerGas': Web3.to_wei(40, 'gwei')}
        )

        result = await gas_manager.check_gas_price(high_priority=True)
        assert result is False


class TestGetHighPriorityTxParams:
    async def test_returns_correct_params(self, gas_manager: GasManager) -> None:
        priority_fee = Web3.to_wei(3, 'gwei')
        base_fee = Web3.to_wei(10, 'gwei')

        gas_manager.execution_client.eth.fee_history = AsyncMock(
            return_value={
                'reward': [[priority_fee]] * 10,
            }
        )
        gas_manager.execution_client.eth.get_block = AsyncMock(
            return_value={'baseFeePerGas': base_fee}
        )

        tx_params = await gas_manager.get_high_priority_tx_params()

        expected_priority = Web3.to_wei(3, 'gwei')
        expected_max_fee = Wei(expected_priority + 2 * base_fee)
        assert tx_params['maxPriorityFeePerGas'] == expected_priority
        assert tx_params['maxFeePerGas'] == expected_max_fee


class TestCalcHighPriorityFee:
    async def test_averages_rewards(self, gas_manager: GasManager) -> None:
        """Computes mean of fee history rewards."""
        rewards = [
            [Web3.to_wei(1, 'gwei')],
            [Web3.to_wei(3, 'gwei')],
        ]
        gas_manager.priority_fee_num_blocks = 2
        gas_manager.execution_client.eth.fee_history = AsyncMock(return_value={'reward': rewards})

        result = await gas_manager._calc_high_priority_fee()
        # mean of 1 and 3 gwei = 2 gwei, rounded to nearest 10^8
        assert result == Web3.to_wei(2, 'gwei')

    async def test_rounds_large_values(self, gas_manager: GasManager) -> None:
        """Values above 1 gwei get rounded to nearest 0.1 gwei."""
        # 1.55 gwei -> mean 1.55 gwei -> round(-8) -> 1.6 gwei
        reward_value = Web3.to_wei(1.55, 'gwei')
        gas_manager.execution_client.eth.fee_history = AsyncMock(
            return_value={'reward': [[reward_value]]}
        )
        gas_manager.priority_fee_num_blocks = 1

        result = await gas_manager._calc_high_priority_fee()
        assert result == Web3.to_wei(1.6, 'gwei')

    async def test_no_rounding_below_1_gwei(self, gas_manager: GasManager) -> None:
        """Values at or below 1 gwei are not rounded."""
        reward_value = Wei(500_000_000)  # 0.5 gwei
        gas_manager.execution_client.eth.fee_history = AsyncMock(
            return_value={'reward': [[reward_value]]}
        )
        gas_manager.priority_fee_num_blocks = 1

        result = await gas_manager._calc_high_priority_fee()
        assert result == Wei(500_000_000)

    async def test_min_effective_priority_fee(self, mock_execution_client: AsyncMock) -> None:
        """Result is at least min_effective_priority_fee_per_gas."""
        min_fee = Web3.to_wei(5, 'gwei')
        gm = GasManager(
            execution_client=mock_execution_client,
            min_effective_priority_fee_per_gas=min_fee,
        )
        # reward below min
        mock_execution_client.eth.fee_history = AsyncMock(
            return_value={'reward': [[Web3.to_wei(1, 'gwei')]]}
        )
        gm.priority_fee_num_blocks = 1

        result = await gm._calc_high_priority_fee()
        assert result == min_fee

    async def test_empty_reward_history_falls_back(self, mock_execution_client: AsyncMock) -> None:
        """Empty reward list falls back to max_priority_fee."""
        gm = GasManager(execution_client=mock_execution_client)
        mock_execution_client.eth.fee_history = AsyncMock(return_value={'reward': []})
        mock_execution_client.eth.max_priority_fee = _make_awaitable(Wei(Web3.to_wei(2, 'gwei')))
        gm.priority_fee_num_blocks = 1

        result = await gm._calc_high_priority_fee()
        assert result == Web3.to_wei(2, 'gwei')

    async def test_min_zero_not_applied(self, mock_execution_client: AsyncMock) -> None:
        """Wei(0) min fee is falsy and does not override computed fee."""
        gm = GasManager(
            execution_client=mock_execution_client,
            min_effective_priority_fee_per_gas=Wei(0),
        )
        reward_value = Wei(500_000_000)  # 0.5 gwei
        mock_execution_client.eth.fee_history = AsyncMock(return_value={'reward': [[reward_value]]})
        gm.priority_fee_num_blocks = 1

        result = await gm._calc_high_priority_fee()
        assert result == reward_value

    async def test_min_effective_priority_fee_not_applied_when_higher(
        self, mock_execution_client: AsyncMock
    ) -> None:
        """When computed fee exceeds min, use computed fee."""
        min_fee = Web3.to_wei(1, 'gwei')
        gm = GasManager(
            execution_client=mock_execution_client,
            min_effective_priority_fee_per_gas=min_fee,
        )
        mock_execution_client.eth.fee_history = AsyncMock(
            return_value={'reward': [[Web3.to_wei(5, 'gwei')]]}
        )
        gm.priority_fee_num_blocks = 1

        result = await gm._calc_high_priority_fee()
        assert result == Web3.to_wei(5, 'gwei')


async def _make_awaitable(value: object) -> object:
    """Create an awaitable that returns the given value."""
    return value
