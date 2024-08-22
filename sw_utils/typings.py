from dataclasses import dataclass
from typing import Literal, NewType, TypeAlias

from eth_keys.datatypes import PublicKey
from eth_typing import BlockNumber, HexStr
from web3 import Web3
from web3.types import ChecksumAddress, Timestamp, Wei

Bytes32 = NewType('Bytes32', bytes)

Finality: TypeAlias = Literal['finalized', 'current_justified', 'previous_justified']


@dataclass
class ConsensusFork:
    version: bytes
    epoch: int


@dataclass
class ChainHead:
    epoch: int
    slot: int
    block_number: BlockNumber
    execution_ts: Timestamp

    @property
    def consensus_block(self) -> int:
        return self.slot

    @property
    def execution_block(self) -> BlockNumber:
        return self.block_number


@dataclass
class Oracle:
    endpoints: list[str]
    public_key: HexStr

    @property
    def address(self) -> ChecksumAddress:
        public_key = PublicKey(Web3.to_bytes(hexstr=self.public_key))
        return public_key.to_checksum_address()


@dataclass
# pylint: disable-next=too-many-instance-attributes
class ProtocolConfig:
    oracles: list[Oracle]
    supported_relays: list[str]

    # 1 percent = 100 bps
    vault_fee_max_bps: int

    validator_min_active_epochs: int
    # 1 percent = 100 bps
    validators_exit_queued_assets_bps: int

    inactive_validator_balance: Wei

    validators_approval_batch_limit: int
    validators_exit_rotation_batch_limit: int

    # The epoch when exit signature params changed.
    exit_signature_epoch: int

    # Time to submit new signatures into the contract (seconds).
    signature_validity_period: int

    # Period for operators to rotate exit signatures
    until_force_exit_epochs: int

    exit_signature_recover_threshold: int

    validators_threshold: int = 0
    rewards_threshold: int = 0
