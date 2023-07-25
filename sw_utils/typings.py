from dataclasses import dataclass
from typing import NewType

from eth_typing import BlockNumber
from web3.types import Timestamp

Bytes32 = NewType('Bytes32', bytes)


@dataclass
class ConsensusFork:
    version: bytes
    epoch: int


@dataclass
class ChainHead:
    epoch: int
    consensus_block: int
    execution_block: BlockNumber
    execution_ts: Timestamp
