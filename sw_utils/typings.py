from dataclasses import dataclass
from typing import NewType

Bytes32 = NewType('Bytes32', bytes)


@dataclass
class ConsensusFork:
    version: bytes
    epoch: int
