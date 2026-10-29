import dataclasses
import json
from pathlib import Path
from typing import Any

from web3.types import Timestamp

from sw_utils.networks import HOODI, NETWORKS, BaseNetworkConfig

FIXTURES_DIR = Path(__file__).parent / 'fixtures'

HOODI_CONFIG = NETWORKS[HOODI]

# Sepolia is not a sw-utils network, but it is the first public network with Gloas.
SEPOLIA = dataclasses.replace(
    HOODI_CONFIG,
    GENESIS_TIMESTAMP=Timestamp(1655733600),
    SECONDS_PER_SLOT=12,
    GLOAS_EPOCH=353024,
)

# Fulu block on Hoodi, `execution_payload` path.
FULU_SLOT = 4234080
FULU_BLOCK_NUMBER = 3891504
# Gloas blocks on Sepolia. `bid.parent_block_hash` of each one points to the expected EL block.
SELF_BUILD_SLOT = 11404096
SELF_BUILD_EXECUTION_BLOCK_NUMBER = 11962172
# Builder bid (builder_index != 2**64 - 1), its payload was not delivered (empty slot).
BUILDER_SLOT = 11403711
# Block right after the empty slot: its parent hash is the one of `BUILDER_SLOT` block.
AFTER_EMPTY_PARENT_SLOT = 11403712
AFTER_EMPTY_PARENT_EXECUTION_BLOCK_NUMBER = 11961792


def load_json(filename: str) -> Any:
    return json.loads((FIXTURES_DIR / filename).read_text())


def consensus_ts(network_config: BaseNetworkConfig, slot: int) -> int:
    return network_config.GENESIS_TIMESTAMP + slot * network_config.SECONDS_PER_SLOT
