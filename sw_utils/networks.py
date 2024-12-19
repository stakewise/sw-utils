from dataclasses import dataclass

from eth_typing import BlockNumber, ChecksumAddress, HexAddress, HexStr
from web3 import Web3
from web3.types import Timestamp

from sw_utils.typings import Bytes32, ConsensusFork

MAINNET = 'mainnet'
HOLESKY = 'holesky'
GNOSIS = 'gnosis'
CHIADO = 'chiado'

ETH_NETWORKS = [MAINNET, HOLESKY]
GNO_NETWORKS = [GNOSIS, CHIADO]

EMPTY_ADDR_HEX = HexAddress(HexStr('0x' + '00' * 20))


@dataclass
# pylint: disable-next=too-many-instance-attributes
class BaseNetworkConfig:
    SLOTS_PER_EPOCH: int
    SECONDS_PER_SLOT: int
    GENESIS_TIMESTAMP: Timestamp
    GENESIS_VALIDATORS_ROOT: Bytes32
    GENESIS_FORK_VERSION: bytes
    KEEPER_CONTRACT_ADDRESS: ChecksumAddress
    KEEPER_GENESIS_BLOCK: BlockNumber
    KEEPER_GENESIS_TIMESTAMP: Timestamp
    MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS: ChecksumAddress
    VALIDATORS_REGISTRY_CONTRACT_ADDRESS: ChecksumAddress  # eth2 deposit contract
    VALIDATORS_REGISTRY_GENESIS_BLOCK: BlockNumber  # eth2 deposit contract genesis
    SHARED_MEV_ESCROW_CONTRACT_ADDRESS: ChecksumAddress
    SHARED_MEV_ESCROW_GENESIS_BLOCK: BlockNumber
    MULTICALL_CONTRACT_ADDRESS: ChecksumAddress
    V2_POOL_CONTRACT_ADDRESS: ChecksumAddress
    V2_POOL_GENESIS_BLOCK: BlockNumber
    GENESIS_VAULT_CONTRACT_ADDRESS: ChecksumAddress
    GNO_TOKEN_CONTRACT_ADDRESS: ChecksumAddress
    GENESIS_VALIDATORS_IPFS_HASH: str
    CHAIN_ID: int
    IS_POA: bool
    FAR_FUTURE_EPOCH: int
    SHAPELLA_FORK_VERSION: bytes
    SHAPELLA_EPOCH: int
    SHAPELLA_BLOCK: BlockNumber

    @property
    def SECONDS_PER_BLOCK(self) -> int:
        return self.SECONDS_PER_SLOT

    @property
    def BLOCKS_PER_DAY(self) -> int:
        return 86400 // self.SECONDS_PER_BLOCK

    @property
    def SECONDS_PER_EPOCH(self) -> int:
        return self.SECONDS_PER_SLOT * self.SLOTS_PER_EPOCH

    @property
    def SHAPELLA_FORK(self) -> ConsensusFork:
        return ConsensusFork(
            version=self.SHAPELLA_FORK_VERSION,
            epoch=self.SHAPELLA_EPOCH,
        )


NETWORKS = {
    MAINNET: BaseNetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        GENESIS_TIMESTAMP=Timestamp(1606824023),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95')
            )
        ),
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x00000000')),
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x6B5815467da09DaA7DC83Db21c9239d98Bb487b5'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(18470089),
        KEEPER_GENESIS_TIMESTAMP=Timestamp(1698755051),
        MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA593948a0bC611fC6945eA013806b0191aE79B47'
        ),
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(11052983),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x48319f97E5Da1233c21c48b80097c0FB7a20Ff86'
        ),
        SHARED_MEV_ESCROW_GENESIS_BLOCK=BlockNumber(18470080),
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xC874b064f465bdD6411D45734b56fac750Cda29A'
        ),
        V2_POOL_GENESIS_BLOCK=BlockNumber(11726297),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xAC0F906E433d58FA868F936E8A43230473652885'
        ),
        GNO_TOKEN_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeih7iqn3ke2cydzctd6bmg5j3xyjdhpg352lvzhxd2fld7h2erzpuu',
        CHAIN_ID=1,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000000')),
        SHAPELLA_EPOCH=194048,
        SHAPELLA_BLOCK=BlockNumber(17034870),
    ),
    HOLESKY: BaseNetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xB580799Bf7d62721D1a523f0FDF2f5Ed7BA4e259'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(215379),
        KEEPER_GENESIS_TIMESTAMP=Timestamp(1698670956),
        MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xD595e0bDcdB632299aED5296083f082D3f80406d'
        ),
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x4242424242424242424242424242424242424242'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(0),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xc98F25BcAA6B812a07460f18da77AF8385be7b56'
        ),
        SHARED_MEV_ESCROW_GENESIS_BLOCK=BlockNumber(215370),
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        V2_POOL_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x8A94e1d22D83990205843cda08376d16F150c9bb'
        ),
        GNO_TOKEN_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeifg4pobtkdhav577d354d6j4wga3krvrnz3zbviqbm7rfqewh6foy',
        GENESIS_TIMESTAMP=Timestamp(1695902400),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1')
            )
        ),
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x01017000')),
        CHAIN_ID=17000,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x04017000')),
        SHAPELLA_EPOCH=256,
        SHAPELLA_BLOCK=BlockNumber(6698),
    ),
    GNOSIS: BaseNetworkConfig(
        SLOTS_PER_EPOCH=16,
        SECONDS_PER_SLOT=5,
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcAC0e3E35d3BA271cd2aaBE688ac9DB1898C26aa'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(34778552),
        KEEPER_GENESIS_TIMESTAMP=Timestamp(1720014665),
        MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA6991959FD04B23882b430555409FFb220826338'
        ),
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x0B98057eA310F4d31F2a452B414647007d1645d9'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(19469076),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x30db0d10d3774e78f8cB214b9e8B72D4B402488a'
        ),
        SHARED_MEV_ESCROW_GENESIS_BLOCK=BlockNumber(34778538),
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2f99472b727e15EECf9B9eFF9F7481B85d3b4444'
        ),
        V2_POOL_GENESIS_BLOCK=BlockNumber(21275812),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x4b4406Ed8659D03423490D8b62a1639206dA0A7a'
        ),
        GNO_TOKEN_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x9C58BAcC331c9aa871AFD802DB6379a98e80CEdb'
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeih5addmhcgkuwliowdu5in3y2o5jtcayazol4mgi2jmcgm3dkxqpu',
        GENESIS_TIMESTAMP=Timestamp(1638993340),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0xf5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47')
            )
        ),
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x00000064')),
        CHAIN_ID=100,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000064')),
        SHAPELLA_EPOCH=648704,
        SHAPELLA_BLOCK=BlockNumber(29242932),
    ),
    CHIADO: BaseNetworkConfig(
        SLOTS_PER_EPOCH=16,
        SECONDS_PER_SLOT=5,
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5f31eD13eBF81B67a9f9498F3d1D2Da553058988'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(10627588),
        KEEPER_GENESIS_TIMESTAMP=Timestamp(1720027625),
        MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2b99e59Dc9435a3D7265F65127990dc2FB1834C1'
        ),
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xb97036A26259B7147018913bD58a774cf91acf25'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(155434),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x453056f0bc4631abB15eEC656139f88067668E3E'
        ),
        SHARED_MEV_ESCROW_GENESIS_BLOCK=BlockNumber(10627570),
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        V2_POOL_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xF82f6E46d0d0a9536b9CA4bc480372EeaFcd9E6c'
        ),
        GNO_TOKEN_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x19C653Da7c37c66208fbfbE8908A5051B57b4C70'
        ),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeihkagspdbjaj4n5an4q5gzwyc6y3zu5s7xwjc5d7oqvzh7c4v4lfe',
        GENESIS_TIMESTAMP=Timestamp(1665396300),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e')
            )
        ),
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x0000006f')),
        CHAIN_ID=10200,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x0300006f')),
        SHAPELLA_EPOCH=244224,
        SHAPELLA_BLOCK=BlockNumber(4101611),
    ),
}
