from dataclasses import dataclass

from eth_typing import BlockNumber, ChecksumAddress, HexAddress, HexStr
from web3 import Web3
from web3.types import Timestamp, Wei

from sw_utils.typings import Bytes32, ConsensusFork

MAINNET = 'mainnet'
HOODI = 'hoodi'
GNOSIS = 'gnosis'
CHIADO = 'chiado'

ETH_NETWORKS = [MAINNET, HOODI]
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
    GENESIS_VALIDATORS_LAST_BLOCK: BlockNumber
    CHAIN_ID: int
    IS_POA: bool
    FAR_FUTURE_EPOCH: int
    SHAPELLA_FORK_VERSION: bytes
    SHAPELLA_EPOCH: int
    SHAPELLA_BLOCK: BlockNumber
    PECTRA_EPOCH: int
    PECTRA_BLOCK: BlockNumber
    PECTRA_VAULT_VERSION: int
    OSTOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS: ChecksumAddress
    MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS: Wei

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

    @property
    def PECTRA_SLOT(self) -> int:
        return self.PECTRA_EPOCH * self.SLOTS_PER_EPOCH


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
            '0xa9dc250dF4EE9273D09CFa455da41FB1cAC78d34'
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
        GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(21245634),
        CHAIN_ID=1,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x03000000')),
        SHAPELLA_EPOCH=194048,
        SHAPELLA_BLOCK=BlockNumber(17034870),
        PECTRA_EPOCH=364032,
        PECTRA_BLOCK=BlockNumber(0),
        PECTRA_VAULT_VERSION=5,
        OSTOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x2A261e60FB14586B474C208b1B7AC6D0f5000306'
        ),
        MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS=Web3.to_wei(0, 'gwei'),
    ),
    HOODI: BaseNetworkConfig(
        SLOTS_PER_EPOCH=32,
        SECONDS_PER_SLOT=12,
        KEEPER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xA7D1Ac9D6F32B404C75626874BA56f7654c1dC0f'
        ),
        KEEPER_GENESIS_BLOCK=BlockNumber(94074),
        KEEPER_GENESIS_TIMESTAMP=Timestamp(1743444252),
        MERKLE_DISTRIBUTOR_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xc61847D6Fc1F64162fF9F1d06205D9c4cDb2f239'
        ),
        VALIDATORS_REGISTRY_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x00000000219ab540356cBB839Cbe05303d7705Fa'
        ),
        VALIDATORS_REGISTRY_GENESIS_BLOCK=BlockNumber(0),
        SHARED_MEV_ESCROW_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x51FD45BAEfB12f54766B5C4d639b360Ea50063bd'
        ),
        SHARED_MEV_ESCROW_GENESIS_BLOCK=BlockNumber(94050),
        MULTICALL_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xcA11bde05977b3631167028862bE2a173976CA11'
        ),
        V2_POOL_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        V2_POOL_GENESIS_BLOCK=BlockNumber(0),
        GENESIS_VAULT_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0xba447498DC4c169f2b4f427B2c4D532320457E89'
        ),
        GNO_TOKEN_CONTRACT_ADDRESS=Web3.to_checksum_address(EMPTY_ADDR_HEX),
        GENESIS_VALIDATORS_IPFS_HASH='bafybeieual2aumusnnbetwovmurfdwqvqb5fa5uktq5c4t3mnsup6di4r4',
        GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(133),
        GENESIS_TIMESTAMP=Timestamp(1742213400),
        GENESIS_VALIDATORS_ROOT=Bytes32(
            Web3.to_bytes(
                hexstr=HexStr('0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f')
            )
        ),
        GENESIS_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x10000910')),
        CHAIN_ID=560048,
        IS_POA=False,
        FAR_FUTURE_EPOCH=18446744073709551615,
        SHAPELLA_FORK_VERSION=Web3.to_bytes(hexstr=HexStr('0x40000910')),
        SHAPELLA_EPOCH=0,
        SHAPELLA_BLOCK=BlockNumber(0),
        PECTRA_EPOCH=2048,
        PECTRA_BLOCK=BlockNumber(60412),
        PECTRA_VAULT_VERSION=5,
        OSTOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x140Fc69Eabd77fFF91d9852B612B2323256f7Ac1'
        ),
        MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS=Web3.to_wei(0, 'gwei'),
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
            '0xFBceefdBB0ca25a4043b35EF49C2810425243710'
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
        GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(37195642),
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
        PECTRA_EPOCH=1337856,
        PECTRA_BLOCK=BlockNumber(0),
        PECTRA_VAULT_VERSION=3,
        OSTOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x60B2053d7f2a0bBa70fe6CDd88FB47b579B9179a'
        ),
        MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS=Web3.to_wei(1, 'gwei'),
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
            '0xd0747320d5457256D0203dfe61209Afbb90d22D7'
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
        GENESIS_VALIDATORS_LAST_BLOCK=BlockNumber(12906080),
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
        PECTRA_EPOCH=948224,
        PECTRA_BLOCK=BlockNumber(14642217),
        PECTRA_VAULT_VERSION=3,
        OSTOKEN_VAULT_CONTROLLER_CONTRACT_ADDRESS=Web3.to_checksum_address(
            '0x5518052f2d898f062ee59964004A560F24E2eE7d'
        ),
        MIN_EFFECTIVE_PRIORITY_FEE_PER_GAS=Web3.to_wei(1, 'gwei'),
    ),
}
