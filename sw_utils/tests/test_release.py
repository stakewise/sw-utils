from unittest import mock

import pytest
from web3 import Web3

from sw_utils.tests import faker
from sw_utils.release import (
    is_meta_vault_upgraded_to_release,
    is_vault_upgraded_to_release,
)
from sw_utils.networks import (
    MAINNET,
    NETWORKS,
    ContractRelease,
    ContractReleaseVersion,
)


NETWORK = MAINNET


@pytest.fixture
def genesis_vault_address():
    address = Web3.to_checksum_address(faker.eth_address())
    with mock.patch.object(NETWORKS[NETWORK], 'GENESIS_VAULT_CONTRACT_ADDRESS', new=address):
        yield address


@pytest.fixture
def release_v4():
    patched_release = ContractRelease(
        version=ContractReleaseVersion.V4,
        vault_version=5,
        genesis_vault_version=6,
        meta_vault_version=5,
    )
    releases = NETWORKS[NETWORK].CONTRACTS_RELEASES.copy()
    patched = [r if r.version != ContractReleaseVersion.V4 else patched_release for r in releases]
    with mock.patch.object(NETWORKS[NETWORK], 'CONTRACTS_RELEASES', new=patched):
        yield patched_release


@pytest.fixture
def release_v5():
    patched_release = ContractRelease(
        version=ContractReleaseVersion.V5,
        vault_version=5,
        genesis_vault_version=7,
        meta_vault_version=6,
    )
    releases = NETWORKS[NETWORK].CONTRACTS_RELEASES.copy()
    patched = [r if r.version != ContractReleaseVersion.V5 else patched_release for r in releases]
    with mock.patch.object(NETWORKS[NETWORK], 'CONTRACTS_RELEASES', new=patched):
        yield patched_release


class TestIsVaultUpgradedToRelease:
    def test_regular_vault_below_min_version(self, release_v4):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_vault_upgraded_to_release(NETWORK, vault_address, 4, ContractReleaseVersion.V4)
            is False
        )

    def test_regular_vault_at_min_version(self, release_v4):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_vault_upgraded_to_release(
                NETWORK, vault_address, release_v4.vault_version, ContractReleaseVersion.V4
            )
            is True
        )

    def test_regular_vault_above_min_version(self, release_v4):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_vault_upgraded_to_release(
                NETWORK, vault_address, release_v4.vault_version + 1, ContractReleaseVersion.V4
            )
            is True
        )

    def test_genesis_vault_uses_genesis_version(self, genesis_vault_address, release_v4):
        # genesis_vault_version=6, vault_version=5
        # version 5 passes for regular vaults but not genesis
        assert (
            is_vault_upgraded_to_release(
                NETWORK,
                genesis_vault_address,
                release_v4.vault_version,
                ContractReleaseVersion.V4,
            )
            is False
        )

    def test_genesis_vault_at_genesis_min_version(self, genesis_vault_address, release_v4):
        assert (
            is_vault_upgraded_to_release(
                NETWORK,
                genesis_vault_address,
                release_v4.genesis_vault_version,
                ContractReleaseVersion.V4,
            )
            is True
        )

    def test_genesis_vault_above_genesis_min_version(self, genesis_vault_address, release_v4):
        assert (
            is_vault_upgraded_to_release(
                NETWORK,
                genesis_vault_address,
                release_v4.genesis_vault_version + 1,
                ContractReleaseVersion.V4,
            )
            is True
        )


class TestIsMetaVaultUpgradedToRelease:
    def test_below_min_version(self, release_v5):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_meta_vault_upgraded_to_release(
                NETWORK,
                vault_address,
                release_v5.meta_vault_version - 1,
                ContractReleaseVersion.V5,
            )
            is False
        )

    def test_at_min_version(self, release_v5):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_meta_vault_upgraded_to_release(
                NETWORK,
                vault_address,
                release_v5.meta_vault_version,
                ContractReleaseVersion.V5,
            )
            is True
        )

    def test_above_min_version(self, release_v5):
        vault_address = Web3.to_checksum_address(faker.eth_address())
        assert (
            is_meta_vault_upgraded_to_release(
                NETWORK,
                vault_address,
                release_v5.meta_vault_version + 1,
                ContractReleaseVersion.V5,
            )
            is True
        )
