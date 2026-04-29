from eth_typing import ChecksumAddress

from sw_utils.networks import (
    NETWORKS,
    PECTRA_CONTRACTS_RELEASE_VERSION,
    ContractReleaseVersion,
)


def is_vault_upgraded_to_pectra(
    network: str, vault_address: ChecksumAddress, vault_version: int
) -> bool:
    # Up to Pectra release, meta vault version is the same as regular vault version,
    # so we can use the same function for both meta and non-meta vaults
    return is_vault_upgraded_to_release(
        network=network,
        vault_address=vault_address,
        vault_version=vault_version,
        release_version=PECTRA_CONTRACTS_RELEASE_VERSION,
    )


def is_meta_vault_upgraded_to_release(
    network: str,
    vault_address: ChecksumAddress,
    vault_version: int,
    release_version: ContractReleaseVersion,
) -> bool:
    return is_vault_upgraded_to_release(
        network=network,
        vault_address=vault_address,
        vault_version=vault_version,
        release_version=release_version,
        is_meta_vault=True,
    )


def is_vault_upgraded_to_release(
    network: str,
    vault_address: ChecksumAddress,
    vault_version: int,
    release_version: ContractReleaseVersion,
    is_meta_vault: bool = False,
) -> bool:
    network_config = NETWORKS[network]

    release = network_config.CONTRACTS_RELEASE_VERSION_TO_RELEASE[release_version]
    is_genesis_vault = vault_address == network_config.GENESIS_VAULT_CONTRACT_ADDRESS
    if is_meta_vault:
        min_version = release.meta_vault_version
    elif is_genesis_vault:
        min_version = release.genesis_vault_version
    else:
        min_version = release.vault_version
    return vault_version >= min_version
