from eth_typing import ChecksumAddress

from sw_utils.networks import GNO_NETWORKS, NETWORKS

GNO_GENESIS_VAULT_PECTRA_VERSION = 4


def get_pectra_vault_version(network: str, vault_address: ChecksumAddress) -> int:
    """
    Returns the minimal vault version which supports Pectra fork.
    """
    network_config = NETWORKS[network]

    if network in GNO_NETWORKS and vault_address == network_config.GENESIS_VAULT_CONTRACT_ADDRESS:
        return GNO_GENESIS_VAULT_PECTRA_VERSION

    return network_config.PECTRA_VAULT_VERSION
