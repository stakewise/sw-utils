from web3 import Web3
from web3.types import Wei

from sw_utils.typings import Oracle, ProtocolConfig


def build_protocol_config(
    config_data: dict, rewards_threshold: int | None = None, validators_threshold: int | None = None
) -> ProtocolConfig:
    oracles = []
    for oracle in config_data['oracles']:
        oracles.append(
            Oracle(
                public_key=oracle['public_key'],
                endpoints=oracle['endpoints'],
            )
        )

    if rewards_threshold is not None and not 1 <= rewards_threshold <= len(oracles):
        raise ValueError('Invalid rewards threshold')

    if validators_threshold is not None and not 1 <= validators_threshold <= len(oracles):
        raise ValueError('Invalid validators threshold')

    public_keys = [oracle.public_key for oracle in oracles]
    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    exit_signature_recover_threshold = config_data['exit_signature_recover_threshold']

    if validators_threshold and exit_signature_recover_threshold > validators_threshold:
        raise ValueError('Invalid exit signature threshold')

    vault_exiting_validators_limit_bps = config_data.get('vault_exiting_validators_limit_bps') or 0
    os_token_vaults = [
        Web3.to_checksum_address(v) for v in config_data.get('os_token_vaults') or []
    ]

    return ProtocolConfig(
        oracles=oracles,
        rewards_threshold=rewards_threshold or 0,
        validators_threshold=validators_threshold or 0,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        supported_relays=config_data['supported_relays'],
        vault_fee_max_bps=config_data['vault_max_fee'],
        validator_min_active_epochs=config_data['validator_min_active_epochs'],
        validators_exit_queued_assets_bps=config_data['validators_exit_queued_assets_bps'],
        inactive_validator_balance=Wei(int(config_data['inactive_validator_balance'])),
        validators_approval_batch_limit=config_data['validators_approval_batch_limit'],
        validators_exit_rotation_batch_limit=config_data['validators_exit_rotation_batch_limit'],
        exit_signature_epoch=config_data['exit_signature_epoch'],
        signature_validity_period=config_data['signature_validity_period'],
        until_force_exit_epochs=config_data['until_force_exit_epochs'],
        vault_exiting_validators_limit_bps=vault_exiting_validators_limit_bps,
        os_token_vaults=os_token_vaults,
    )
