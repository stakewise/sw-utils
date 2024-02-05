from sw_utils.typings import Oracle, ProtocolConfig


def build_protocol_config(
    config_data: dict, rewards_threshold: int = 0, validators_threshold: int = 0
) -> ProtocolConfig:
    oracles = []
    for oracle in config_data['oracles']:
        oracles.append(
            Oracle(
                public_key=oracle['public_key'],
                endpoints=oracle['endpoints'],
            )
        )

    if rewards_threshold and not 1 <= rewards_threshold <= len(oracles):
        raise ValueError('Invalid rewards threshold')

    if validators_threshold and not 1 <= validators_threshold <= len(oracles):
        raise ValueError('Invalid validators threshold')

    public_keys = [oracle.public_key for oracle in oracles]
    if len(public_keys) != len(set(public_keys)):
        raise ValueError('Duplicate public keys in oracles config')

    exit_signature_recover_threshold = config_data['exit_signature_recover_threshold']

    if validators_threshold and exit_signature_recover_threshold > validators_threshold:
        raise ValueError('Invalid exit signature threshold')

    return ProtocolConfig(
        oracles=oracles,
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        supported_relays=config_data['supported_relays'],
        vault_fee_max_bps=config_data['vault_max_fee'],
        validator_min_active_epochs=config_data['validator_min_active_epochs'],
        validators_exit_queued_assets_bps=config_data['validators_exit_queued_assets_bps'],
        validators_approval_batch_limit=config_data['validators_approval_batch_limit'],
        validators_exit_rotation_batch_limit=config_data['validators_exit_rotation_batch_limit'],
        exit_signature_epoch=config_data['exit_signature_epoch'],
        signature_validity_period=config_data['signature_validity_period'],
        until_force_exit_epochs=config_data['until_force_exit_epochs'],
    )
