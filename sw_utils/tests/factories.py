import random
import string
from secrets import randbits

from faker import Faker
from faker.providers import BaseProvider
from py_ecc.bls import G2ProofOfPossession
from web3 import Web3
from web3.types import Wei

from sw_utils.typings import Oracle, ProtocolConfig

w3 = Web3()
faker = Faker()


class Web3Provider(BaseProvider):
    def private_key(self) -> int:
        seed = randbits(256).to_bytes(32, 'big')
        private_key = G2ProofOfPossession.KeyGen(seed)
        return private_key

    def eth_address(self) -> str:
        account = w3.eth.account.create()
        return account.address

    def eth_proof(self) -> str:
        # 32 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=64))

    def eth_signature(self) -> str:
        # 96 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=192))

    def eth_public_key(self) -> str:
        # 48 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=96))

    def wei_amount(self, start: int = 10, stop: int = 1000) -> Wei:
        eth_value = faker.random_int(start, stop)
        return w3.to_wei(eth_value, 'ether')


faker.add_provider(Web3Provider)


# pylint: disable=too-many-arguments
def get_mocked_protocol_config(
    oracles: list[Oracle],
    oracles_count: int = 1,
    rewards_threshold: int = 1,
    validators_threshold: int = 1,
    exit_signature_recover_threshold: int = 1,
    exit_signature_epoch: int = 0,
    validators_approval_batch_limit: int = 100,
    validators_exit_rotation_batch_limit: int = 1000,
    signature_validity_period: int = 60,
    until_force_exit_epochs: int = 1000,
    validators_exit_queued_assets_bps: int = 500,  # 5%
    validator_min_active_epochs: int = 2250,  # 10 days
    vault_fee_max_bps: int = 1500,  # 15%
) -> ProtocolConfig:
    return ProtocolConfig(
        oracles=oracles
        or [
            Oracle(public_key=faker.eth_public_key(), endpoints=[f'https://example{i}.com'])
            for i in range(oracles_count)
        ],
        supported_relays=[
            'http://relay',
        ],
        vault_fee_max_bps=vault_fee_max_bps,
        validator_min_active_epochs=validator_min_active_epochs,
        validators_exit_queued_assets_bps=validators_exit_queued_assets_bps,
        validators_approval_batch_limit=validators_approval_batch_limit,
        validators_exit_rotation_batch_limit=validators_exit_rotation_batch_limit,
        exit_signature_epoch=exit_signature_epoch,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        signature_validity_period=signature_validity_period,
        until_force_exit_epochs=until_force_exit_epochs,
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
    )
