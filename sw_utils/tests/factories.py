import random
import string
from secrets import randbits

from eth_typing import ChecksumAddress
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

    def eth_address(self) -> ChecksumAddress:
        account = w3.eth.account.create()
        return account.address

    def eth_proof(self) -> str:
        # 32 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=64))

    def eth_signature(self) -> str:
        # Deprecated. Use `validator_signature` or `account_signature`.
        # 96 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=192))

    def validator_signature(self) -> str:
        # BLS signature, 96 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=192))

    def account_signature(self) -> str:
        # ECDSA signature, 65 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=130))

    def eth_public_key(self) -> str:
        # Deprecated. Use `validator_public_key` or `account_public_key`.
        # 48 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=96))

    def validator_public_key(self) -> str:
        # 48 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=96))

    def ecies_public_key(self) -> str:
        # 64 bytes
        return '0x' + ''.join(random.choices('abcdef' + string.digits, k=128))

    def account_public_key(self) -> str:
        # ECIES public key, 64 bytes
        return self.ecies_public_key()

    def wei_amount(self) -> Wei:
        amount = random.randint(Web3.to_wei(1, 'gwei'), Web3.to_wei(100, 'ether'))
        return Wei(amount)

    def eth_amount(self, start: int = 10, stop: int = 1000) -> Wei:
        eth_value = faker.random_int(start, stop)
        return w3.to_wei(eth_value, 'ether')

    def ipfs_hash(self) -> str:
        """
        Returns string of length 59 simulating an IPFS hash v1.
        """
        return 'bafk' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=55))


faker.add_provider(Web3Provider)


# pylint: disable=too-many-arguments,too-many-locals
def get_mocked_protocol_config(
    oracles: list[Oracle] | None = None,
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
    inactive_validator_balance: Wei = Web3.to_wei(31.75, 'ether'),
    validator_min_active_epochs: int = 2250,  # 10 days
    vault_fee_max_bps: int = 1500,  # 15%
    os_token_vaults_exit_limit_bps: int = 10_000,  # 100%
    os_token_vaults: list[str] | None = None,
) -> ProtocolConfig:
    return ProtocolConfig(
        oracles=oracles
        or [
            Oracle(
                public_key=faker.ecies_public_key(),
                endpoints=[f'https://example{i}.com'],
            )
            for i in range(oracles_count)
        ],
        supported_relays=[
            'http://relay',
        ],
        vault_fee_max_bps=vault_fee_max_bps,
        validator_min_active_epochs=validator_min_active_epochs,
        validators_exit_queued_assets_bps=validators_exit_queued_assets_bps,
        inactive_validator_balance=inactive_validator_balance,
        validators_approval_batch_limit=validators_approval_batch_limit,
        validators_exit_rotation_batch_limit=validators_exit_rotation_batch_limit,
        exit_signature_epoch=exit_signature_epoch,
        exit_signature_recover_threshold=exit_signature_recover_threshold,
        signature_validity_period=signature_validity_period,
        until_force_exit_epochs=until_force_exit_epochs,
        rewards_threshold=rewards_threshold,
        validators_threshold=validators_threshold,
        os_token_vaults_exit_limit_bps=os_token_vaults_exit_limit_bps,
        os_token_vaults=os_token_vaults or [],
    )
