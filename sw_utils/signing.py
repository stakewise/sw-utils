# pylint: disable=W0511
# TODO: remove once https://github.com/ethereum/py-ssz/issues/127 fixed
from eth_typing import BLSPubkey, BLSSignature, HexAddress
from eth_utils import to_canonical_address
# pylint: disable=no-name-in-module
from milagro_bls_binding import Verify as MilagroBlsVerify
from py_ecc.bls import G2ProofOfPossession

from .ssz import Serializable, bytes4, bytes32, bytes48, bytes96, uint64
from .typings import Bytes32

ETH1_ADDRESS_WITHDRAWAL_PREFIX = bytes.fromhex('01')
DOMAIN_DEPOSIT = bytes.fromhex('03000000')
ZERO_BYTES32 = b'\x00' * 32


# Crypto Domain SSZ
class SigningData(Serializable):
    fields = [('object_root', bytes32), ('domain', bytes32)]


class ForkData(Serializable):
    fields = [
        ('current_version', bytes4),
        ('genesis_validators_root', bytes32),
    ]


class DepositMessage(Serializable):
    fields = [
        ('pubkey', bytes48),
        ('withdrawal_credentials', bytes32),
        ('amount', uint64),
    ]


class DepositData(Serializable):
    fields = [
        ('pubkey', bytes48),
        ('withdrawal_credentials', bytes32),
        ('amount', uint64),
        ('signature', bytes96),
    ]


class VoluntaryExit(Serializable):
    fields = [('epoch', uint64), ('validator_index', uint64)]


def compute_deposit_message(
    public_key: bytes, withdrawal_credentials: bytes, amount_gwei: int
) -> DepositMessage:
    return DepositMessage(
        pubkey=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount_gwei,
    )


def get_eth1_withdrawal_credentials(vault: HexAddress) -> Bytes32:
    withdrawal_credentials = ETH1_ADDRESS_WITHDRAWAL_PREFIX
    withdrawal_credentials += b'\x00' * 11
    withdrawal_credentials += to_canonical_address(vault)
    return Bytes32(withdrawal_credentials)


def is_valid_deposit_data_signature(
    public_key: BLSPubkey,
    withdrawal_credentials: Bytes32,
    signature: BLSSignature,
    amount_gwei: int,
    fork_version: bytes,
) -> bool:
    """Checks whether deposit data is valid."""
    domain = _compute_deposit_domain(fork_version=fork_version)
    deposit_message = DepositMessage(
        pubkey=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount_gwei,
    )
    return MilagroBlsVerify(public_key, _compute_signing_root(deposit_message, domain), signature)


def is_valid_exit_signature(
    validator_index: int, public_key: BLSPubkey, signature: BLSSignature
) -> bool:
    """Checks whether exit signature is valid."""
    # pylint: disable=protected-access
    if not G2ProofOfPossession._is_valid_signature(signature):
        return False
    voluntary_exit = VoluntaryExit(epoch=0, validator_index=validator_index)
    return MilagroBlsVerify(public_key, voluntary_exit.hash_tree_root, signature)


def _compute_deposit_domain(fork_version: bytes) -> bytes:
    """
    Deposit-only `compute_domain`
    """
    if len(fork_version) != 4:
        raise ValueError(f'Fork version should be in 4 bytes. Got {len(fork_version)}.')
    domain_type = DOMAIN_DEPOSIT
    fork_data_root = _compute_deposit_fork_data_root(fork_version)
    return domain_type + fork_data_root[:28]


def _compute_deposit_fork_data_root(current_version: bytes) -> bytes:
    """
    Return the appropriate ForkData root for a given deposit version.
    """
    genesis_validators_root = ZERO_BYTES32  # For deposit, it's fixed value
    if len(current_version) != 4:
        raise ValueError(f'Fork version should be in 4 bytes. Got {len(current_version)}.')
    return ForkData(
        current_version=current_version,
        genesis_validators_root=genesis_validators_root,
    ).hash_tree_root


def _compute_signing_root(ssz_object: Serializable, domain: bytes) -> bytes:
    """
    Return the signing root of an object by calculating the root of the object-domain tree.
    The root is the hash tree root of:
    https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#signingdata
    """
    if len(domain) != 32:
        raise ValueError(f'Domain should be in 32 bytes. Got {len(domain)}.')
    domain_wrapped_object = SigningData(
        object_root=ssz_object.hash_tree_root,
        domain=domain,
    )
    return domain_wrapped_object.hash_tree_root
