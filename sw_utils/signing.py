# pylint: disable=W0511
# TODO: remove once https://github.com/ethereum/py-ssz/issues/127 fixed
from typing import Dict

from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from eth_typing import BLSPubkey, BLSSignature, HexAddress
from eth_utils import to_canonical_address
# pylint: disable=no-name-in-module
from milagro_bls_binding import Verify as MilagroBlsVerify
from py_ecc.bls import G2ProofOfPossession
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.optimized_bls12_381.optimized_curve import (Z1, add, curve_order,
                                                        multiply)
from py_ecc.utils import prime_field_inv

from .ssz import Serializable, bytes4, bytes32, bytes48, bytes96, uint64
from .typings import Bytes32

PRIME = curve_order

EXIT_SIGNATURE_SHARD_LENGTH = 640
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


def compute_deposit_domain(fork_version: bytes) -> bytes:
    """
    Deposit-only `compute_domain`
    """
    if len(fork_version) != 4:
        raise ValueError(f'Fork version should be in 4 bytes. Got {len(fork_version)}.')
    domain_type = DOMAIN_DEPOSIT
    fork_data_root = compute_deposit_fork_data_root(fork_version)
    return domain_type + fork_data_root[:28]


def compute_deposit_fork_data_root(current_version: bytes) -> bytes:
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


def compute_signing_root(ssz_object: Serializable, domain: bytes) -> bytes:
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
    domain = compute_deposit_domain(fork_version=fork_version)
    deposit_message = DepositMessage(
        pubkey=public_key,
        withdrawal_credentials=withdrawal_credentials,
        amount=amount_gwei,
    )
    return MilagroBlsVerify(public_key, compute_signing_root(deposit_message, domain), signature)


def reconstruct_shared_bls_public_key(public_keys: Dict[int, BLSPubkey]) -> BLSPubkey:
    """
    Reconstructs shared BLS public key.
    Copied from https://github.com/dankrad/python-ibft/blob/master/bls_threshold.py
    """
    r = Z1
    for i, key in public_keys.items():
        key_point = pubkey_to_G1(key)
        coef = 1
        for j in public_keys:
            if j != i:
                coef = -coef * (j + 1) * prime_field_inv(i - j, curve_order) % curve_order
        r = add(r, multiply(key_point, coef))
    return G1_to_pubkey(r)


def decrypt_exit_signature_shard(encryption: bytes, rsa_account: RSA.RsaKey) -> BLSSignature:
    """Decrypts exit signature shard with oracle's RSA private key."""
    private_key_size = rsa_account.size_in_bytes()

    # extract encryption parts
    enc_session_key = encryption[:private_key_size]
    nonce = encryption[private_key_size : private_key_size + 16]
    tag = encryption[private_key_size + 16 : private_key_size + 32]
    ciphertext = encryption[private_key_size + 32 :]

    # decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(rsa_account)
    session_key = cipher_rsa.decrypt(enc_session_key)

    # decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    return BLSSignature(cipher_aes.decrypt_and_verify(ciphertext, tag))  # type: ignore


def is_valid_exit_signature(
    validator_index: int, public_key: BLSPubkey, signature: BLSSignature
) -> bool:
    """Checks whether exit signature is valid."""
    # pylint: disable=protected-access
    if not G2ProofOfPossession._is_valid_signature(signature):
        return False
    voluntary_exit = VoluntaryExit(epoch=0, validator_index=validator_index)
    return MilagroBlsVerify(public_key, voluntary_exit.hash_tree_root, signature)
