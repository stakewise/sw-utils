import json
import random
from functools import lru_cache
from pathlib import Path

import pytest
from multiformats import CID, multihash

from sw_utils.vendor.ipfs_unixfs import CarDecodeError, _build_dag, _build_leaf
from sw_utils.vendor.ipfs_unixfs import _encode_dag_pb_node as _kubo_encode_dag_pb_node
from sw_utils.vendor.ipfs_unixfs import _split_chunks, compute_cid, decode_car

FIXTURES_DIR = Path(__file__).parent / 'fixtures'

SMALL_CID = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'
SMALL_CAR = (FIXTURES_DIR / f'{SMALL_CID}.car').read_bytes()
SMALL_CONTENT = b'[{"a":"b"}]'

CONFIG_CID = 'QmeCywDfupWC7jz5EDHsU5yEb2unAhn8iSGWBUEdrMjdMc'
CONFIG_CAR = (FIXTURES_DIR / f'{CONFIG_CID}.car').read_bytes()

MAX_CONTENT_SIZE = 10 * 1024 * 1024


# --- minimal, independent encoders used only to build synthetic CAR fixtures for these tests ---


def _encode_varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def _encode_protobuf_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_protobuf_bytes_field(field_number: int, value: bytes) -> bytes:
    return _encode_protobuf_tag(field_number, 2) + _encode_varint(len(value)) + value


def _encode_protobuf_varint_field(field_number: int, value: int) -> bytes:
    return _encode_protobuf_tag(field_number, 0) + _encode_varint(value)


def _encode_unixfs_data(
    fs_type: int, data: bytes, block_sizes: list[int], file_size: int | None, packed: bool = False
) -> bytes:
    out = bytearray()
    out += _encode_protobuf_varint_field(1, fs_type)
    if data:
        out += _encode_protobuf_bytes_field(2, data)
    if file_size is not None:
        out += _encode_protobuf_varint_field(3, file_size)
    if packed:
        packed_values = b''.join(_encode_varint(size) for size in block_sizes)
        if packed_values:
            out += _encode_protobuf_bytes_field(4, packed_values)
    else:
        for size in block_sizes:
            out += _encode_protobuf_varint_field(4, size)
    return bytes(out)


def _encode_dag_pb_node(data: bytes, links: list[tuple[CID, int]]) -> bytes:
    # Kubo writes Links (field 2) before Data (field 1); matched here even though our own
    # decoder does not care about field order.
    out = bytearray()
    for cid, t_size in links:
        link_bytes = bytearray()
        link_bytes += _encode_protobuf_bytes_field(1, bytes(cid))
        if t_size:
            link_bytes += _encode_protobuf_varint_field(3, t_size)
        out += _encode_protobuf_bytes_field(2, bytes(link_bytes))
    if data:
        out += _encode_protobuf_bytes_field(1, data)
    return bytes(out)


def _raw_block(data: bytes) -> tuple[CID, bytes]:
    digest = multihash.digest(data, 'sha2-256')
    return CID('base32', 1, 'raw', digest), data


def _unixfs_file_node(
    data: bytes,
    children: list[tuple[CID, int]],
    filesize: int,
    packed_block_sizes: bool = False,
    block_sizes: list[int] | None = None,
) -> tuple[CID, bytes]:
    if block_sizes is None:
        block_sizes = [size for _, size in children]
    unixfs_data = _encode_unixfs_data(2, data, block_sizes, filesize, packed=packed_block_sizes)
    node_bytes = _encode_dag_pb_node(unixfs_data, children)
    digest = multihash.digest(node_bytes, 'sha2-256')
    return CID('base32', 1, 'dag-pb', digest), node_bytes


def _unixfs_directory_node(children: list[tuple[CID, int]]) -> tuple[CID, bytes]:
    unixfs_data = _encode_unixfs_data(1, b'', [], None)
    node_bytes = _encode_dag_pb_node(unixfs_data, children)
    digest = multihash.digest(node_bytes, 'sha2-256')
    return CID('base32', 1, 'dag-pb', digest), node_bytes


def _car(blocks: list[tuple[CID, bytes]]) -> bytes:
    # decode_car ignores the header entirely (roots are untrusted), so a minimal placeholder
    # byte stands in for a real dag-cbor CARv1 header here.
    header = b'\x00'
    out = bytearray()
    out += _encode_varint(len(header))
    out += header
    for cid, block in blocks:
        section = bytes(cid) + block
        out += _encode_varint(len(section))
        out += section
    return bytes(out)


def _flip_byte(data: bytes, offset: int) -> bytes:
    tampered = bytearray(data)
    tampered[offset] ^= 0xFF
    return bytes(tampered)


class TestRealFixtures:
    def test_pins_builder_to_real_kubo_block_section(self) -> None:
        # The real 111-byte fixture has a 1-byte header-length varint + 56-byte header,
        # followed by the block section (section-length varint + CIDv0 + PBNode bytes).
        real_block_section = SMALL_CAR[57:]

        root_cid, node_bytes = _unixfs_file_node(SMALL_CONTENT, [], filesize=len(SMALL_CONTENT))
        root_cid_v0 = root_cid.set(base='base58btc', version=0)
        assert str(root_cid_v0) == SMALL_CID

        built_section = (
            _encode_varint(len(bytes(root_cid_v0)) + len(node_bytes))
            + bytes(root_cid_v0)
            + node_bytes
        )
        assert built_section == real_block_section

    def test_decodes_single_block_fixture(self) -> None:
        assert decode_car(SMALL_CID, SMALL_CAR, max_content_size=MAX_CONTENT_SIZE) == SMALL_CONTENT

    def test_decodes_config_fixture(self) -> None:
        data = decode_car(CONFIG_CID, CONFIG_CAR, max_content_size=MAX_CONTENT_SIZE)
        assert json.loads(data)['supported_relays'] is not None

    def test_decodes_config_fixture_requested_as_cidv1(self) -> None:
        cid_v1 = str(CID.decode(CONFIG_CID).set(version=1))
        data = decode_car(cid_v1, CONFIG_CAR, max_content_size=MAX_CONTENT_SIZE)
        assert json.loads(data)['supported_relays'] is not None

    def test_tampered_last_byte_raises(self) -> None:
        with pytest.raises(CarDecodeError):
            decode_car(
                SMALL_CID,
                _flip_byte(SMALL_CAR, len(SMALL_CAR) - 1),
                max_content_size=MAX_CONTENT_SIZE,
            )

    def test_tampered_mid_payload_byte_raises(self) -> None:
        with pytest.raises(CarDecodeError):
            decode_car(
                CONFIG_CID,
                _flip_byte(CONFIG_CAR, len(CONFIG_CAR) // 2),
                max_content_size=MAX_CONTENT_SIZE,
            )

    def test_truncated_car_raises(self) -> None:
        with pytest.raises(CarDecodeError):
            decode_car(CONFIG_CID, CONFIG_CAR[:-500], max_content_size=MAX_CONTENT_SIZE)


class TestSyntheticMultiBlock:
    def test_multi_block_file_decodes_to_concatenation(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb', b'cccc')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=12)
        car = _car(leaves + [(root_cid, root_bytes)])

        assert decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE) == b'aaaabbbbcccc'

    def test_leaf_byte_flip_raises(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb', b'cccc')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=12)
        tampered_leaves = [leaves[0], (leaves[1][0], _flip_byte(leaves[1][1], 0)), leaves[2]]
        car = _car(tampered_leaves + [(root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match='hash mismatch'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_missing_leaf_raises(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb', b'cccc')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=12)
        car = _car(leaves[:2] + [(root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match='not found in CAR'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_shuffled_block_order_still_decodes_in_link_order(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb', b'cccc')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=12)
        shuffled = [leaves[2], leaves[0], leaves[1]]
        car = _car(shuffled + [(root_cid, root_bytes)])

        assert decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE) == b'aaaabbbbcccc'

    def test_wrong_filesize_raises(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=999)
        car = _car(leaves + [(root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match='filesize'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_wrong_blocksizes_entry_raises(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=8, block_sizes=[4, 999])
        car = _car(leaves + [(root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match='blocksizes'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_packed_block_sizes_accepted(self) -> None:
        leaves = [_raw_block(chunk) for chunk in (b'aaaa', b'bbbb', b'cccc')]
        children = [(cid, len(data)) for cid, data in leaves]
        root_cid, root_bytes = _unixfs_file_node(
            b'', children, filesize=12, packed_block_sizes=True
        )
        car = _car(leaves + [(root_cid, root_bytes)])

        assert decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE) == b'aaaabbbbcccc'

    def test_nested_file_node_decodes(self) -> None:
        inner_leaves = [_raw_block(chunk) for chunk in (b'xxxx', b'yyyy')]
        inner_children = [(cid, len(data)) for cid, data in inner_leaves]
        inner_cid, inner_bytes = _unixfs_file_node(b'', inner_children, filesize=8)

        outer_leaf = _raw_block(b'zzzz')
        outer_children = [(inner_cid, 8), (outer_leaf[0], 4)]
        root_cid, root_bytes = _unixfs_file_node(b'', outer_children, filesize=12)

        car = _car(inner_leaves + [(inner_cid, inner_bytes), outer_leaf, (root_cid, root_bytes)])

        assert decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE) == b'xxxxyyyyzzzz'

    def test_directory_root_raises_not_a_file(self) -> None:
        leaf_cid, leaf_bytes = _raw_block(b'aaaa')
        directory_cid, directory_bytes = _unixfs_directory_node([(leaf_cid, 4)])
        car = _car([(leaf_cid, leaf_bytes), (directory_cid, directory_bytes)])

        with pytest.raises(CarDecodeError, match='not a file'):
            decode_car(str(directory_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_requested_cid_absent_from_car_raises(self) -> None:
        leaf_cid, leaf_bytes = _raw_block(b'aaaa')
        other_cid, _ = _raw_block(b'bbbb')
        car = _car([(leaf_cid, leaf_bytes)])

        with pytest.raises(CarDecodeError, match='not found in CAR'):
            decode_car(str(other_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_depth_bomb_raises(self) -> None:
        leaf_cid, leaf_bytes = _raw_block(b'z')
        blocks = [(leaf_cid, leaf_bytes)]
        current_cid, current_size = leaf_cid, 1
        for _ in range(100):
            node_cid, node_bytes = _unixfs_file_node(
                b'', [(current_cid, current_size)], current_size
            )
            blocks.append((node_cid, node_bytes))
            current_cid, current_size = node_cid, current_size

        car = _car(blocks)
        with pytest.raises(CarDecodeError, match='depth'):
            decode_car(str(current_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_moderate_nesting_still_decodes(self) -> None:
        leaf_cid, leaf_bytes = _raw_block(b'z')
        blocks = [(leaf_cid, leaf_bytes)]
        current_cid, current_size = leaf_cid, 1
        for _ in range(10):
            node_cid, node_bytes = _unixfs_file_node(
                b'', [(current_cid, current_size)], current_size
            )
            blocks.append((node_cid, node_bytes))
            current_cid, current_size = node_cid, current_size

        car = _car(blocks)
        assert decode_car(str(current_cid), car, max_content_size=MAX_CONTENT_SIZE) == b'z'


class TestMalformedInput:
    def test_empty_bytes_raises(self) -> None:
        with pytest.raises(CarDecodeError):
            decode_car(SMALL_CID, b'', max_content_size=MAX_CONTENT_SIZE)

    def test_garbage_bytes_raises(self) -> None:
        with pytest.raises(CarDecodeError):
            decode_car(SMALL_CID, b'\xff\xff\xff\xff\xff', max_content_size=MAX_CONTENT_SIZE)

    def test_group_wire_type_in_root_raises(self) -> None:
        # Field tag with wire type 3 (start group), which our protobuf decoder must reject.
        group_field_tag = _encode_protobuf_tag(1, 3)
        node_bytes = group_field_tag + b'\x00'
        digest = multihash.digest(node_bytes, 'sha2-256')
        root_cid = CID('base32', 1, 'dag-pb', digest)
        car = _car([(root_cid, node_bytes)])

        with pytest.raises(CarDecodeError, match='wire type'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_pbnode_without_data_field_raises(self) -> None:
        # No Links either, so the PBNode itself serializes to zero bytes.
        node_bytes = _encode_dag_pb_node(b'', [])
        digest = multihash.digest(node_bytes, 'sha2-256')
        root_cid = CID('base32', 1, 'dag-pb', digest)
        car = _car([(root_cid, node_bytes)])

        with pytest.raises(CarDecodeError, match='missing Type'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_unixfs_data_without_type_field_raises(self) -> None:
        # UnixFS Data submessage with only the `Data` field (2), omitting the mandatory
        # `Type` field (1).
        unixfs_data = _encode_protobuf_bytes_field(2, b'abc')
        node_bytes = _encode_dag_pb_node(unixfs_data, [])
        digest = multihash.digest(node_bytes, 'sha2-256')
        root_cid = CID('base32', 1, 'dag-pb', digest)
        car = _car([(root_cid, node_bytes)])

        with pytest.raises(CarDecodeError, match='missing Type'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)


class TestContentSizeLimit:
    def test_repeated_link_amplification_decodes_within_limit(self) -> None:
        # One ~1 KiB leaf linked 1000 times: the CAR stores it once, the decoded content is ~1 MiB.
        leaf_data = b'x' * 1024
        leaf_cid, leaf_bytes = _raw_block(leaf_data)
        num_links = 1000
        children = [(leaf_cid, len(leaf_data))] * num_links
        total_size = len(leaf_data) * num_links
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=total_size)
        car = _car([(leaf_cid, leaf_bytes), (root_cid, root_bytes)])

        decoded = decode_car(str(root_cid), car, max_content_size=total_size)
        assert len(decoded) == total_size

    def test_repeated_link_amplification_raises_when_over_limit(self) -> None:
        leaf_data = b'x' * 1024
        leaf_cid, leaf_bytes = _raw_block(leaf_data)
        num_links = 1000
        children = [(leaf_cid, len(leaf_data))] * num_links
        total_size = len(leaf_data) * num_links
        root_cid, root_bytes = _unixfs_file_node(b'', children, filesize=total_size)
        car = _car([(leaf_cid, leaf_bytes), (root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match='exceeds limit'):
            decode_car(str(root_cid), car, max_content_size=total_size - 1)

    def test_declared_filesize_above_limit_rejected_before_walking(self) -> None:
        huge_declared_filesize = MAX_CONTENT_SIZE * 10
        root_cid, root_bytes = _unixfs_file_node(b'small data', [], filesize=huge_declared_filesize)
        car = _car([(root_cid, root_bytes)])

        with pytest.raises(CarDecodeError, match=f'exceeds limit of {MAX_CONTENT_SIZE} bytes'):
            decode_car(str(root_cid), car, max_content_size=MAX_CONTENT_SIZE)

    def test_raw_root_above_limit_raises(self) -> None:
        with pytest.raises(CarDecodeError, match='exceeds limit'):
            decode_car(SMALL_CID, SMALL_CAR, max_content_size=len(SMALL_CONTENT) - 1)

    def test_real_fixture_decodes_with_generous_limit(self) -> None:
        data = decode_car(CONFIG_CID, CONFIG_CAR, max_content_size=MAX_CONTENT_SIZE)
        assert len(data) > 100

    def test_real_fixture_raises_with_limit_smaller_than_content(self) -> None:
        with pytest.raises(CarDecodeError, match='exceeds limit'):
            decode_car(CONFIG_CID, CONFIG_CAR, max_content_size=100)


# Reference vectors produced with Kubo v0.43.0 (`ipfs add -Q --cid-version 1`).
ABC_CID = 'bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu'
EMPTY_CID = 'bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku'
ONE_CHUNK_CID = 'bafkreih2bk74eu5axngebs6vftmmkcaqboysjjy726xzy5hksnqmfgw5fy'
TWO_LEAVES_CID = 'bafybeidbbs6ocod3v27jtr4uhvc6n55y3gbrtur3bvjsnraudtbxkozi2y'
ONE_MILLION_BYTES_CID = 'bafybeib7ib7ug3wvblnvhfxfpagy5wqhpsswkb6kpfozceke5quor46rmy'
FULL_DEPTH_ONE_NODE_CID = 'bafybeih3ebhydpblov22wbakszm4spvku7hbo3oa5gdhgoh7gnub26mtx4'
DEPTH_TWO_CID = 'bafybeidsyc3rx6lmbjml2fg4ucagkjh3kse6tbphoyyhms46fqhmu6ujbi'

_TWO_LEAVES_ROOT_NODE_HEX = (
    '122c0a2401551220ffa48c58bde244083f669d62f280ce9f37297eba8477bad88b320804b3aacb63'
    '120018808010'
    '122a0a240155122076be8b528d0075f7aae98d6fa57a6d3c83ae480a8469e668d7b0af968995ac71'
    '1200'
    '1801'
    '0a0c080218818010208080102001'
)


@lru_cache
def _random_bytes(length: int) -> bytes:
    return random.Random(length).randbytes(length)


class TestComputeCid:
    def test_abc(self) -> None:
        assert str(compute_cid(b'abc')) == ABC_CID

    def test_empty_data_is_one_empty_chunk(self) -> None:
        assert str(compute_cid(b'')) == EMPTY_CID

    def test_exactly_one_chunk(self) -> None:
        assert str(compute_cid(_random_bytes(262144))) == ONE_CHUNK_CID

    def test_two_leaves(self) -> None:
        assert str(compute_cid(_random_bytes(262145))) == TWO_LEAVES_CID

    def test_one_million_bytes(self) -> None:
        assert str(compute_cid(_random_bytes(1_000_000))) == ONE_MILLION_BYTES_CID

    def test_full_depth_one_node(self) -> None:
        assert str(compute_cid(_random_bytes(174 * 262144))) == FULL_DEPTH_ONE_NODE_CID

    def test_forces_depth_two(self) -> None:
        assert str(compute_cid(_random_bytes(174 * 262144 + 1))) == DEPTH_TWO_CID


class TestEncodeDagPbNode:
    def test_two_leaves_root_node_matches_kubo_wire_bytes(self) -> None:
        data = _random_bytes(262145)
        leaves = [_build_leaf(chunk) for chunk in _split_chunks(data)]

        encoded = _kubo_encode_dag_pb_node(leaves)

        assert encoded.hex() == _TWO_LEAVES_ROOT_NODE_HEX


class TestRoundTrip:
    def test_encoded_dag_decodes_back_to_original_bytes(self) -> None:
        data = _random_bytes(1_000_000)
        root, blocks = _build_dag(data)
        car = _car(blocks)

        decoded = decode_car(str(root.cid), car, max_content_size=len(data))

        assert decoded == data
