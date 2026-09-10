"""
Reproduces Kubo's default `ipfs add --cid-version 1` layout (raw leaves, `size-262144`
chunker, balanced DAG with at most 174 links per node, sha2-256, CIDv1) so that an IPFS
upload response can be verified against the bytes we actually sent, without trusting the
provider's own CID computation.

A provider using a different layout (different chunk size, trickle DAG, different hash
function, ...) would produce a different CID here and be rejected by design: Pinata,
Filebase and a plain Kubo node all agree on these defaults today (Pinata's `cidVersion: 1`,
Filebase's `add?cid-version=1`), and the multi-upload quorum in `sw_utils/ipfs.py` already
relies on that agreement.
"""

from dataclasses import dataclass

from multiformats import CID, multihash

_CHUNK_SIZE = 262144
_MAX_LINKS_PER_NODE = 174

_RAW_CODEC = 'raw'
_DAG_PB_CODEC = 'dag-pb'
_SHA2_256 = 'sha2-256'

_UNIXFS_TYPE_FILE = 2


@dataclass
class _Node:
    cid: CID
    tsize: int
    content_size: int


def compute_cid(data: bytes) -> CID:
    level = [_build_leaf(chunk) for chunk in _split_chunks(data)]

    while len(level) > 1:
        level = [_build_parent(group) for group in _group(level, _MAX_LINKS_PER_NODE)]

    return level[0].cid


def _split_chunks(data: bytes) -> list[bytes]:
    if not data:
        return [b'']
    return [data[offset : offset + _CHUNK_SIZE] for offset in range(0, len(data), _CHUNK_SIZE)]


def _group(nodes: list[_Node], size: int) -> list[list[_Node]]:
    return [nodes[offset : offset + size] for offset in range(0, len(nodes), size)]


def _build_leaf(chunk: bytes) -> _Node:
    digest = multihash.digest(chunk, _SHA2_256)
    return _Node(cid=CID('base32', 1, _RAW_CODEC, digest), tsize=len(chunk), content_size=len(chunk))


def _build_parent(children: list[_Node]) -> _Node:
    encoded = _encode_dag_pb_node(children)
    digest = multihash.digest(encoded, _SHA2_256)
    return _Node(
        cid=CID('base32', 1, _DAG_PB_CODEC, digest),
        tsize=len(encoded) + sum(child.tsize for child in children),
        content_size=sum(child.content_size for child in children),
    )


def _encode_dag_pb_node(children: list[_Node]) -> bytes:
    # Kubo's canonical dag-pb form writes Links (field 2) before Data (field 1).
    out = bytearray()
    for child in children:
        out += _encode_pb_link(child)
    out += _encode_pb_bytes_field(1, _encode_unixfs_data(children))
    return bytes(out)


def _encode_pb_link(child: _Node) -> bytes:
    link = bytearray()
    link += _encode_pb_bytes_field(1, bytes(child.cid))
    link += _encode_pb_bytes_field(2, b'')  # Name: always present, always empty here
    link += _encode_pb_varint_field(3, child.tsize)
    return _encode_pb_bytes_field(2, bytes(link))


def _encode_unixfs_data(children: list[_Node]) -> bytes:
    out = bytearray()
    out += _encode_pb_varint_field(1, _UNIXFS_TYPE_FILE)
    out += _encode_pb_varint_field(3, sum(child.content_size for child in children))
    for child in children:
        out += _encode_pb_varint_field(4, child.content_size)  # unpacked, one per child
    return bytes(out)


def _encode_pb_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_pb_bytes_field(field_number: int, value: bytes) -> bytes:
    return _encode_pb_tag(field_number, 2) + _encode_varint(len(value)) + value


def _encode_pb_varint_field(field_number: int, value: int) -> bytes:
    return _encode_pb_tag(field_number, 0) + _encode_varint(value)


def _encode_varint(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            return bytes(result)
