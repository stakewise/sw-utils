"""
dag-pb + UnixFS wire format, both directions: decoding a CAR (v1) to verify fetched IPFS
content against its CID, and encoding to reproduce Kubo's `ipfs add --cid-version 1` layout
in order to verify a CID a provider claims for uploaded content.

Implemented in-house instead of `ipfs-car-decoder`/`unix-fs-exporter`: those depend on
`protobuf<4` (3.20.x is EOL and flagged by pip-audit, PYSEC-2026-1805/1806) and their generated
code does not load on newer protobuf. dag-pb and UnixFS need only a handful of protobuf fields,
so both directions are parsed/written here directly against the wire format, with no protobuf
dependency at all.

`decode_car` only supports file content (UnixFS `File`/`Raw` nodes and raw leaves); directories,
symlinks and HAMT shards are rejected. Output size is capped by `max_content_size`: UnixFS
allows linking one block many times, so a small CAR can expand to an arbitrarily large output.

`compute_cid` reproduces Kubo's default `ipfs add --cid-version 1` layout (raw leaves,
`size-262144` chunker, balanced DAG with at most 174 links per node, sha2-256, CIDv1).
A provider using a different layout (chunk size, trickle DAG, hash function) would produce
a different CID and be rejected by design: Pinata, Filebase and a plain Kubo node all agree
on these defaults, and the multi-upload quorum in `sw_utils/ipfs.py` already relies on that.
"""

from dataclasses import dataclass, field

from multiformats import CID, multihash

# --- varint ---
_MAX_VARINT_BYTES = 9

# --- CID / codec / hash function ---
_CID_V0_PREFIX = b'\x12\x20'
_CID_V0_LENGTH = 34
_RAW_CODEC = 0x55
_DAG_PB_CODEC = 0x70
_IDENTITY_HASH_CODE = 0x00
_SHA2_256 = 'sha2-256'

# --- UnixFS Data.Type values ---
_UNIXFS_TYPE_RAW = 0
_UNIXFS_TYPE_FILE = 2

# --- dag-pb protobuf field numbers ---
_PBNODE_DATA_FIELD = 1
_PBNODE_LINKS_FIELD = 2
_PBLINK_HASH_FIELD = 1
_PBLINK_NAME_FIELD = 2
_PBLINK_TSIZE_FIELD = 3

# --- UnixFS Data protobuf field numbers ---
_UNIXFS_DATA_TYPE_FIELD = 1
_UNIXFS_DATA_DATA_FIELD = 2
_UNIXFS_DATA_FILESIZE_FIELD = 3
_UNIXFS_DATA_BLOCKSIZES_FIELD = 4

# --- decode-side limits ---
_MAX_DAG_DEPTH = 64

# --- encode-side defaults (Kubo `ipfs add --cid-version 1`) ---
_CHUNK_SIZE = 262144
_MAX_LINKS_PER_NODE = 174


class CarDecodeError(ValueError):
    pass


@dataclass
class _UnixFsData:
    type: int
    data: bytes
    file_size: int | None
    block_sizes: list[int]


@dataclass
class _DagPbFrame:
    # A node being walked: `head` is its own UnixFS `Data`, `children_content` accumulates
    # already-resolved child bytes in link order as the iterative walk below fills them in.
    head: bytes
    depth: int
    declared_block_sizes: list[int]
    declared_file_size: int | None
    child_cids: list[CID]
    child_index: int = 0
    children_content: list[bytes] = field(default_factory=list)


@dataclass
class _ContentSizeGuard:
    # Counts bytes as they are actually produced: declared sizes are attacker-controlled.
    max_content_size: int
    total: int = 0

    def add(self, size: int) -> None:
        self.total += size
        if self.total > self.max_content_size:
            raise CarDecodeError(f'decoded content exceeds limit of {self.max_content_size} bytes')


@dataclass
class _Node:
    cid: CID
    tsize: int
    content_size: int


def decode_car(cid: str, car: bytes, *, max_content_size: int) -> bytes:
    root_cid = CID.decode(cid)
    block_index = _index_car_blocks(car)
    root = _open_dag_pb_node(root_cid, block_index, depth=0)
    if isinstance(root, bytes):
        if len(root) > max_content_size:
            raise CarDecodeError(f'decoded content exceeds limit of {max_content_size} bytes')
        return root

    if root.declared_file_size is not None and root.declared_file_size > max_content_size:
        raise CarDecodeError(
            f'declared filesize {root.declared_file_size} exceeds limit of {max_content_size} bytes'
        )

    return _walk_dag_pb_tree(root, block_index, max_content_size)


def _decode_binary_cid(buf: bytes, pos: int) -> tuple[CID, int]:
    if buf[pos : pos + 2] == _CID_V0_PREFIX:
        end = pos + _CID_V0_LENGTH
        if end > len(buf):
            raise CarDecodeError('truncated CIDv0')
        return CID.decode(buf[pos:end]), end

    version, next_pos = _read_varint(buf, pos)
    if version != 1:
        raise CarDecodeError(f'unsupported CID version {version}')
    _, next_pos = _read_varint(buf, next_pos)  # codec, re-derived by CID.decode below
    _, next_pos = _read_varint(buf, next_pos)  # multihash code, re-derived by CID.decode below
    hash_length, next_pos = _read_varint(buf, next_pos)
    end = next_pos + hash_length
    if end > len(buf):
        raise CarDecodeError('truncated CID digest')
    return CID.decode(buf[pos:end]), end


def _index_car_blocks(car: bytes) -> dict[bytes, bytes]:
    header_length, pos = _read_varint(car, 0)
    pos += header_length
    if pos > len(car):
        raise CarDecodeError('truncated CAR header')

    # Header contents (version, roots) are ignored: roots are untrusted, we only walk from
    # the requested CID.
    index: dict[bytes, bytes] = {}
    while pos < len(car):
        section_length, section_start = _read_varint(car, pos)
        section_end = section_start + section_length
        if section_length <= 0 or section_end > len(car):
            raise CarDecodeError('truncated CAR section')

        cid, block_start = _decode_binary_cid(car, section_start)
        digest = bytes(cid.digest)
        if digest not in index:  # keep the first block for a duplicated CID
            index[digest] = car[block_start:section_end]
        pos = section_end

    return index


def _get_verified_block(cid: CID, block_index: dict[bytes, bytes]) -> bytes:
    if cid.hashfun.code == _IDENTITY_HASH_CODE:
        return bytes(cid.raw_digest)

    block = block_index.get(bytes(cid.digest))
    if block is None:
        raise CarDecodeError(f'block {cid} not found in CAR')
    if cid.hashfun.digest(block) != cid.digest:
        raise CarDecodeError(f'block hash mismatch for {cid}')
    return block


def _parse_dag_pb_link_hash(data: bytes) -> bytes:
    for field_number, wire_type, value in _decode_protobuf_fields(data):
        if field_number == _PBLINK_HASH_FIELD:
            if wire_type != 2 or not isinstance(value, bytes):
                raise CarDecodeError('invalid PBLink.Hash field')
            return value
    raise CarDecodeError('PBLink missing Hash field')


def _parse_dag_pb_node(data: bytes) -> tuple[bytes, list[bytes]]:
    node_data = b''
    link_hashes: list[bytes] = []
    for field_number, wire_type, value in _decode_protobuf_fields(data):
        if field_number == _PBNODE_DATA_FIELD:
            if wire_type != 2 or not isinstance(value, bytes):
                raise CarDecodeError('invalid PBNode.Data field')
            node_data = value
        elif field_number == _PBNODE_LINKS_FIELD:
            if wire_type != 2 or not isinstance(value, bytes):
                raise CarDecodeError('invalid PBNode.Links field')
            link_hashes.append(_parse_dag_pb_link_hash(value))
    return node_data, link_hashes


def _parse_unixfs_data(data: bytes) -> _UnixFsData:
    fs_type: int | None = None
    fs_data = b''
    file_size: int | None = None
    block_sizes: list[int] = []

    for field_number, wire_type, value in _decode_protobuf_fields(data):
        if field_number == _UNIXFS_DATA_TYPE_FIELD and isinstance(value, int):
            fs_type = value
        elif field_number == _UNIXFS_DATA_DATA_FIELD and isinstance(value, bytes):
            fs_data = value
        elif field_number == _UNIXFS_DATA_FILESIZE_FIELD and isinstance(value, int):
            file_size = value
        elif field_number == _UNIXFS_DATA_BLOCKSIZES_FIELD:
            if wire_type == 0 and isinstance(value, int):
                block_sizes.append(value)
            elif wire_type == 2 and isinstance(value, bytes):
                block_sizes.extend(_decode_packed_varints(value))
        # fields 5-8 (hashType, fanout, mode, mtime) are not needed to read file content

    # `Type` is `required` in Kubo's proto2 unixfs.proto: an absent (or empty/Type-less)
    # `Data` submessage must not silently default to Raw.
    if fs_type is None:
        raise CarDecodeError('UnixFS Data missing Type field')

    return _UnixFsData(type=fs_type, data=fs_data, file_size=file_size, block_sizes=block_sizes)


def _open_dag_pb_node(cid: CID, block_index: dict[bytes, bytes], depth: int) -> bytes | _DagPbFrame:
    if cid.codec.code == _RAW_CODEC:
        return _get_verified_block(cid, block_index)
    if cid.codec.code != _DAG_PB_CODEC:
        raise CarDecodeError(f'unsupported codec {cid.codec.name} for {cid}')
    if depth > _MAX_DAG_DEPTH:
        raise CarDecodeError(f'DAG depth exceeded {_MAX_DAG_DEPTH} while resolving {cid}')

    node_data, link_hashes = _parse_dag_pb_node(_get_verified_block(cid, block_index))
    unix_fs = _parse_unixfs_data(node_data)
    if unix_fs.type not in (_UNIXFS_TYPE_RAW, _UNIXFS_TYPE_FILE):
        raise CarDecodeError(f'not a file: type {unix_fs.type}')

    return _DagPbFrame(
        head=unix_fs.data,
        depth=depth,
        declared_block_sizes=unix_fs.block_sizes,
        declared_file_size=unix_fs.file_size,
        child_cids=[CID.decode(link_hash) for link_hash in link_hashes],
    )


def _finalize_frame(frame: _DagPbFrame) -> bytes:
    if frame.declared_block_sizes:
        if len(frame.declared_block_sizes) != len(frame.children_content):
            raise CarDecodeError('blocksizes count does not match link count')
        for actual, expected in zip(frame.children_content, frame.declared_block_sizes):
            if len(actual) != expected:
                raise CarDecodeError('blocksizes entry does not match resolved child length')

    content = frame.head + b''.join(frame.children_content)
    if frame.declared_file_size is not None and len(content) != frame.declared_file_size:
        raise CarDecodeError('filesize does not match resolved content length')

    return content


def _walk_dag_pb_tree(
    root: _DagPbFrame, block_index: dict[bytes, bytes], max_content_size: int
) -> bytes:
    size_guard = _ContentSizeGuard(max_content_size)
    size_guard.add(len(root.head))

    stack = [root]
    while True:
        frame = stack[-1]
        if frame.child_index < len(frame.child_cids):
            child_cid = frame.child_cids[frame.child_index]
            child = _open_dag_pb_node(child_cid, block_index, depth=frame.depth + 1)
            if isinstance(child, bytes):
                size_guard.add(len(child))
                frame.children_content.append(child)
                frame.child_index += 1
            else:
                size_guard.add(len(child.head))
                stack.append(child)
            continue

        content = _finalize_frame(frame)
        stack.pop()
        if not stack:
            return content
        parent = stack[-1]
        # `content` is already counted via its head and leaves.
        parent.children_content.append(content)
        parent.child_index += 1


def compute_cid(data: bytes) -> CID:
    root, _ = _build_dag(data)
    return root.cid


def _build_dag(data: bytes) -> tuple[_Node, list[tuple[CID, bytes]]]:
    chunks = _split_chunks(data)
    level = [_build_leaf(chunk) for chunk in chunks]
    blocks = [(node.cid, chunk) for node, chunk in zip(level, chunks)]

    while len(level) > 1:
        parents: list[_Node] = []
        for group in _group(level, _MAX_LINKS_PER_NODE):
            parent, encoded = _build_parent(group)
            parents.append(parent)
            blocks.append((parent.cid, encoded))
        level = parents

    return level[0], blocks


def _split_chunks(data: bytes) -> list[bytes]:
    if not data:
        return [b'']
    return [data[offset : offset + _CHUNK_SIZE] for offset in range(0, len(data), _CHUNK_SIZE)]


def _group(nodes: list[_Node], size: int) -> list[list[_Node]]:
    return [nodes[offset : offset + size] for offset in range(0, len(nodes), size)]


def _build_leaf(chunk: bytes) -> _Node:
    digest = multihash.digest(chunk, _SHA2_256)
    return _Node(
        cid=CID('base32', 1, _RAW_CODEC, digest), tsize=len(chunk), content_size=len(chunk)
    )


def _build_parent(children: list[_Node]) -> tuple[_Node, bytes]:
    encoded = _encode_dag_pb_node(children)
    digest = multihash.digest(encoded, _SHA2_256)
    node = _Node(
        cid=CID('base32', 1, _DAG_PB_CODEC, digest),
        tsize=len(encoded) + sum(child.tsize for child in children),
        content_size=sum(child.content_size for child in children),
    )
    return node, encoded


def _encode_dag_pb_node(children: list[_Node]) -> bytes:
    # Kubo's canonical dag-pb form writes Links (field 2) before Data (field 1).
    out = bytearray()
    for child in children:
        out += _encode_pb_link(child)
    out += _encode_pb_bytes_field(_PBNODE_DATA_FIELD, _encode_unixfs_data(children))
    return bytes(out)


def _encode_pb_link(child: _Node) -> bytes:
    link = bytearray()
    link += _encode_pb_bytes_field(_PBLINK_HASH_FIELD, bytes(child.cid))
    link += _encode_pb_bytes_field(_PBLINK_NAME_FIELD, b'')  # Name: always present, always empty
    link += _encode_pb_varint_field(_PBLINK_TSIZE_FIELD, child.tsize)
    return _encode_pb_bytes_field(_PBNODE_LINKS_FIELD, bytes(link))


def _encode_unixfs_data(children: list[_Node]) -> bytes:
    out = bytearray()
    out += _encode_pb_varint_field(_UNIXFS_DATA_TYPE_FIELD, _UNIXFS_TYPE_FILE)
    out += _encode_pb_varint_field(
        _UNIXFS_DATA_FILESIZE_FIELD, sum(child.content_size for child in children)
    )
    for child in children:
        out += _encode_pb_varint_field(_UNIXFS_DATA_BLOCKSIZES_FIELD, child.content_size)
    return bytes(out)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for offset in range(_MAX_VARINT_BYTES):
        if pos + offset >= len(buf):
            raise CarDecodeError('truncated varint')
        byte = buf[pos + offset]
        value |= (byte & 0x7F) << (7 * offset)
        if not byte & 0x80:
            return value, pos + offset + 1
    raise CarDecodeError('varint exceeds maximum length of 9 bytes')


def _decode_protobuf_fields(data: bytes) -> list[tuple[int, int, bytes | int]]:
    fields: list[tuple[int, int, bytes | int]] = []
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        field_number, wire_type = tag >> 3, tag & 0x7
        value: bytes | int
        if wire_type == 0:
            value, pos = _read_varint(data, pos)
        elif wire_type == 2:
            length, pos = _read_varint(data, pos)
            end = pos + length
            if end > len(data):
                raise CarDecodeError('truncated length-delimited protobuf field')
            value, pos = data[pos:end], end
        elif wire_type in (1, 5):
            width = 8 if wire_type == 1 else 4
            end = pos + width
            if end > len(data):
                raise CarDecodeError('truncated fixed-width protobuf field')
            value, pos = data[pos:end], end
        else:
            raise CarDecodeError(f'unsupported protobuf wire type {wire_type}')
        fields.append((field_number, wire_type, value))
    return fields


def _decode_packed_varints(data: bytes) -> list[int]:
    values = []
    pos = 0
    while pos < len(data):
        value, pos = _read_varint(data, pos)
        values.append(value)
    return values


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
