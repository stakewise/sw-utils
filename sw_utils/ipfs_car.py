"""
Minimal CAR (v1) + dag-pb + UnixFS decoder used to verify fetched IPFS content against its CID.

Implemented in-house instead of `ipfs-car-decoder`/`unix-fs-exporter`: those depend on
`protobuf<4` (3.20.x is EOL and flagged by pip-audit, PYSEC-2026-1805/1806) and their generated
code does not load on newer protobuf. dag-pb and UnixFS need only a handful of protobuf fields,
so they are parsed here directly from the wire format with no protobuf dependency.
Only file content is supported (UnixFS `File`/`Raw` nodes and raw leaves); directories,
symlinks and HAMT shards are rejected. Output size is capped by `max_content_size`: UnixFS
allows linking one block many times, so a small CAR can expand to an arbitrarily large output.
"""

from dataclasses import dataclass, field

from multiformats import CID

_MAX_VARINT_BYTES = 9

_CID_V0_PREFIX = b'\x12\x20'
_CID_V0_LENGTH = 34

_RAW_CODEC = 0x55
_DAG_PB_CODEC = 0x70
_IDENTITY_HASH_CODE = 0x00

_UNIXFS_TYPE_RAW = 0
_UNIXFS_TYPE_FILE = 2

_MAX_DAG_DEPTH = 64


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


def _parse_dag_pb_link_hash(data: bytes) -> bytes:
    for field_number, wire_type, value in _decode_protobuf_fields(data):
        if field_number == 1:
            if wire_type != 2 or not isinstance(value, bytes):
                raise CarDecodeError('invalid PBLink.Hash field')
            return value
    raise CarDecodeError('PBLink missing Hash field')


def _parse_dag_pb_node(data: bytes) -> tuple[bytes, list[bytes]]:
    node_data = b''
    link_hashes: list[bytes] = []
    for field_number, wire_type, value in _decode_protobuf_fields(data):
        if field_number == 1:
            if wire_type != 2 or not isinstance(value, bytes):
                raise CarDecodeError('invalid PBNode.Data field')
            node_data = value
        elif field_number == 2:
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
        if field_number == 1 and isinstance(value, int):
            fs_type = value
        elif field_number == 2 and isinstance(value, bytes):
            fs_data = value
        elif field_number == 3 and isinstance(value, int):
            file_size = value
        elif field_number == 4:
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
