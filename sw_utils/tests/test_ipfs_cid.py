import random
from functools import lru_cache

from sw_utils.vendor.ipfs_cid import _build_leaf, _encode_dag_pb_node, _split_chunks, compute_cid

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

        encoded = _encode_dag_pb_node(leaves)

        assert encoded.hex() == _TWO_LEAVES_ROOT_NODE_HEX
