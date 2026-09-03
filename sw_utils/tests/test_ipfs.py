import hashlib
import json
from pathlib import Path
from unittest import mock

import pytest
from aiohttp import ClientSession
from multiformats import CID, multihash

from sw_utils.exceptions import IpfsException
from sw_utils.ipfs import IpfsFetchClient

FIXTURES_DIR = Path(__file__).parent / 'fixtures'

# Fetched once from https://stakewise.myfilebase.com/ipfs/{cid}?format=car and committed
# as-is; both are real, small mainnet objects.
SMALL_CID = 'QmawUdo17Fvo7xa6ARCUSMV1eoVwPtVuzx8L8Crj2xozWm'
SMALL_CAR = (FIXTURES_DIR / f'{SMALL_CID}.car').read_bytes()
SMALL_CONTENT = b'[{"a":"b"}]'

CONFIG_CID = 'QmeCywDfupWC7jz5EDHsU5yEb2unAhn8iSGWBUEdrMjdMc'
CONFIG_CAR = (FIXTURES_DIR / f'{CONFIG_CID}.car').read_bytes()


def _tampered(car: bytes) -> bytes:
    tampered = bytearray(car)
    tampered[-1] ^= 0xFF
    return bytes(tampered)


def _tampered_mid(car: bytes) -> bytes:
    tampered = bytearray(car)
    tampered[len(tampered) // 2] ^= 0xFF
    return bytes(tampered)


def _truncated(car: bytes, drop: int) -> bytes:
    return car[:-drop]


class _FakeGetResponse:
    def __init__(
        self, body: bytes, status: int = 200, content_type: str = 'application/vnd.ipld.car'
    ) -> None:
        self._body = body
        self.status = status
        self.headers = {'Content-Type': content_type}

    async def __aenter__(self) -> '_FakeGetResponse':
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise ValueError(f'unexpected status {self.status}')

    async def read(self) -> bytes:
        return self._body


class TestDecodeCar:
    async def test_valid_car_returns_content(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=[])
        data = await client._decode_car(SMALL_CID, SMALL_CAR)
        assert data == SMALL_CONTENT

    async def test_valid_multi_block_car_returns_content(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=[])
        data = await client._decode_car(CONFIG_CID, CONFIG_CAR)
        assert json.loads(data)['supported_relays'] is not None

    async def test_tampered_car_raises(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=[])
        with pytest.raises(IpfsException, match='CAR verification failed'):
            await client._decode_car(SMALL_CID, _tampered(SMALL_CAR))

    async def test_mid_payload_byte_flip_raises(self) -> None:
        # Regression guard for ipfs_car_decoder.IndexedBlockstore(validate=True): a flip
        # inside an actual block's payload (not the CBOR header) must still be caught.
        client = IpfsFetchClient(ipfs_endpoints=[])
        with pytest.raises(IpfsException, match='CAR verification failed'):
            await client._decode_car(CONFIG_CID, _tampered_mid(CONFIG_CAR))

    async def test_truncated_car_raises(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=[])
        with pytest.raises(IpfsException, match='CAR verification failed'):
            await client._decode_car(CONFIG_CID, _truncated(CONFIG_CAR, 500))


class TestVerifyRawCid:
    def test_matching_raw_v1_passes(self) -> None:
        data = b'{"a": 1}'
        digest = multihash.wrap(_sha256(data), 'sha2-256')
        ipfs_hash = str(CID('base32', 1, 'raw', digest))
        IpfsFetchClient(ipfs_endpoints=[])._verify_raw_cid(ipfs_hash, data)

    def test_tampered_raw_v1_raises(self) -> None:
        data = b'{"a": 1}'
        digest = multihash.wrap(_sha256(data), 'sha2-256')
        ipfs_hash = str(CID('base32', 1, 'raw', digest))
        with pytest.raises(IpfsException, match='content hash mismatch'):
            IpfsFetchClient(ipfs_endpoints=[])._verify_raw_cid(ipfs_hash, data[:-1] + b'0')

    def test_dag_pb_cid_raises_unsupported(self) -> None:
        data = b'{"a": 1}'
        digest = multihash.wrap(_sha256(data), 'sha2-256')
        ipfs_hash = str(CID('base32', 1, 'dag-pb', digest))
        with pytest.raises(IpfsException, match='Unsupported CID'):
            IpfsFetchClient(ipfs_endpoints=[])._verify_raw_cid(ipfs_hash, data)


class _FakeIpfsRpcClient:
    def __init__(self, *, cat: bytes = b'', dag_export: bytes = b'') -> None:
        self.cat = mock.Mock(return_value=cat)
        self.dag = mock.Mock()
        self.dag.export = mock.Mock(return_value=dag_export)

    def __enter__(self) -> '_FakeIpfsRpcClient':
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class TestIpfsFetchClient:
    async def test_fetch_bytes_decodes_verified_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one'])
        with mock.patch.object(ClientSession, 'get', side_effect=[_FakeGetResponse(SMALL_CAR)]):
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT

    async def test_fetch_bytes_falls_through_to_next_endpoint_on_tampered_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'])
        with mock.patch.object(
            ClientSession,
            'get',
            side_effect=[_FakeGetResponse(_tampered(SMALL_CAR)), _FakeGetResponse(SMALL_CAR)],
        ), mock.patch('sw_utils.ipfs.logger.warning') as warning:
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT
        warning.assert_called_once()

    async def test_fetch_bytes_raises_when_all_endpoints_have_tampered_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'], retry_timeout=0)
        tampered = _tampered(SMALL_CAR)
        with mock.patch.object(
            ClientSession,
            'get',
            side_effect=[_FakeGetResponse(tampered), _FakeGetResponse(tampered)],
        ):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)

    async def test_fetch_bytes_skips_car_verification_when_disabled(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one'], verify_hash=False)
        requested_urls = []

        def fake_get(url: str, **_kwargs: object) -> _FakeGetResponse:
            requested_urls.append(url)
            return _FakeGetResponse(SMALL_CONTENT)

        with mock.patch.object(ClientSession, 'get', side_effect=fake_get):
            data = await client.fetch_bytes(SMALL_CID)

        assert data == SMALL_CONTENT
        assert requested_urls == [f'https://one/ipfs/{SMALL_CID}']

    async def test_fetch_json_parses_verified_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one'])
        with mock.patch.object(ClientSession, 'get', side_effect=[_FakeGetResponse(CONFIG_CAR)]):
            data = await client.fetch_json(CONFIG_CID)
        assert data['supported_relays'] is not None

    async def test_fetch_bytes_falls_back_unverified_when_no_endpoint_serves_car(self) -> None:
        non_car = _FakeGetResponse(SMALL_CONTENT, content_type='application/json')
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'])
        with mock.patch.object(
            ClientSession, 'get', side_effect=[non_car, non_car, _FakeGetResponse(SMALL_CONTENT)]
        ), mock.patch('sw_utils.ipfs.logger.error') as error:
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT
        error.assert_called_once()

    async def test_fetch_bytes_raises_on_mismatch_even_with_unverifiable_endpoint(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'], retry_timeout=0)
        with mock.patch.object(
            ClientSession,
            'get',
            side_effect=[
                _FakeGetResponse(_tampered(SMALL_CAR)),
                _FakeGetResponse(SMALL_CONTENT, content_type='application/json'),
            ],
        ):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)

    async def test_fetch_bytes_verified_car_wins_over_unverifiable_endpoint(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'])
        with mock.patch.object(
            ClientSession,
            'get',
            side_effect=[
                _FakeGetResponse(SMALL_CONTENT, content_type='application/json'),
                _FakeGetResponse(SMALL_CAR),
            ],
        ), mock.patch('sw_utils.ipfs.logger.error') as error:
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT
        error.assert_not_called()

    async def test_ipfs_rpc_node_returns_verified_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['/dns/node/tcp/5001'])
        rpc_client = _FakeIpfsRpcClient(dag_export=SMALL_CAR)
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT
        rpc_client.dag.export.assert_called_once()

    async def test_ipfs_rpc_node_tampered_car_raises(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['/dns/node/tcp/5001'], retry_timeout=0)
        rpc_client = _FakeIpfsRpcClient(dag_export=_tampered(SMALL_CAR))
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)

    async def test_ipfs_rpc_node_skips_car_verification_when_disabled(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['/dns/node/tcp/5001'], verify_hash=False)
        rpc_client = _FakeIpfsRpcClient(cat=SMALL_CONTENT)
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT
        rpc_client.cat.assert_called_once()
        rpc_client.dag.export.assert_not_called()

    async def test_falls_through_to_s3_when_ipfs_endpoints_fail(self) -> None:
        data = b'{"a": 1}'
        digest = multihash.wrap(_sha256(data), 'sha2-256')
        ipfs_hash = str(CID('base32', 1, 'raw', digest))
        client = IpfsFetchClient(ipfs_endpoints=['https://one'], s3_endpoints=['https://s3'])
        with mock.patch.object(
            ClientSession, 'get', side_effect=[RuntimeError('boom'), _FakeGetResponse(data)]
        ):
            result = await client.fetch_bytes(ipfs_hash)
        assert result == data


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()
