import json
from pathlib import Path
from typing import Any, AsyncIterator
from unittest import mock

import aiohttp
import pytest
from aiohttp import ClientResponseError, ClientSession, RequestInfo
from multidict import CIMultiDict, CIMultiDictProxy
from multiformats import CID
from yarl import URL

from sw_utils.exceptions import IpfsException
from sw_utils.ipfs import (
    BaseUploadClient,
    FilebaseUploadClient,
    IpfsFetchClient,
    IpfsMultiUploadClient,
    IpfsUploadClient,
    PinataUploadClient,
    _dump_json,
)
from sw_utils.vendor.ipfs_unixfs import compute_cid

FIXTURES_DIR = Path(__file__).parent / 'fixtures'

# Real CIDv1 (sha2-256) that `ipfs add --cid-version 1` (and Pinata/Filebase, same defaults)
# produce for b'abc'.
ABC_CID = 'bafkreif2pall7dybz7vecqka3zo24irdwabwdi4wc55jznaq75q7eaavvu'
# A valid but unrelated CID (real CID of b'xyz'), used to simulate a provider returning a
# well-formed CID that does not commit to the uploaded content.
WRONG_CID = 'bafkreibwbc6kdzcou3cne2hlnwyceybgtcjmbnblq257dz32n6qwypesqi'

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


class _FakeContent:
    def __init__(self, body: bytes) -> None:
        self._body = body

    async def iter_chunked(self, chunk_size: int) -> AsyncIterator[bytes]:
        for offset in range(0, len(self._body), chunk_size):
            yield self._body[offset : offset + chunk_size]


class _FakeGetResponse:
    def __init__(
        self,
        body: bytes,
        status: int = 200,
        content_type: str = 'application/vnd.ipld.car',
        content_length: int | None = -1,
    ) -> None:
        self._body = body
        self.status = status
        self.headers = {'Content-Type': content_type}
        # -1 derives Content-Length from the body; None simulates a missing header.
        self.content_length = len(body) if content_length == -1 else content_length
        self.content = _FakeContent(body)

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
        # A flip inside a block payload (not the CAR header) must still be caught.
        client = IpfsFetchClient(ipfs_endpoints=[])
        with pytest.raises(IpfsException, match='CAR verification failed'):
            await client._decode_car(CONFIG_CID, _tampered_mid(CONFIG_CAR))

    async def test_truncated_car_raises(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=[])
        with pytest.raises(IpfsException, match='CAR verification failed'):
            await client._decode_car(CONFIG_CID, _truncated(CONFIG_CAR, 500))


class _FakeIpfsRpcClient:
    def __init__(self, *, dag_export: bytes = b'') -> None:
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

    async def test_fetch_json_parses_verified_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one'])
        with mock.patch.object(ClientSession, 'get', side_effect=[_FakeGetResponse(CONFIG_CAR)]):
            data = await client.fetch_json(CONFIG_CID)
        assert data['supported_relays'] is not None

    async def test_fetch_bytes_raises_when_no_endpoint_serves_car(self) -> None:
        non_car = _FakeGetResponse(SMALL_CONTENT, content_type='application/json')
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'], retry_timeout=0)
        with mock.patch.object(ClientSession, 'get', side_effect=[non_car, non_car]) as get:
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)
        assert get.call_count == 2

    async def test_fetch_bytes_raises_when_endpoints_are_tampered_or_non_car(self) -> None:
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

    async def test_fetch_bytes_falls_through_non_car_endpoint_to_verified_car(self) -> None:
        client = IpfsFetchClient(ipfs_endpoints=['https://one', 'https://two'])
        with mock.patch.object(
            ClientSession,
            'get',
            side_effect=[
                _FakeGetResponse(SMALL_CONTENT, content_type='application/json'),
                _FakeGetResponse(SMALL_CAR),
            ],
        ):
            data = await client.fetch_bytes(SMALL_CID)
        assert data == SMALL_CONTENT

    async def test_fetch_bytes_rejects_poisoned_gateway_when_it_is_the_only_endpoint(
        self,
    ) -> None:
        poisoned = _FakeGetResponse(b'{"oracles": []}', content_type='application/json')
        client = IpfsFetchClient(ipfs_endpoints=['https://one'], retry_timeout=0)
        with mock.patch.object(ClientSession, 'get', side_effect=[poisoned]):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)

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

    async def test_fetch_bytes_skips_endpoint_when_content_length_exceeds_limit(self) -> None:
        client = IpfsFetchClient(
            ipfs_endpoints=['https://one'], retry_timeout=0, max_content_size=len(SMALL_CAR) - 1
        )
        with mock.patch.object(ClientSession, 'get', side_effect=[_FakeGetResponse(SMALL_CAR)]):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)

    async def test_fetch_bytes_skips_endpoint_when_body_exceeds_limit_without_content_length(
        self,
    ) -> None:
        # Content-Length may be absent or wrong, so the body itself is capped while streaming.
        oversized = _FakeGetResponse(SMALL_CAR, content_length=None)
        client = IpfsFetchClient(
            ipfs_endpoints=['https://one'], retry_timeout=0, max_content_size=len(SMALL_CAR) - 1
        )
        with mock.patch.object(ClientSession, 'get', side_effect=[oversized]):
            with pytest.raises(IpfsException, match='Failed to fetch IPFS data'):
                await client.fetch_bytes(SMALL_CID)


class _FakePostResponse:
    def __init__(self, payload: dict | None = None, status: int = 200) -> None:
        self._payload = payload or {}
        self.status = status

    async def __aenter__(self) -> '_FakePostResponse':
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=mock.Mock(), history=(), status=self.status
            )

    async def json(self) -> dict:
        return self._payload


def _find_posted_field(form_data: aiohttp.FormData, name: str) -> tuple[Any, Any, Any]:
    for type_options, headers, value in form_data._fields:
        if type_options.get('name') == name:
            return type_options, headers, value
    raise AssertionError(f'field {name} not found')


def _read_posted_field(form_data: aiohttp.FormData, name: str) -> Any:
    return _find_posted_field(form_data, name)[2]


class TestFilebaseUploadClient:
    async def test_upload_bytes_posts_file_and_returns_hash(self) -> None:
        client = FilebaseUploadClient(api_token='my-token')
        response = _FakePostResponse({'Name': 'small.json', 'Hash': ABC_CID, 'Size': '3'})
        with mock.patch.object(ClientSession, 'post', autospec=True, return_value=response) as post:
            ipfs_hash = await client.upload_bytes(b'abc')

        assert ipfs_hash == ABC_CID
        session, _, kwargs = post.call_args.args[0], post.call_args.args[1:], post.call_args.kwargs
        assert kwargs['url'] == 'https://rpc.filebase.io/api/v0/add'
        assert kwargs['params'] == {'cid-version': '1'}
        type_options, headers, value = _find_posted_field(kwargs['data'], 'file')
        assert value == b'abc'
        assert type_options['filename'] == 'file'
        assert headers['Content-Type'] == 'application/octet-stream'
        assert session.headers == {'Authorization': 'Bearer my-token'}

    async def test_upload_json_serialises_with_dump_json(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        data = [{'a': 'b'}]
        json_cid = str(compute_cid(_dump_json(data)))
        response = _FakePostResponse({'Hash': json_cid})
        with mock.patch.object(ClientSession, 'post', return_value=response) as post:
            ipfs_hash = await client.upload_json(data)

        assert ipfs_hash == json_cid
        _, kwargs = post.call_args
        assert _read_posted_field(kwargs['data'], 'file') == _dump_json(data)

    async def test_upload_bytes_raises_on_cid_mismatch(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        response = _FakePostResponse({'Hash': WRONG_CID})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')

    async def test_upload_bytes_raises_on_undecodable_cid(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        response = _FakePostResponse({'Hash': 'not-a-cid!!'})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='undecodable CID'):
                await client.upload_bytes(b'abc')

    async def test_upload_bytes_raises_on_cid_version_mismatch(self) -> None:
        # A CIDv0 response is never equal to the CIDv1 we requested, even with a matching digest.
        client = FilebaseUploadClient(api_token='token')
        v0_cid = str(CID('base58btc', 0, 'dag-pb', compute_cid(b'abc').digest))
        response = _FakePostResponse({'Hash': v0_cid})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')

    async def test_remove_posts_to_pin_rm_with_arg(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        response = _FakePostResponse({'Pins': ['bafkreitest']})
        with mock.patch.object(ClientSession, 'post', return_value=response) as post:
            await client.remove('bafkreitest')

        _, kwargs = post.call_args
        assert kwargs['url'] == 'https://rpc.filebase.io/api/v0/pin/rm'
        assert kwargs['params'] == {'arg': 'bafkreitest'}

    async def test_upload_bytes_raises_on_empty_data(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        with pytest.raises(ValueError, match='Empty data provided'):
            await client.upload_bytes(b'')

    async def test_upload_json_raises_on_empty_data(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        with pytest.raises(ValueError, match='Empty data provided'):
            await client.upload_json([])

    async def test_remove_raises_on_empty_hash(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        with pytest.raises(ValueError, match='Empty IPFS hash provided'):
            await client.remove('')

    async def test_upload_bytes_raises_client_response_error_on_error_status(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        response = _FakePostResponse(status=401)
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(aiohttp.ClientResponseError):
                await client.upload_bytes(b'abc')

    async def test_remove_raises_client_response_error_on_error_status(self) -> None:
        client = FilebaseUploadClient(api_token='token')
        response = _FakePostResponse(status=500)
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(aiohttp.ClientResponseError):
                await client.remove('bafkreitest')


class TestPinataUploadClient:
    async def test_upload_bytes_posts_file_and_returns_hash(self) -> None:
        client = PinataUploadClient(api_key='my-key', secret_key='my-secret')
        response = _FakePostResponse({'IpfsHash': ABC_CID})
        with mock.patch.object(ClientSession, 'post', return_value=response) as post:
            ipfs_hash = await client.upload_bytes(b'abc')

        assert ipfs_hash == ABC_CID
        _, kwargs = post.call_args
        assert kwargs['url'] == 'https://api.pinata.cloud/pinning/pinFileToIPFS'
        type_options, headers, value = _find_posted_field(kwargs['data'], 'file')
        assert value == b'abc'
        assert type_options['filename'] == 'file'
        assert headers['Content-Type'] == 'application/octet-stream'
        assert _read_posted_field(kwargs['data'], 'pinataOptions') == '{"cidVersion": 1}'

    async def test_upload_bytes_raises_on_cid_mismatch(self) -> None:
        client = PinataUploadClient(api_key='my-key', secret_key='my-secret')
        response = _FakePostResponse({'IpfsHash': WRONG_CID})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')

    async def test_upload_bytes_raises_on_undecodable_cid(self) -> None:
        client = PinataUploadClient(api_key='my-key', secret_key='my-secret')
        response = _FakePostResponse({'IpfsHash': 'not-a-cid!!'})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='undecodable CID'):
                await client.upload_bytes(b'abc')

    async def test_upload_bytes_raises_on_cid_version_mismatch(self) -> None:
        # A CIDv0 response is never equal to the CIDv1 we requested, even with a matching digest.
        client = PinataUploadClient(api_key='my-key', secret_key='my-secret')
        v0_cid = str(CID('base58btc', 0, 'dag-pb', compute_cid(b'abc').digest))
        response = _FakePostResponse({'IpfsHash': v0_cid})
        with mock.patch.object(ClientSession, 'post', return_value=response):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')


class _FakeIpfsUploadRpcClient:
    def __init__(self, *, add_bytes_return: str) -> None:
        self.add_bytes = mock.Mock(return_value=add_bytes_return)
        self.pin = mock.Mock()

    def __enter__(self) -> '_FakeIpfsUploadRpcClient':
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


class TestIpfsUploadClient:
    async def test_upload_bytes_pins_and_returns_verified_hash(self) -> None:
        client = IpfsUploadClient(endpoint='/dns/node/tcp/5001')
        rpc_client = _FakeIpfsUploadRpcClient(add_bytes_return=ABC_CID)
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            ipfs_hash = await client.upload_bytes(b'abc')

        assert ipfs_hash == ABC_CID
        rpc_client.pin.add.assert_called_once_with(ABC_CID)

    async def test_upload_bytes_raises_on_cid_mismatch_and_does_not_pin(self) -> None:
        client = IpfsUploadClient(endpoint='/dns/node/tcp/5001')
        rpc_client = _FakeIpfsUploadRpcClient(add_bytes_return=WRONG_CID)
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')
        rpc_client.pin.add.assert_not_called()

    async def test_upload_bytes_raises_on_undecodable_cid_and_does_not_pin(self) -> None:
        client = IpfsUploadClient(endpoint='/dns/node/tcp/5001')
        rpc_client = _FakeIpfsUploadRpcClient(add_bytes_return='not-a-cid!!')
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            with pytest.raises(IpfsException, match='undecodable CID'):
                await client.upload_bytes(b'abc')
        rpc_client.pin.add.assert_not_called()

    async def test_upload_bytes_raises_on_cid_version_mismatch_and_does_not_pin(self) -> None:
        # A CIDv0 response is never equal to the CIDv1 we requested, even with a matching digest.
        client = IpfsUploadClient(endpoint='/dns/node/tcp/5001')
        v0_cid = str(CID('base58btc', 0, 'dag-pb', compute_cid(b'abc').digest))
        rpc_client = _FakeIpfsUploadRpcClient(add_bytes_return=v0_cid)
        with mock.patch('sw_utils.ipfs.ipfshttpclient.connect', return_value=rpc_client):
            with pytest.raises(IpfsException, match='content hashes to'):
                await client.upload_bytes(b'abc')
        rpc_client.pin.add.assert_not_called()


def _client_response_error_with_leaking_header() -> ClientResponseError:
    # repr() of ClientResponseError includes request_info.headers, so a naive
    # `logger.error(repr(exc))` would leak an Authorization header into logs.
    headers = CIMultiDictProxy(CIMultiDict({'Authorization': 'Bearer SECRET-TOKEN'}))
    request_info = RequestInfo(URL('https://example.com'), 'POST', headers)
    return ClientResponseError(request_info, (), status=401, message='Unauthorized')


class _FailingUploadClient(BaseUploadClient):
    async def upload_bytes(self, data: bytes) -> str:
        raise _client_response_error_with_leaking_header()

    async def upload_json(self, data: dict | list) -> str:
        raise _client_response_error_with_leaking_header()

    async def remove(self, ipfs_hash: str) -> None:
        raise _client_response_error_with_leaking_header()


class TestIpfsMultiUploadClient:
    async def test_upload_bytes_does_not_log_leaked_credentials_on_failure(self) -> None:
        client = IpfsMultiUploadClient(
            upload_clients=[_FailingUploadClient(), _FailingUploadClient()], retry_timeout=0
        )
        with mock.patch('sw_utils.ipfs.logger.error') as error:
            with pytest.raises(IpfsException, match='Upload to all clients has failed'):
                await client.upload_bytes(b'data')

        assert error.call_count == 2
        for call in error.call_args_list:
            formatted_message = call.args[0] % call.args[1:]
            assert 'SECRET-TOKEN' not in formatted_message

    async def test_upload_bytes_excludes_client_with_wrong_cid_but_reaches_quorum(self) -> None:
        # 3 clients so a lone wrong CID (client verification failure) does not spoil quorum
        # for the 2 clients that returned the real CID.
        client = IpfsMultiUploadClient(
            upload_clients=[
                FilebaseUploadClient(api_token='token-1'),
                FilebaseUploadClient(api_token='token-2'),
                FilebaseUploadClient(api_token='token-3'),
            ],
            retry_timeout=0,
        )
        responses = [
            _FakePostResponse({'Hash': ABC_CID}),
            _FakePostResponse({'Hash': ABC_CID}),
            _FakePostResponse({'Hash': WRONG_CID}),
        ]
        with mock.patch.object(ClientSession, 'post', side_effect=responses):
            ipfs_hash = await client.upload_bytes(b'abc')

        assert ipfs_hash == ABC_CID
