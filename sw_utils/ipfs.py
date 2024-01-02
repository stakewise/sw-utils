import asyncio
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import aiohttp
import boto3
import botocore.config
import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout
from ipfs_cid import cid_sha256_hash
from ipfshttpclient.encoding import Json
from ipfshttpclient.exceptions import ErrorResponse
from multiformats import CID

from sw_utils.decorators import retry_ipfs_exception
from sw_utils.exceptions import IpfsException

if TYPE_CHECKING:
    from tenacity import RetryCallState


logger = logging.getLogger(__name__)

IPFS_DEFAULT_TIMEOUT = 120


class BaseUploadClient(ABC):
    @abstractmethod
    async def upload_bytes(self, data: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    async def upload_json(self, data: dict | list) -> str:
        raise NotImplementedError

    @abstractmethod
    async def remove(self, ipfs_hash: str) -> None:
        raise NotImplementedError


class IpfsUploadClient(BaseUploadClient):
    def __init__(
        self,
        endpoint: str,
        username: str | None = None,
        password: str | None = None,
        timeout: int = IPFS_DEFAULT_TIMEOUT,
    ):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.timeout = timeout

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')

        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
        ) as client:
            ipfs_id = client.add_bytes(data, opts={'cid-version': 1})
            client.pin.add(ipfs_id)

        return _strip_ipfs_prefix(ipfs_id)

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
        ) as client:
            ipfs_id = client.add_json(data, opts={'cid-version': 1})
            client.pin.add(ipfs_id)

        return _strip_ipfs_prefix(ipfs_id)

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
        ) as client:
            try:
                client.pin.rm(_strip_ipfs_prefix(ipfs_hash))
            except ErrorResponse as e:
                if hasattr(e, 'args') and e.args and e.args[0] == 'not pinned or pinned indirectly':
                    return
                raise e

    async def prune(self) -> None:
        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
        ) as client:
            client.repo.gc(quiet=True)


class PinataUploadClient(BaseUploadClient):
    json_endpoint = 'https://api.pinata.cloud/pinning/pinJSONToIPFS'
    bytes_endpoint = 'https://api.pinata.cloud/pinning/pinFileToIPFS'
    unpin_endpoint = 'https://api.pinata.cloud/pinning/unpin/'

    def __init__(self, api_key: str, secret_key: str, timeout: int = IPFS_DEFAULT_TIMEOUT):
        self.headers = {
            'pinata_api_key': api_key,
            'pinata_secret_api_key': secret_key,
        }
        self.timeout = timeout

    async def upload_bytes(self, data: bytes) -> str:
        async with ClientSession(
            headers=self.headers, timeout=aiohttp.ClientTimeout(self.timeout)
        ) as session:
            form_data = aiohttp.FormData()
            form_data.add_field('pinataOptions', '{"cidVersion": 1}')
            form_data.add_field('file', data, content_type='Content-Type: application/octet-stream')
            async with session.post(
                url=self.bytes_endpoint,
                data=form_data,
            ) as response:
                response.raise_for_status()
                ipfs_id = (await response.json())['IpfsHash']

        return _strip_ipfs_prefix(ipfs_id)

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')
        return await self.upload_bytes(_dump_json(data))

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        async with ClientSession(
            headers=headers, timeout=aiohttp.ClientTimeout(self.timeout)
        ) as session:
            async with session.delete(url=urljoin(self.unpin_endpoint, ipfs_hash)) as response:
                response.raise_for_status()
        return None


class WebStorageClient(BaseUploadClient):
    upload_endpoint = 'https://api.web3.storage/upload'
    unpin_endpoint = 'https://api.web3.storage/pins'

    def __init__(self, api_token: str, timeout: int = IPFS_DEFAULT_TIMEOUT):
        self.headers = {
            'Authorization': f'bearer {api_token}',
        }
        self.timeout = timeout

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')

        form_data = aiohttp.FormData()
        form_data.add_field('file', data, content_type='Content-Type: application/octet-stream')
        return await self._upload(form_data)

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        form_data = aiohttp.FormData()
        form_data.add_field('file', _dump_json(data), content_type='Content-Type: application/json')
        return await self._upload(form_data)

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')
        async with ClientSession(
            headers=self.headers, timeout=aiohttp.ClientTimeout(self.timeout)
        ) as session:
            async with session.delete(url=urljoin(self.unpin_endpoint, ipfs_hash)) as response:
                response.raise_for_status()
        return None

    async def _upload(self, form_data: aiohttp.FormData) -> str:
        async with ClientSession(
            headers=self.headers, timeout=aiohttp.ClientTimeout(self.timeout)
        ) as session:
            async with session.post(
                url=self.upload_endpoint,
                data=form_data,
            ) as response:
                response.raise_for_status()
                ipfs_id = (await response.json())['cid']

        return _strip_ipfs_prefix(ipfs_id)


class FilebaseS3Client(BaseUploadClient):
    """
    Uploads to 3x replicated IPFS storage using S3-compatible api.
    """

    upload_endpoint = 'https://s3.filebase.com'
    unpin_endpoint = ''

    def __init__(
        self,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        bucket: str,
        timeout: int = IPFS_DEFAULT_TIMEOUT,
    ):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.bucket = bucket
        self.read_timeout = timeout
        self.connect_timeout = timeout

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')
        s3 = self.get_s3_client()

        # S3 api requires unique key for each object
        ipfs_hash = cid_sha256_hash(data)
        logger.info('ipfs_hash %s', ipfs_hash)

        # Warning: blocking call, not async
        res = s3.put_object(Body=data, Bucket=self.bucket, Key=ipfs_hash)

        cid_v0 = res['ResponseMetadata']['HTTPHeaders']['x-amz-meta-cid']
        cid_v1 = _cid_v0_to_v1(cid_v0)

        # `cid_v1` must be the same as `ipfs_hash`
        # but there may be issues on Filebase side
        # So use the cid returned from Filebase
        return cid_v1

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')
        return await self.upload_bytes(_dump_json(data))

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        s3 = self.get_s3_client()

        # Warning: blocking call, not async
        s3.delete_object(Bucket=self.bucket, Key=ipfs_hash)

        return None

    def get_s3_client(self) -> Any:
        config = botocore.config.Config(
            read_timeout=self.read_timeout,
            connect_timeout=self.connect_timeout,
            retries={'max_attempts': 0},
        )
        return boto3.client(
            's3',
            config=config,
            endpoint_url=self.upload_endpoint,
            aws_access_key_id=self.aws_access_key_id,
            aws_secret_access_key=self.aws_secret_access_key,
        )


class IpfsMultiUploadClient(BaseUploadClient):
    def __init__(self, clients: list[BaseUploadClient], retry_timeout: int = 120):
        if len(clients) == 0:
            raise ValueError('Invalid number of clients')
        self.clients = clients
        self.quorum = (len(clients) // 2) + 1
        self.retry_timeout = retry_timeout

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')

        def custom_before_log(retry_state: 'RetryCallState') -> None:
            if retry_state.attempt_number <= 1:
                return
            logger.info('Retrying upload_bytes, attempt %s', retry_state.attempt_number)

        retry_decorator = retry_ipfs_exception(delay=self.retry_timeout, before=custom_before_log)
        return await retry_decorator(self._upload_bytes_all_clients)(data)

    async def _upload_bytes_all_clients(self, data: bytes) -> str:
        coros = [client.upload_bytes(data) for client in self.clients]
        return await self._upload(coros)

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        def custom_before_log(retry_state: 'RetryCallState') -> None:
            if retry_state.attempt_number <= 1:
                return
            logger.info('Retrying upload_json, attempt %s', retry_state.attempt_number)

        retry_decorator = retry_ipfs_exception(delay=self.retry_timeout, before=custom_before_log)
        return await retry_decorator(self._upload_json_all_clients)(data)

    async def _upload_json_all_clients(self, data: dict | list) -> str:
        coros = [client.upload_json(data) for client in self.clients]
        return await self._upload(coros)

    async def _upload(self, coros: list) -> str:
        result = await asyncio.gather(*coros, return_exceptions=True)

        ipfs_hashes: dict[str, int] = {}
        for value in result:
            if isinstance(value, BaseException):
                logger.warning(repr(value))
                continue

            ipfs_hash = _strip_ipfs_prefix(value)
            ipfs_hashes[ipfs_hash] = ipfs_hashes.get(ipfs_hash, 0) + 1

        if not ipfs_hashes:
            raise IpfsException('Upload to all clients has failed')

        ipfs_hash = max(ipfs_hashes, key=ipfs_hashes.get)  # type: ignore
        count = ipfs_hashes[ipfs_hash]
        if count < self.quorum:
            logger.warning(
                'quorum: %s, ipfs hashes: %s', self.quorum, ', '.join(ipfs_hashes.keys())
            )
            raise IpfsException('Failed to reach the uploads quorum')

        return ipfs_hash

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')
        result = await asyncio.gather(
            *[client.remove(ipfs_hash) for client in self.clients], return_exceptions=True
        )
        for value in result:
            if isinstance(value, BaseException):
                logger.warning(repr(value))
                continue
        return None


class IpfsFetchClient:
    def __init__(self, endpoints: list[str], timeout: int = 60, retry_timeout: int = 120):
        self.endpoints = endpoints
        self.timeout = timeout
        self.retry_timeout = retry_timeout

    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        def custom_before_log(retry_state: 'RetryCallState') -> None:
            if retry_state.attempt_number <= 1:
                return
            logger.info('Retrying fetch_bytes, attempt %s', retry_state.attempt_number)

        retry_decorator = retry_ipfs_exception(delay=self.retry_timeout, before=custom_before_log)
        return await retry_decorator(self._fetch_bytes_all_endpoints)(ipfs_hash)

    async def _fetch_bytes_all_endpoints(self, ipfs_hash: str) -> bytes:
        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_bytes(endpoint, ipfs_hash)

                return self._ipfs_fetch_bytes(endpoint, ipfs_hash)
            except Exception as e:
                logger.warning(repr(e))

        raise IpfsException(f'Failed to fetch IPFS data at {ipfs_hash}')

    async def _http_gateway_fetch_bytes(self, endpoint: str, ipfs_hash: str) -> bytes:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            async with session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}") as response:
                response.raise_for_status()
                return await response.read()

    def _ipfs_fetch_bytes(self, endpoint: str, ipfs_hash: str) -> bytes:
        with ipfshttpclient.connect(
            endpoint,
        ) as client:
            return client.cat(ipfs_hash, timeout=self.timeout)

    async def fetch_json(self, ipfs_hash: str) -> Any:
        """Tries to fetch IPFS hash from different sources."""
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        def custom_before_log(retry_state: 'RetryCallState') -> None:
            if retry_state.attempt_number <= 1:
                return
            logger.info('Retrying fetch_json, attempt %s', retry_state.attempt_number)

        retry_decorator = retry_ipfs_exception(delay=self.retry_timeout, before=custom_before_log)
        return await retry_decorator(self._fetch_json_all_endpoints)(ipfs_hash)

    async def _fetch_json_all_endpoints(self, ipfs_hash: str) -> Any:
        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_json(endpoint, ipfs_hash)

                return self._ipfs_fetch_json(endpoint, ipfs_hash)
            except Exception as e:
                logger.warning(repr(e))

        raise IpfsException(f'Failed to fetch IPFS data at {ipfs_hash}')

    async def _http_gateway_fetch_json(self, endpoint: str, ipfs_hash: str) -> Any:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            async with session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}") as response:
                response.raise_for_status()
                return await response.json()

    def _ipfs_fetch_json(self, endpoint: str, ipfs_hash: str) -> Any:
        with ipfshttpclient.connect(
            endpoint,
        ) as client:
            return client.get_json(ipfs_hash, timeout=self.timeout)


def _strip_ipfs_prefix(ipfs_hash: str) -> str:
    return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')


def _dump_json(data: Any) -> bytes:
    return Json().encode(data)


def _cid_v0_to_v1(cid: str) -> str:
    cid_v0 = CID.decode(cid)
    if cid_v0.version != 0:
        raise ValueError('cid version is not v0')
    cid_v1 = cid_v0.set(base='base32', version=1)
    return cid_v1.encode()
