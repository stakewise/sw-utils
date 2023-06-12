import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any
from urllib.parse import urljoin

import aiohttp
import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout
from ipfshttpclient.encoding import Json
from ipfshttpclient.exceptions import ErrorResponse

logger = logging.getLogger(__name__)


class IpfsException(Exception):
    pass


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
    def __init__(self, endpoint: str, username: str | None = None, password: str | None = None):
        self.endpoint = endpoint
        self.username = username
        self.password = password

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')

        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
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
        ) as client:
            client.repo.gc(quiet=True)


class PinataUploadClient(BaseUploadClient):
    json_endpoint = 'https://api.pinata.cloud/pinning/pinJSONToIPFS'
    bytes_endpoint = 'https://api.pinata.cloud/pinning/pinFileToIPFS'
    unpin_endpoint = 'https://api.pinata.cloud/pinning/unpin/'

    def __init__(self, api_key: str, secret_key: str):
        self.headers = {
            'pinata_api_key': api_key,
            'pinata_secret_api_key': secret_key,
        }

    async def upload_bytes(self, data: bytes) -> str:
        async with ClientSession(headers=self.headers) as session:
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
        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        async with ClientSession(headers=headers) as session:
            async with session.post(
                url=self.json_endpoint,
                data=_dump_json({'pinataOptions': {'cidVersion': 1}, 'pinataContent': data}),
            ) as response:
                response.raise_for_status()
                ipfs_id = (await response.json())['IpfsHash']
        return _strip_ipfs_prefix(ipfs_id)

    async def remove(self, ipfs_hash: str) -> None:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        headers = self.headers.copy()
        headers['Content-Type'] = 'application/json'
        async with ClientSession(headers=headers) as session:
            async with session.delete(url=urljoin(self.unpin_endpoint, ipfs_hash)) as response:
                response.raise_for_status()
        return None


class WebStorageClient(BaseUploadClient):
    upload_endpoint = 'https://api.web3.storage/upload'
    unpin_endpoint = 'https://api.web3.storage/pins'

    def __init__(self, api_token: str):
        self.headers = {
            'Authorization': f'bearer {api_token}',
        }

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
        async with ClientSession(headers=self.headers) as session:
            async with session.delete(url=urljoin(self.unpin_endpoint, ipfs_hash)) as response:
                response.raise_for_status()
        return None

    async def _upload(self, form_data: aiohttp.FormData) -> str:
        async with ClientSession(headers=self.headers) as session:
            async with session.post(
                url=self.upload_endpoint,
                data=form_data,
            ) as response:
                response.raise_for_status()
                ipfs_id = (await response.json())['cid']

        return _strip_ipfs_prefix(ipfs_id)


class IpfsMultiUploadClient(BaseUploadClient):
    def __init__(self, clients: list[BaseUploadClient]):
        if len(clients) == 0:
            raise ValueError('Invalid number of clients')
        self.clients = clients
        self.quorum = (len(clients) // 2) + 1

    async def upload_bytes(self, data: bytes) -> str:
        if not data:
            raise ValueError('Empty data provided')
        coros = [client.upload_bytes(data) for client in self.clients]
        return await self._upload(coros)

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        coros = [client.upload_json(data) for client in self.clients]
        return await self._upload(coros)

    async def _upload(self, coros: list) -> str:
        result = await asyncio.gather(*coros, return_exceptions=True)

        ipfs_hashes: dict[str, int] = {}
        for value in result:
            if isinstance(value, BaseException):
                logger.error(repr(value))
                continue

            ipfs_hash = _strip_ipfs_prefix(value)
            ipfs_hashes[ipfs_hash] = ipfs_hashes.get(ipfs_hash, 0) + 1

        if not ipfs_hashes:
            raise IpfsException('Upload to all clients has failed')

        ipfs_hash = max(ipfs_hashes, key=ipfs_hashes.get)  # type: ignore
        count = ipfs_hashes[ipfs_hash]
        if count < self.quorum:
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
                logger.error(repr(value))
                continue
        return None


class IpfsFetchClient:
    def __init__(
            self,
            endpoints: list[str],
            timeout: int = 60,
    ):
        self.endpoints = endpoints
        self.timeout = timeout

    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_bytes(endpoint, ipfs_hash)

                return self._ipfs_fetch_bytes(endpoint, ipfs_hash)
            except Exception as e:
                logger.error(repr(e))

        raise IpfsException(f'Failed to fetch IPFS data at {ipfs_hash}')

    async def _http_gateway_fetch_bytes(self, endpoint: str, ipfs_hash: str) -> bytes:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            async with session.get(
                    f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}"
            ) as response:
                response.raise_for_status()
                return await response.read()

    def _ipfs_fetch_bytes(self, endpoint: str, ipfs_hash: str) -> bytes:
        with ipfshttpclient.connect(
                endpoint,
        ) as client:
            return client.cat(ipfs_hash, timeout=self.timeout)

    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        """Tries to fetch IPFS hash from different sources."""
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_json(endpoint, ipfs_hash)

                return self._ipfs_fetch_json(endpoint, ipfs_hash)
            except Exception as e:
                logger.error(repr(e))

        raise IpfsException(f'Failed to fetch IPFS data at {ipfs_hash}')

    async def _http_gateway_fetch_json(self, endpoint: str, ipfs_hash: str) -> dict | list:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            async with session.get(
                    f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}"
            ) as response:
                response.raise_for_status()
                return await response.json()

    def _ipfs_fetch_json(self, endpoint: str, ipfs_hash: str) -> dict | list:
        with ipfshttpclient.connect(
                endpoint,
        ) as client:
            return client.get_json(ipfs_hash, timeout=self.timeout)


def _strip_ipfs_prefix(ipfs_hash: str) -> str:
    return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')


def _dump_json(data: Any) -> bytes:
    return Json().encode(data)
