import asyncio
import base64
import json
import logging
from abc import ABC, abstractmethod

import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout
from ipfshttpclient.exceptions import ErrorResponse

logger = logging.getLogger(__name__)


class BaseUploadClient(ABC):
    @abstractmethod
    async def upload_bytes(self, data: bytes) -> str:
        raise NotImplementedError

    @abstractmethod
    async def upload_json(self, data: dict | list) -> str:
        raise NotImplementedError


class IpfsUploadClient(BaseUploadClient):
    def __init__(
        self, endpoint: str, username: str | None = None, password: str | None = None
    ):
        self.endpoint = endpoint
        self.username = username
        self.password = password

    async def upload_bytes(self, data: bytes) -> str:
        return await self.upload_json(_to_json(data))

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
        ) as client:
            ipfs_id = client.add_json(data)
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
    endpoint = 'https://api.pinata.cloud/pinning/pinJSONToIPFS'

    def __init__(self, api_key: str, secret_key: str):
        self.headers = {
            'pinata_api_key': api_key,
            'pinata_secret_api_key': secret_key,
            'Content-Type': 'application/json',
        }

    async def upload_bytes(self, data: bytes) -> str:
        return await self.upload_json(_to_json(data))

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        async with ClientSession(headers=self.headers) as session:
            async with session.post(
                url=self.endpoint,
                data=json.dumps({'pinataContent': data}),
            ) as response:
                response.raise_for_status()
                ipfs_id = (await response.json())['IpfsHash']
        return _strip_ipfs_prefix(ipfs_id)


class IpfsMultiUploadClient(BaseUploadClient):
    def __init__(self, clients: list[BaseUploadClient]):
        if len(clients) == 0:
            raise ValueError('Invalid number of clients')
        self.clients = clients
        self.quorum = (len(clients) // 2) + 1

    async def upload_bytes(self, data: bytes) -> str:
        return await self.upload_json(_to_json(data))

    async def upload_json(self, data: dict | list) -> str:
        if not data:
            raise ValueError('Empty data provided')

        result = await asyncio.gather(
            *[client.upload_json(data) for client in self.clients],
            return_exceptions=True
        )

        ipfs_hashes: dict[str, int] = {}
        for value in result:
            if isinstance(value, BaseException):
                logger.error(value)
                continue

            ipfs_hash = _strip_ipfs_prefix(value)
            ipfs_hashes[ipfs_hash] = ipfs_hashes.get(ipfs_hash, 0) + 1

        if not ipfs_hashes:
            raise RuntimeError('Upload to all clients has failed')

        ipfs_hash = max(ipfs_hashes, key=ipfs_hashes.get)  # type: ignore
        count = ipfs_hashes[ipfs_hash]
        if count < self.quorum:
            raise RuntimeError('Failed to reach the uploads quorum')

        return ipfs_hash


class IpfsFetchClient:
    def __init__(self, endpoints: list[str], timeout: int = 60):
        self.endpoints = endpoints
        self.timeout = timeout

    async def _fetch_ipfs(self, endpoint: str, ipfs_hash: str) -> dict | list:
        with ipfshttpclient.connect(
            endpoint,
        ) as client:
            return client.get_json(ipfs_hash, timeout=self.timeout)

    async def _fetch_http(self, endpoint: str, ipfs_hash: str) -> dict | list:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            async with session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}") as response:
                response.raise_for_status()
                return await response.json()

    async def fetch_bytes(self, ipfs_hash: str) -> bytes:
        return _from_json(await self.fetch_json(ipfs_hash))  # type: ignore

    async def fetch_json(self, ipfs_hash: str) -> dict | list:
        """Tries to fetch IPFS hash from different sources."""
        if not ipfs_hash:
            raise ValueError('Empty IPFS hash provided')

        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._fetch_http(endpoint, ipfs_hash)

                return await self._fetch_ipfs(endpoint, ipfs_hash)
            except Exception as e:
                logger.error(e)

        raise RuntimeError(f'Failed to fetch IPFS data at {ipfs_hash}')


def _strip_ipfs_prefix(ipfs_hash: str) -> str:
    return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')


def _to_json(data: bytes) -> list:
    return [base64.b64encode(data).decode('ascii')]


def _from_json(data: list) -> bytes:
    return base64.b64decode(data[0])
