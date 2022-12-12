import asyncio
import json
import logging
from typing import Dict, Optional

import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout

timeout = ClientTimeout(total=60)

logger = logging.getLogger(__name__)


def _strip_ipfs_prefix(ipfs_hash: str) -> str:
    return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')


class BaseUploadClient:
    async def upload(self, data: str) -> str:
        raise NotImplementedError


class IpfsUploadClient(BaseUploadClient):
    def __init__(
        self, endpoint: str, username: Optional[str] = None, password: Optional[str] = None
    ):
        self.endpoint = endpoint
        self.username = username
        self.password = password

    async def upload(self, data: str) -> str:
        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
        ) as client:
            ipfs_id = client.add_str(data)
            client.pin.add(ipfs_id)

        return _strip_ipfs_prefix(ipfs_id)

    async def remove(self, ipfs_hash: str) -> None:
        with ipfshttpclient.connect(
            self.endpoint,
            username=self.username,
            password=self.password,
        ) as client:
            client.pin.rm(_strip_ipfs_prefix(ipfs_hash))

    async def cleanup(self) -> None:
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

    async def upload(self, data: str) -> str:
        async with ClientSession(headers=self.headers) as session:
            response = await session.post(
                url=self.endpoint,
                data=json.dumps({'pinataContent': data}, sort_keys=True),
            )
            response.raise_for_status()
            ipfs_id = (await response.json())['IpfsHash']
        return _strip_ipfs_prefix(ipfs_id)


class IpfsMultiUploadClient(BaseUploadClient):
    def __init__(self, clients: list[BaseUploadClient]):
        if len(clients) == 0:
            raise ValueError('Invalid number of clients')
        self.clients = clients
        self.quorum = (len(clients) // 2) + 1

    async def upload(self, data: str) -> str:
        result = await asyncio.gather(
            *[client.upload(data) for client in self.clients],
            return_exceptions=True
        )

        ipfs_hashes: Dict[str, int] = {}
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
    def __init__(self, endpoints: list[str]):
        self.endpoints = endpoints

    @staticmethod
    async def _fetch_ipfs(endpoint: str, ipfs_hash: str) -> str:
        with ipfshttpclient.connect(
            endpoint,
        ) as client:
            return client.cat(ipfs_hash).decode('utf-8')

    @staticmethod
    async def _fetch_http(endpoint: str, ipfs_hash: str) -> str:
        async with ClientSession(timeout=timeout) as session:
            response = await session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}")
            response.raise_for_status()

        return (await response.read()).decode('utf-8')

    async def fetch(self, ipfs_hash: str) -> str:
        """Tries to fetch IPFS hash from different sources."""
        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._fetch_http(endpoint, ipfs_hash)

                return await self._fetch_ipfs(endpoint, ipfs_hash)
            except Exception as e:
                logger.error(e)

        raise RuntimeError(f'Failed to fetch IPFS data at {ipfs_hash}')
