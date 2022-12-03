import json
import logging
from typing import Dict, Optional

import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout

from sw_utils.common import LimitedSizeDict

timeout = ClientTimeout(total=60)

logger = logging.getLogger(__name__)

CACHE_SIZE = 1024
IPFS_CACHE: Dict[str, bytes] = LimitedSizeDict(size_limit=CACHE_SIZE)


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


class IpfsFetchClient:
    def __init__(self, endpoints: list[str]):
        self.endpoints = endpoints

    @staticmethod
    async def _fetch_ipfs(endpoint: str, ipfs_hash: str) -> bytes:
        with ipfshttpclient.connect(
            endpoint,
        ) as client:
            return client.cat(ipfs_hash)

    @staticmethod
    async def _fetch_http(endpoint: str, ipfs_hash: str) -> bytes:
        async with ClientSession(timeout=timeout) as session:
            response = await session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}")
            response.raise_for_status()

        return await response.read()

    async def fetch(self, ipfs_hash: str) -> bytes:
        """Tries to fetch IPFS hash from different sources."""
        ipfs_hash = _strip_ipfs_prefix(ipfs_hash)
        if IPFS_CACHE.get(ipfs_hash):
            return IPFS_CACHE[ipfs_hash]

        for endpoint in self.endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._fetch_http(endpoint, ipfs_hash)

                return await self._fetch_ipfs(endpoint, ipfs_hash)
            except Exception as e:
                logger.error(e)

        raise RuntimeError(f'Failed to fetch IPFS data at {ipfs_hash}')
