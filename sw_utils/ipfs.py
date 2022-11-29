import json
import logging
from typing import Dict

import backoff
import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout

from sw_utils.common import LimitedSizeDict

logger = logging.getLogger(__name__)

timeout = ClientTimeout(total=60)

CACHE_SIZE = 1024
IPFS_CACHE: Dict[str, bytes] = LimitedSizeDict(size_limit=CACHE_SIZE)


class BaseConnector:

    async def fetch(self, ipfs_hash: str) -> bytes | None:
        raise NotImplementedError

    async def upload(self, data: str) -> str | None:
        raise NotImplementedError


class LocalConnector(BaseConnector):
    endpoint: str

    def __init__(self, endpoint: str):
        self.endpoint = endpoint

    async def fetch(self, ipfs_hash: str) -> bytes | None:
        try:
            with ipfshttpclient.connect(self.endpoint) as client:
                return client.cat(ipfs_hash)
        except ipfshttpclient.exceptions.TimeoutError:
            logger.info('IPFS local connection timeout...')
            return None

    async def upload(self, data: str) -> str | None:
        try:
            with ipfshttpclient.connect(self.endpoint) as client:
                ipfs_id = client.add_str(data)
                client.pin.add(ipfs_id)
                return ipfs_id
        except Exception as e:
            logger.error(e)
            return None


class GatewayConnector(BaseConnector):
    endpoints: list[str]

    def __init__(self, endpoints: list[str]):
        self.endpoints = endpoints

    async def fetch(self, ipfs_hash: str) -> bytes | None:
        async with ClientSession(timeout=timeout) as session:
            for endpoint in self.endpoints:
                try:
                    response = await session.get(f"{endpoint.rstrip('/')}/ipfs/{ipfs_hash}")
                    response.raise_for_status()
                    return await response.read()
                except BaseException as e:  # noqa: E722
                    logger.exception(e)
        return None

    async def upload(self, data: str) -> str | None:
        raise NotImplementedError


class InfuraConnector(BaseConnector):
    endpoint: str
    username: str
    password: str

    def __init__(self, endpoint: str, username: str, password: str):
        self.endpoint = endpoint
        self.username = username
        self.password = password

    async def fetch(self, ipfs_hash: str) -> bytes | None:
        try:
            with ipfshttpclient.connect(
                    self.endpoint,
                    username=self.username,
                    password=self.password,
            ) as client:
                return client.cat(ipfs_hash)
        except ipfshttpclient.exceptions.TimeoutError:
            logger.info('IPFS Infura connection timeout...')
            return None

    async def upload(self, data: str) -> str | None:
        try:
            with ipfshttpclient.connect(
                    self.endpoint,
                    username=self.username,
                    password=self.password,
            ) as client:
                ipfs_id = client.add_str(data)
                client.pin.add(ipfs_id)
                return ipfs_id
        except Exception as e:
            logger.error(e)
            return None


class PinataConnector(BaseConnector):
    endpoint: str
    api_key: str
    secret_key: str

    def __init__(self, endpoint: str, api_key: str, secret_key: str):
        self.endpoint = endpoint
        self.api_key = api_key
        self.secret_key = secret_key

    async def fetch(self, ipfs_hash: str) -> bytes | None:
        raise NotImplementedError

    async def upload(self, data: str) -> str | None:
        headers = {
            'pinata_api_key': self.api_key,
            'pinata_secret_api_key': self.secret_key,
            'Content-Type': 'application/json',
        }
        try:
            async with ClientSession(headers=headers) as session:
                response = await session.post(
                    url=self.endpoint,
                    data=json.dumps({'pinataContent': data}, sort_keys=True),
                )
                response.raise_for_status()
                ipfs_id = (await response.json())['IpfsHash']
                return ipfs_id
        except Exception as e:  # noqa: E722
            logger.error(e)
            logger.error('Failed to submit claims to Pinata')
            return None


class IpfsClient:
    local_connector: LocalConnector | None
    infura_connector: InfuraConnector | None
    pinata_connector: PinataConnector | None
    gateway_connector: GatewayConnector | None

    def __init__(
            self,
            local_connector: LocalConnector | None = None,
            infura_connector: InfuraConnector | None = None,
            pinata_connector: PinataConnector | None = None,
            gateway_connector: GatewayConnector | None = None,
    ):
        self.local_connector = local_connector
        self.infura_connector = infura_connector
        self.pinata_connector = pinata_connector
        self.gateway_connector = gateway_connector

    @backoff.on_exception(backoff.expo, Exception, max_time=300)
    async def fetch(self, ipfs_hash: str) -> bytes:
        """Tries to fetch IPFS hash from different sources."""
        ipfs_hash = self._strip_ipfs_prefix(ipfs_hash)
        if IPFS_CACHE.get(ipfs_hash):
            return IPFS_CACHE[ipfs_hash]

        for connector in self.fetch_connectors:
            data = await connector.fetch(ipfs_hash)
            if data:
                IPFS_CACHE[ipfs_hash] = data
                return data

        raise RuntimeError(f'Failed to fetch IPFS data at {ipfs_hash}')

    @backoff.on_exception(backoff.expo, Exception, max_time=300)
    async def upload(self, data: str) -> str:
        """Uploads data to the IPFS and pins the file."""
        ipfs_ids: list[str] = []
        if not ipfs_ids:
            raise RuntimeError('Failed to submit claims to IPFS')

        for connector in self.upload_connectors:
            ipfs_id = await connector.upload(data)
            if ipfs_id:
                ipfs_ids.append(ipfs_id)

        uniq_ipfs_ids = set(map(self._strip_ipfs_prefix, ipfs_ids))
        if len(uniq_ipfs_ids) != 1:
            raise RuntimeError(f"Received different ipfs IDs: {','.join(uniq_ipfs_ids)}")

        return uniq_ipfs_ids.pop()

    def _strip_ipfs_prefix(self, ipfs_hash: str) -> str:
        return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')

    @property
    def fetch_connectors(self):
        connectors = [self.local_connector, self.gateway_connector, self.infura_connector]
        return [c for c in connectors if c]

    @property
    def upload_connectors(self):
        connectors = [self.local_connector, self.infura_connector, self.pinata_connector]
        return [c for c in connectors if c]
