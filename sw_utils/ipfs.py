import asyncio
import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, AsyncIterator, cast
from urllib.parse import urljoin

import aiohttp
import ipfshttpclient
from aiohttp import ClientSession, ClientTimeout
from ipfshttpclient.encoding import Json
from ipfshttpclient.exceptions import ErrorResponse

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


class BasePinClient(ABC):
    """
    Allows to re-pin existing CID.
    https://ipfs.github.io/pinning-services-api-spec/
    """

    @abstractmethod
    async def pin(self, ipfs_hash: str) -> str:
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


class FilebasePinClient(BasePinClient):
    """
    https://docs.filebase.com/api-documentation/ipfs-pinning-service-api
    """

    # base_url must end with "/"
    base_url = 'https://api.filebase.io/v1/ipfs/'

    def __init__(self, api_token: str, timeout: int = IPFS_DEFAULT_TIMEOUT):
        self.api_token = api_token
        self.timeout = timeout

    async def pin(self, ipfs_hash: str) -> str:
        data = {
            'cid': ipfs_hash,
        }
        response = await self._call('POST', 'pins', data=data)
        cid = response['pin']['cid']
        if cid != ipfs_hash:
            raise ValueError(f'cid {cid} is not equal to ipfs_hash {ipfs_hash}')
        return cid

    async def remove(self, ipfs_hash: str) -> None:
        pin_results = await self._call('GET', 'pins', params={'cid': ipfs_hash})

        # Filebase returns the same request_id when pinning the same cid twice
        request_id = pin_results['results'][0]['requestid']

        await self._call('DELETE', f'pins/{request_id}')

    async def _call(
        self, http_method: str, endpoint: str, data: dict | None = None, params: dict | None = None
    ) -> dict:
        url = urljoin(self.base_url, endpoint)
        logger.debug('%s %s', http_method, url)

        # User and bucket are determined by token
        headers = {'Authorization': f'Bearer {self.api_token}'}

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            session_method = getattr(session, http_method.lower())
            async with session_method(url, json=data, params=params, headers=headers) as response:
                response.raise_for_status()
                return await response.json()


class QuicknodePinClient(BasePinClient):
    """
    https://www.quicknode.com/docs/ipfs/getting-started
    """

    # base_url must end with "/"
    base_url = 'https://api.quicknode.com/ipfs/rest/'

    def __init__(self, api_token: str, timeout: int = IPFS_DEFAULT_TIMEOUT, page_size: int = 100):
        self.api_token = api_token
        self.timeout = timeout
        self.page_size = page_size

    async def pin(self, ipfs_hash: str) -> str:
        data = {
            'cid': ipfs_hash,
            'name': ipfs_hash,
        }
        response = cast(dict, await self._call('POST', 'v1/pinning', data=data))
        cid = response['cid']
        if cid != ipfs_hash:
            raise ValueError(f'cid {cid} is not equal to ipfs_hash {ipfs_hash}')
        return cid

    async def remove(self, ipfs_hash: str) -> None:
        request_id = await self._get_request_id_by_ipfs_hash(ipfs_hash)

        if not request_id:
            raise ValueError(f'ipfs_hash {ipfs_hash} not found among pinned objects')

        await self._call('DELETE', f'v1/pinning/{request_id}', parse_json=False)

    async def _get_request_id_by_ipfs_hash(self, ipfs_hash: str) -> str | None:
        """
        'get-pins-list' endpoint can not filter by ipfs_hash.
        I have to search manually :\
        """
        async for pin_result in self._iter_pins():
            if pin_result['cid'] == ipfs_hash:
                # Multiple requests with same CID are not allowed by Quicknode.
                return pin_result['requestId']

        return None

    async def _iter_pins(self) -> AsyncIterator[dict]:
        """
        Iterator allows to search specific item without fetching all pages
        """
        page_number = 1
        total_pages = None

        while total_pages is None or page_number <= total_pages:
            params = {
                'pageNumber': page_number,
                'perPage': self.page_size,
            }
            pin_results = cast(dict, await self._call('GET', 'v1/pinning', params=params))
            for pin_result in pin_results['data']:
                yield pin_result

            page_number += 1
            total_pages = pin_results['totalPages']

    # pylint: disable-next=too-many-arguments
    async def _call(
        self,
        http_method: str,
        endpoint: str,
        data: dict | None = None,
        params: dict | None = None,
        parse_json: bool = True,
    ) -> dict | bytes:
        url = urljoin(self.base_url, endpoint)
        logger.debug('%s %s', http_method, url)

        headers = {'x-api-key': self.api_token}

        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(self.timeout)) as session:
            session_method = getattr(session, http_method.lower())
            async with session_method(url, params=params, json=data, headers=headers) as response:
                response.raise_for_status()
                if parse_json:
                    return await response.json()
                return await response.read()


class IpfsMultiUploadClient(BaseUploadClient):
    def __init__(
        self,
        upload_clients: list[BaseUploadClient],
        pin_clients: list[BasePinClient] | None = None,
        retry_timeout: int = 120,
    ):
        self.upload_clients = upload_clients
        self.pin_clients = pin_clients or []

        if len(self.upload_clients) == 0:
            raise ValueError('Invalid number of upload clients')

        self.quorum = (len(self.upload_clients) // 2) + 1
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
        coros = [client.upload_bytes(data) for client in self.upload_clients]
        ipfs_hash = await self._upload(coros)

        if self.pin_clients:
            await asyncio.gather(*(pin_client.pin(ipfs_hash) for pin_client in self.pin_clients))

        return ipfs_hash

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
        coros = [client.upload_json(data) for client in self.upload_clients]
        ipfs_hash = await self._upload(coros)

        if self.pin_clients:
            await asyncio.gather(*(pin_client.pin(ipfs_hash) for pin_client in self.pin_clients))

        return ipfs_hash

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
        clients: list[BaseUploadClient | BasePinClient] = self.upload_clients + self.pin_clients
        result = await asyncio.gather(
            *[client.remove(ipfs_hash) for client in clients], return_exceptions=True
        )
        for value in result:
            if isinstance(value, BaseException):
                logger.warning(repr(value))
                continue
        return None


class IpfsFetchClient:
    def __init__(
        self,
        ipfs_endpoints: list[str],
        s3_endpoints: list[str] | None = None,
        timeout: int = 60,
        retry_timeout: int = 120,
    ):
        self.ipfs_endpoints = ipfs_endpoints
        s3_endpoints = s3_endpoints or []
        self.s3_endpoints = [_ensure_ends_with_slash(e) for e in s3_endpoints]

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
        for endpoint in self.ipfs_endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_bytes(endpoint, ipfs_hash)

                return self._ipfs_fetch_bytes(endpoint, ipfs_hash)
            except Exception as e:
                logger.warning(repr(e))

        for endpoint in self.s3_endpoints:
            try:
                return await self._s3_fetch_bytes(endpoint, ipfs_hash)
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

    async def _s3_fetch_bytes(self, endpoint: str, ipfs_hash: str) -> bytes:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            # No "ipfs" part in url path, compare with ipfs gateway
            async with session.get(urljoin(endpoint, ipfs_hash)) as response:
                response.raise_for_status()
                return await response.read()

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
        for endpoint in self.ipfs_endpoints:
            try:
                if endpoint.startswith('http'):
                    return await self._http_gateway_fetch_json(endpoint, ipfs_hash)

                return self._ipfs_fetch_json(endpoint, ipfs_hash)
            except Exception as e:
                logger.warning(repr(e))

        for endpoint in self.s3_endpoints:
            try:
                return await self._s3_fetch_json(endpoint, ipfs_hash)
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

    async def _s3_fetch_json(self, endpoint: str, ipfs_hash: str) -> Any:
        async with ClientSession(timeout=ClientTimeout(self.timeout)) as session:
            # No "ipfs" part in url path, compare with ipfs gateway
            async with session.get(urljoin(endpoint, ipfs_hash)) as response:
                response.raise_for_status()
                return await response.json()


def _strip_ipfs_prefix(ipfs_hash: str) -> str:
    return ipfs_hash.replace('ipfs://', '').replace('/ipfs/', '')


def _dump_json(data: Any) -> bytes:
    return Json().encode(data)


def _ensure_ends_with_slash(url: str) -> str:
    if url.endswith('/'):
        return url
    return url + '/'
