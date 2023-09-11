import asyncio
import logging

import aiohttp
import requests

logger = logging.getLogger(__name__)


# DEPRECATED
AiohttpRecoveredErrors = (
    aiohttp.ClientConnectionError,
    asyncio.TimeoutError,
)
RequestsRecoveredErrors = (
    requests.ConnectionError,
    requests.Timeout,
)
