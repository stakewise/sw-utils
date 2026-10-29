import logging

from web3.exceptions import BlockNotFound

logger = logging.getLogger(__name__)


class IpfsException(Exception):
    pass


class ExecutionBehindConsensusError(BlockNotFound):
    """Execution client does not have a block the consensus client already references."""
