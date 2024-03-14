from web3 import Web3
from web3.types import Wei

WAD = Web3.to_wei(1, 'ether')
MGNO_RATE = Web3.to_wei(32, 'ether')


def convert_to_gno(mgno_amount: Wei) -> Wei:
    """Converts mGNO to GNO."""
    return Wei(mgno_amount * WAD // MGNO_RATE)


def convert_to_mgno(gno_amount: Wei) -> Wei:
    """Converts GNO to mGNO."""
    return Wei(gno_amount * MGNO_RATE // WAD)
