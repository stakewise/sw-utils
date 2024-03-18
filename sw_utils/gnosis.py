from web3.types import Wei

MGNO_RATE = 32


def convert_to_gno(mgno_amount: Wei) -> Wei:
    """Converts mGNO to GNO."""
    return Wei(mgno_amount // MGNO_RATE)


def convert_to_mgno(gno_amount: Wei) -> Wei:
    """Converts GNO to mGNO."""
    return Wei(gno_amount * MGNO_RATE)
