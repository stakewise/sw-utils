import logging
import signal

logger = logging.getLogger(__name__)


class InterruptHandler:
    """
    Tracks SIGINT and SIGTERM signals.
    """

    exit = False

    def __init__(self) -> None:
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    # noinspection PyUnusedLocal
    def exit_gracefully(self, signum: int, *args, **kwargs) -> None:
        # pylint: disable=unused-argument
        logger.info('Received interrupt signal %s, exiting...', signum)
        self.exit = True
