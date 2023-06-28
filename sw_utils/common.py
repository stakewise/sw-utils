import logging
import signal

logger = logging.getLogger(__name__)


class InterruptHandler:
    """
    Tracks SIGINT and SIGTERM signals.
    Usage:
    with InterruptHandler() as interrupt_handler:
        while not interrupt_handler.exit:
        ...
    """

    exit = False

    def __enter__(self) -> 'InterruptHandler':
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        signal.signal(signal.SIGINT, self.exit_default)
        signal.signal(signal.SIGTERM, self.exit_default)

    def exit_gracefully(self, signum: int, *args, **kwargs) -> None:
        # pylint: disable=unused-argument
        if self.exit:
            raise KeyboardInterrupt
        logger.info('Received interrupt signal %s, exiting...', signum)
        self.exit = True

    def exit_default(self, signum: int, *args, **kwargs) -> None:
        # pylint: disable=unused-argument
        raise KeyboardInterrupt
