import logging
from config.constants import LOG_FILENAME, LOG_FORMAT

# logging constants
LEVEL = logging.DEBUG


# create a logger for all modules to use
def setup_logging():
    """
    Configure global logging settings
    Is only called once (from main.py)
    """
    logging.basicConfig(
        filename=LOG_FILENAME,
        level=LEVEL,
        format=LOG_FORMAT,
        filemode="a"
    )

def get_logger(name: str) -> logging.Logger:
    """
    Returns a module-specific logger.
    """
    return logging.getLogger(name)