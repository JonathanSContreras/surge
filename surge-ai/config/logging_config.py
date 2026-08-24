import logging
import os
from config.constants import LOG_FILENAME, LOG_FORMAT

# logging constants
LEVEL = logging.DEBUG

# Third-party libraries that flood the log with low-value DEBUG lines
_QUIET_LOGGERS = [
    "aiosqlite",
    "sqlalchemy.engine",
    "sqlalchemy.pool",
    "uvicorn.access",
    "httpx",
    "httpcore",
]


# create a logger for all modules to use
def setup_logging():
    """
    Configure global logging settings
    Is only called once (from main.py)
    """
    os.makedirs(os.path.dirname(LOG_FILENAME), exist_ok=True)
    logging.basicConfig(
        filename=LOG_FILENAME,
        level=LEVEL,
        format=LOG_FORMAT,
        filemode="a"
    )

    # Silence noisy third-party loggers — keep them at WARNING so real errors
    # still surface, but cursor/pool/request chatter is suppressed.
    for name in _QUIET_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """
    Returns a module-specific logger.
    """
    return logging.getLogger(name)