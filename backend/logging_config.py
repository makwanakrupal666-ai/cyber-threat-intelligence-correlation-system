import logging

from backend.config import LOG_LEVEL


def setup_logging():
    logging.basicConfig(
        level=getattr(
            logging,
            LOG_LEVEL.upper(),
            logging.INFO
        ),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    return logging.getLogger("cti-project")