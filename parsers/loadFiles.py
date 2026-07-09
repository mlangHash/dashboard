import logging
from pathlib import Path
from typing import Iterator

import orjson

logger = logging.getLogger(__name__)


def load_records(filepath: str | Path) -> list[dict]:
    """
    read the specified filepath files
    """
    filepath = Path(filepath)
    with open(filepath, "rb") as f:
        data = orjson.loads(f.read())

    if not isinstance(data, list):
        raise ValueError(f"Expected a list of records, got {type(data).__name__}")

    logger.info("Loaded %d records from %s", len(data), filepath)
    return data

