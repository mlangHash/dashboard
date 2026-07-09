import logging
from pathlib import Path

import orjson

logger = logging.getLogger(__name__)


def load_records(filepath: str | Path) -> list[dict]:
    """Reads a JSON file and returns its records as a list of dicts."""

    filepath = Path(filepath)
    with open(filepath, "rb") as f:
        data = orjson.loads(f.read())

    if not isinstance(data, list):
        raise ValueError(f"Expected a list of records, got {type(data).__name__}")

    logger.info("Loaded %d records from %s", len(data), filepath)
    return data