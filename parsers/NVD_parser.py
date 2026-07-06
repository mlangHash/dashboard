import logging
from pathlib import Path
from typing import Iterator

import orjson

logger = logging.getLogger(__name__)


def load_records(filepath: str | Path) -> list[dict]:
    """
    Read an NVD-format JSON file and return the raw list of CVE records.
    """
    filepath = Path(filepath)
    with open(filepath, "rb") as f:
        data = orjson.loads(f.read())

    if not isinstance(data, list):
        raise ValueError(f"Expected a list of records, got {type(data).__name__}")

    logger.info("Loaded %d records from %s", len(data), filepath)
    return data


# def iter_valid_records(filepath: str | Path) -> Iterator[dict]:

#     REQUIRED_FIELDS = ("cve_id", "description", "published", "source_identifier", "cvss")

#     records = load_nvd_records(filepath)
#     skipped = 0

#     for rec in records:
#         missing = [f for f in REQUIRED_FIELDS if not rec.get(f)]
#         if missing:
#             skipped += 1
#             logger.warning(
#                 "Skipping record (missing %s): %s",
#                 missing, rec.get("cve_id", "<unknown id>"),
#             )
#             continue
#         yield rec

#     if skipped:
#         logger.info("Skipped %d/%d records due to missing required fields", skipped, len(records))