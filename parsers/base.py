"""
Shared utilities for all source parsers.

Every parser imports from here instead of reimplementing helpers.
"""
import re
import logging
from pathlib import Path
from typing import Any, Optional

import orjson
from dateutil import parser as date_parser

logger = logging.getLogger(__name__)

# ── Patterns ──────────────────────────────────────────────────────────
CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-(\d+)\s*(.*)")


# ── File I/O ──────────────────────────────────────────────────────────
def load_records(filepath: str | Path) -> list | dict:
    """Read a JSON file via orjson. Returns list or dict; returns [] on missing file."""
    filepath = Path(filepath)
    if not filepath.exists():
        logger.warning("File not found, skipping: %s", filepath)
        return []
    with open(filepath, "rb") as f:
        data = orjson.loads(f.read())
    if isinstance(data, list):
        logger.info("Loaded %d records from %s", len(data), filepath.name)
    elif isinstance(data, dict):
        logger.info("Loaded dict from %s", filepath.name)
    return data


# ── Date handling ─────────────────────────────────────────────────────
def normalize_date(raw_date: Any) -> Optional[str]:
    """Standardise any date string/object to ISO-8601 (YYYY-MM-DD)."""
    if not raw_date:
        return None
    date_str = str(raw_date).strip()
    if not date_str:
        return None

    # Fast path: already ISO
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str):
        return date_str

    try:
        return date_parser.parse(date_str).date().isoformat()
    except (ValueError, OverflowError):
        pass

    # Fallback regex
    match = re.search(r"(\d{4})[-/](\d{2})(?:[-/](\d{2}))?", date_str)
    if match:
        year, month = match.group(1), match.group(2)
        day = match.group(3) or "01"
        return f"{year}-{month}-{day}"

    logger.warning("Could not parse date: %r", raw_date)
    return None


# ── CWE extraction ───────────────────────────────────────────────────
def extract_cwe(raw: Any) -> tuple[Optional[int], Optional[str]]:
    """'CWE-703 Improper Check...' → (703, 'Improper Check...')."""
    if not raw:
        return None, None
    match = CWE_PATTERN.match(str(raw).strip())
    if not match:
        return None, None
    return int(match.group(1)), (match.group(2).strip() or None)


# ── CVE ID validation ────────────────────────────────────────────────
def validate_cve_id(raw: Any) -> Optional[str]:
    """Normalise and validate a CVE ID string. Returns None if invalid."""
    if not raw:
        return None
    cve_id = str(raw).strip().upper()
    return cve_id if CVE_REGEX.match(cve_id) else None


# ── Severity parsing ─────────────────────────────────────────────────
def parse_severity_string(raw: Any) -> tuple[Optional[str], Optional[float]]:
    """
    Handle mixed severity formats:
      '7.3'          → (None, 7.3)
      '8.6 (High)'   → ('HIGH', 8.6)
      'High'         → ('HIGH', None)
      'Critical'     → ('CRITICAL', None)
    Returns (severity_label, cvss_score).
    """
    if not raw:
        return None, None
    s = str(raw).strip()

    # Try "8.6 (High)" format
    match = re.match(r"([\d.]+)\s*\((\w+)\)", s)
    if match:
        score = float(match.group(1))
        label = match.group(2).upper()
        return label, score

    # Pure numeric
    try:
        score = float(s)
        # Derive label from CVSS v3 ranges
        if score >= 9.0:
            return "CRITICAL", score
        elif score >= 7.0:
            return "HIGH", score
        elif score >= 4.0:
            return "MEDIUM", score
        elif score > 0:
            return "LOW", score
        return None, score
    except ValueError:
        pass

    # Pure label
    if s.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"):
        return s.upper(), None
    return None, None
