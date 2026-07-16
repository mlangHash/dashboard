import logging
from pathlib import Path

from parsers.sources import parse_all_files
from parsers.oem import prepare as parse_oem

logger = logging.getLogger(__name__)


# Tables where records should be deduplicated (key field(s) to dedup on)
DEDUP_KEYS: dict[str, str | tuple[str, ...]] = {
    "vendor":               "name",
    "chipset":              "name",
    "cwe":                  "cwe_id",
    "cve_cwe":              ("cve_id", "cwe_id"),
    "source_repository":    "name",
    "cve_timeline_event":   ("cve_id", "event_type", "event_date"),
    "android_version":      "version_name",
    "device":               "codename",
    "component":            ("name", "layer")
}


# ── Dedup helpers ─────────────────────────────────────────────────────

def _dedup(records: list[dict], key: str | tuple[str, ...]) -> list[dict]:
    """Keep the first occurrence for each unique key value."""
    seen: set = set()
    result: list[dict] = []
    for rec in records:
        if isinstance(key, tuple):
            val = tuple(rec.get(k) for k in key)
        else:
            val = rec.get(key)
        if val not in seen:
            seen.add(val)
            result.append(rec)
    return result


def _dedup_cwe_prefer_filled(records: list[dict]) -> list[dict]:
    """
    Deduplicate CWE records by cwe_id, preferring records that have
    non-null name and description over those with nulls.
    """
    by_id: dict[int, dict] = {}
    for rec in records:
        cwe_id = rec.get("cwe_id")
        if cwe_id is None:
            continue
        if cwe_id not in by_id:
            by_id[cwe_id] = dict(rec)
            continue
        existing = by_id[cwe_id]
        # Prefer non-null name and description
        if existing.get("name") is None and rec.get("name") is not None:
            existing["name"] = rec["name"]
        if existing.get("description") is None and rec.get("description") is not None:
            existing["description"] = rec["description"]
    return list(by_id.values())


def _merge_cve_records(records: list[dict]) -> list[dict]:
    """
    Merge CVE records by cve_id. NVD data comes first (base), subsequent sources
    fill in missing fields (severity, description, exploited_in_wild).
    Longer descriptions win when both exist.
    """
    by_id: dict[str, dict] = {}

    for rec in records:
        cve_id = rec.get("cve_id")
        if not cve_id:
            continue

        if cve_id not in by_id:
            by_id[cve_id] = dict(rec)   # copy
            continue

        existing = by_id[cve_id]

        # Fill in missing scalar fields
        for field in ("description", "cvss_v2_score", "cvss_v3_score",
                      "cvss_v4_score", "severity", "publish_date",
                      "discovery_date", "origin_type"):
            if existing.get(field) is None and rec.get(field) is not None:
                existing[field] = rec[field]

        # Prefer longer description
        if rec.get("description") and existing.get("description"):
            if len(rec["description"]) > len(existing["description"]):
                existing["description"] = rec["description"]

        # Exploitation flag: True wins over None
        if rec.get("exploited_in_wild") is True:
            existing["exploited_in_wild"] = True

    return list(by_id.values())


# ── Main entry point ──────────────────────────────────────────────────

def prepare_all(data_dir: str | Path) -> dict[str, list[dict]]:
    """
    Run every registered parser, merge results by table name, and
    deduplicate records. Returns a dict keyed by table name.
    """
    data_dir = Path(data_dir)

    # Phase 1: Parse all files (merge by table name happens inside)
    merged = parse_all_files(data_dir)

    # Run the new OEM parser (CSV-to-JSON is auto-run if needed)
    oem_data = parse_oem(data_dir)
    for table_name, records in oem_data.items():
        if table_name not in merged:
            merged[table_name] = []
        merged[table_name].extend(records)

    # Phase 2: CWE dedup with preference for filled records
    if "cwe" in merged:
        before = len(merged["cwe"])
        merged["cwe"] = _dedup_cwe_prefer_filled(merged["cwe"])
        after = len(merged["cwe"])
        if before != after:
            logger.info("Deduped cwe (prefer filled): %d → %d", before, after)

    # Phase 3: Standard dedup for other tables
    for table_name, key in DEDUP_KEYS.items():
        if table_name == "cwe":
            continue  # already handled above
        if table_name in merged:
            before = len(merged[table_name])
            merged[table_name] = _dedup(merged[table_name], key)
            after = len(merged[table_name])
            if before != after:
                logger.info("Deduped %s: %d → %d", table_name, before, after)

    # Phase 4: Special merge for cve records (multi-source enrichment)
    if "cve" in merged:
        before = len(merged["cve"])
        merged["cve"] = _merge_cve_records(merged["cve"])
        logger.info("Merged cve records: %d → %d", before, len(merged["cve"]))

    # Phase 5: Ensure every referenced cve_id exists in the cve table to satisfy FK constraints
    referenced_cves = set()
    for table_name, records in merged.items():
        if table_name == "cve":
            continue
        for rec in records:
            if isinstance(rec, dict) and "cve_id" in rec and rec["cve_id"]:
                referenced_cves.add(rec["cve_id"])

    existing_cves = {rec["cve_id"] for rec in merged.get("cve", []) if "cve_id" in rec}
    missing_cves = referenced_cves - existing_cves
    if missing_cves:
        logger.info("Backfilling %d missing CVE stubs to satisfy FK constraints", len(missing_cves))
        if "cve" not in merged:
            merged["cve"] = []
        for cve_id in sorted(missing_cves):
            merged["cve"].append({
                "cve_id":           cve_id,
                "description":      None,
                "cvss_v2_score":    None,
                "cvss_v3_score":    None,
                "cvss_v4_score":    None,
                "severity":         None,
                "publish_date":     None,
                "discovery_date":   None,
                "origin_type":      None,
                "exploited_in_wild": None,
            })

    # Add the four standard layers with empty sublayers list
    merged["layer_sublayer"] = [
        {"layer": "Application", "layer_description": "Application Layer", "sublayers": []},
        {"layer": "Framework", "layer_description": "Application Framework Layer", "sublayers": []},
        {"layer": "Kernel/os", "layer_description": "Kernel / Operating System Layer", "sublayers": []},
        {"layer": "hardware", "layer_description": "Hardware / Chipset OEM Layer", "sublayers": []},
    ]

    # Summary
    for table_name, records in sorted(merged.items()):
        logger.info("  %-30s %6d records", table_name, len(records))

    return dict(merged)
