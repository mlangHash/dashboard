"""
Parser orchestrator — runs every source parser, merges results by table name,
and deduplicates where needed.

Usage:
    from parsers import prepare_all
    dataset = prepare_all(Path("files"))
    # dataset["cve"]           → list of loader-ready cve dicts
    # dataset["cve_reference"] → list of loader-ready cve_reference dicts
    # ...
"""
import logging
from collections import defaultdict
from pathlib import Path

from parsers import nvd, asb, qualcomm, mediatek, samsung, vendor_bulletins, aosp

logger = logging.getLogger(__name__)

# ── Registry: add new parsers here ────────────────────────────────────
# Order matters only for merge priority of 'cve' records — NVD should be
# first so its data forms the base, and other sources enrich on top.
ALL_PARSERS = [
    nvd,
    asb,
    qualcomm,
    mediatek,
    samsung,
    vendor_bulletins,
    aosp,
]

# Tables where records should be deduplicated (key field(s) to dedup on)
DEDUP_KEYS: dict[str, str | tuple[str, ...]] = {
    "vendor":               "name",
    "chipset":              "name",
    "cwe":                  "cwe_id",
    "cve_cwe":              ("cve_id", "cwe_id"),
    "source_repository":    "name",
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
    merged: dict[str, list[dict]] = defaultdict(list)

    for parser_module in ALL_PARSERS:
        name = parser_module.__name__.rsplit(".", 1)[-1]
        logger.info("Running parser: %s", name)
        try:
            result = parser_module.prepare(data_dir)
        except Exception:
            logger.exception("Parser %s failed", name)
            continue

        for table_name, records in result.items():
            merged[table_name].extend(records)

    # ── Post-merge dedup ──────────────────────────────────────────
    for table_name, key in DEDUP_KEYS.items():
        if table_name in merged:
            before = len(merged[table_name])
            merged[table_name] = _dedup(merged[table_name], key)
            after = len(merged[table_name])
            if before != after:
                logger.info("Deduped %s: %d → %d", table_name, before, after)

    # Special merge for cve records (multi-source enrichment)
    if "cve" in merged:
        before = len(merged["cve"])
        merged["cve"] = _merge_cve_records(merged["cve"])
        logger.info("Merged cve records: %d → %d", before, len(merged["cve"]))

    # Summary
    for table_name, records in sorted(merged.items()):
        logger.info("  %-30s %6d records", table_name, len(records))

    return dict(merged)
