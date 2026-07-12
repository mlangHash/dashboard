"""
Parser for Android Security Bulletin (ASB) data.

Source files:
  - asb_bulletins.json       → security_bulletin, vendor
  - asb_cves_raw.json        → (CVE enrichment reserved for future use)
  - asb_references_raw.json  → cve_reference
  - asb_exploited_cves.json  → cve (exploited_in_wild flag)
"""
import logging
from pathlib import Path

from parsers.base import load_records, normalize_date, validate_cve_id

logger = logging.getLogger(__name__)

FILES = [
    "asb_bulletins.json",
    "asb_cves_raw.json",
    "asb_references_raw.json",
    "asb_exploited_cves.json",
]

VENDOR_NAME = "Google"


def _parse_bulletins(data_dir: Path) -> tuple[list[dict], list[dict]]:
    """Parse asb_bulletins.json → security_bulletin + vendor records."""
    records = load_records(data_dir / "asb_bulletins.json")
    if not records:
        return [], []

    bulletins: list[dict] = []
    for r in records:
        bulletins.append({
            "vendor_name":      VENDOR_NAME,
            "title":            r.get("headline") or r.get("title", ""),
            "published_date":   normalize_date(r.get("published_date")),
            "severity_level":   None,
            "bulletin_url":     r.get("canonical_url"),
        })

    vendors = [{"name": VENDOR_NAME, "country": "US", "security_bulletin_url": "https://source.android.com/docs/security/bulletin"}]

    logger.info("ASB bulletins: %d security_bulletin records", len(bulletins))
    return bulletins, vendors


def _parse_references(data_dir: Path) -> list[dict]:
    """Parse asb_references_raw.json → cve_reference records."""
    records = load_records(data_dir / "asb_references_raw.json")
    if not records:
        return []

    refs: list[dict] = []
    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue
        ref_type = r.get("type", "")
        refs.append({
            "cve_id":   cve_id,
            "url":      r.get("url"),
            "source":   "ASB",
            "tags":     f"ASB,{ref_type}" if ref_type else "ASB",
            "is_patch": ref_type == "aosp_patch",
        })

    logger.info("ASB references: %d cve_reference records", len(refs))
    return refs


def _parse_exploited(data_dir: Path) -> list[dict]:
    """
    Parse asb_exploited_cves.json → minimal cve records with exploited_in_wild=True.
    These will be MERGED with NVD cve records by the orchestrator so only
    the exploitation flag survives (other fields stay None → won't overwrite).
    """
    records = load_records(data_dir / "asb_exploited_cves.json")
    if not records:
        return []

    cves: list[dict] = []
    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue
        cves.append({
            "cve_id":                   cve_id,
            "description":              None,
            "cvss_v2_score":            None,
            "cvss_v3_score":            None,
            "cvss_v4_score":            None,
            "severity":                 None,
            "publish_date":             None,
            "discovery_date":           None,
            "origin_type":              None,
            "exploited_in_wild":        True,
        })

    logger.info("ASB exploited: %d CVEs flagged as exploited in wild", len(cves))
    return cves


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    bulletins, vendors = _parse_bulletins(data_dir)
    refs = _parse_references(data_dir)
    exploited_cves = _parse_exploited(data_dir)

    result: dict[str, list[dict]] = {}
    if bulletins:
        result["security_bulletin"] = bulletins
    if vendors:
        result["vendor"] = vendors
    if refs:
        result["cve_reference"] = refs
    if exploited_cves:
        result["cve"] = exploited_cves
    return result
