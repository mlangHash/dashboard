"""
Parser for Samsung semiconductor security CVE data.

Source file: samsung_security_cves.json (116 KB)
Output tables: cve, cve_reference, vendor
"""
import logging
from pathlib import Path

from parsers.base import load_records, normalize_date, validate_cve_id, parse_severity_string

logger = logging.getLogger(__name__)

FILES = ["samsung_security_cves.json"]
VENDOR = "Samsung"


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / FILES[0])
    if not records:
        return {}

    cves: list[dict] = []
    refs: list[dict] = []

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        severity_label, cvss_score = parse_severity_string(r.get("severity"))

        # ── cve table (partial — will merge with NVD) ─────────────
        cves.append({
            "cve_id":           cve_id,
            "description":      r.get("description"),
            "cvss_v2_score":    None,
            "cvss_v3_score":    cvss_score,
            "cvss_v4_score":    None,
            "severity":         severity_label,
            "publish_date":     normalize_date(r.get("reported_date")),
            "discovery_date":   normalize_date(r.get("reported_date")),
            "origin_type":      None,
            "exploited_in_wild": None,
        })

        # ── cve_reference ─────────────────────────────────────────
        url = r.get("url")
        if url:
            refs.append({
                "cve_id":   cve_id,
                "url":      url,
                "source":   "Samsung Semiconductor",
                "tags":     "Vendor Advisory",
                "is_patch": False,
            })

    result: dict[str, list[dict]] = {}
    if cves:
        result["cve"] = cves
    if refs:
        result["cve_reference"] = refs
    result["vendor"] = [{
        "name":                     VENDOR,
        "country":                  "KR",
        "security_bulletin_url":    "https://semiconductor.samsung.com/support/quality-support/product-security-updates/",
    }]

    logger.info("Samsung: %d CVEs, %d references", len(cves), len(refs))
    return result
