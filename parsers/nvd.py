"""
Parser for NVD (National Vulnerability Database) data.

Source file: nvd_parser.json (86 MB)
Output tables: cve, cwe, cve_cwe, cve_reference, cpe
"""
import logging
from pathlib import Path

from parsers.base import load_records, validate_cve_id

logger = logging.getLogger(__name__)

FILES = ["nvd_parser.json"]


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / FILES[0])
    if not records:
        return {}

    cves: list[dict] = []
    cwes: list[dict] = []
    cve_cwes: list[dict] = []
    cve_references: list[dict] = []
    cpe_records: list[dict] = []

    seen_cwes: set[int] = set()

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        # ── cve table ─────────────────────────────────────────────
        cvss = r.get("cvss") or {}
        v2 = cvss.get("v2") or {}
        v3_0 = cvss.get("v3_0") or {}
        v3_1 = cvss.get("v3_1") or {}

        cvss_v3 = v3_1.get("base_score") or v3_0.get("base_score")
        severity = (
            v3_1.get("severity")
            or v3_0.get("severity")
            or v2.get("severity")
        )

        published = r.get("published") or ""
        publish_date = published[:10] if len(published) >= 10 else None

        cves.append({
            "cve_id":           cve_id,
            "description":      r.get("description"),
            "cvss_v2_score":    v2.get("base_score"),
            "cvss_v3_score":    cvss_v3,
            "cvss_v4_score":    None,
            "severity":         severity,
            "publish_date":     publish_date,
            "discovery_date":   publish_date,
            "origin_type":      r.get("source_identifier"),
            "exploited_in_wild": None,
        })

        # ── cwe + cve_cwe tables ──────────────────────────────────
        for cwe_entry in r.get("cwe") or []:
            cwe_id_str = cwe_entry.get("id", "")
            if not cwe_id_str.startswith("CWE-"):
                continue
            try:
                cwe_id = int(cwe_id_str[4:])
            except ValueError:
                continue

            if cwe_id not in seen_cwes:
                seen_cwes.add(cwe_id)
                cwes.append({
                    "cwe_id":       cwe_id,
                    "name":         None,
                    "description":  None,
                })
            cve_cwes.append({"cve_id": cve_id, "cwe_id": cwe_id})

        # ── cve_reference table ───────────────────────────────────
        for ref in r.get("references") or []:
            tags = ref.get("tags") or []
            cve_references.append({
                "cve_id":   cve_id,
                "url":      ref.get("url"),
                "source":   ref.get("source"),
                "tags":     ",".join(tags) if tags else None,
                "is_patch": "Patch" in tags,
            })

        # ── cpe (passthrough for existing cpe loader) ─────────────
        cpe_configs = r.get("cpe_configurations") or []
        if cpe_configs:
            cpe_records.append({
                "cve_id":               cve_id,
                "cpe_configurations":   cpe_configs,
            })

    result: dict[str, list[dict]] = {}
    if cves:
        result["cve"] = cves
    if cwes:
        result["cwe"] = cwes
    if cve_cwes:
        result["cve_cwe"] = cve_cwes
    if cve_references:
        result["cve_reference"] = cve_references
    if cpe_records:
        result["cpe"] = cpe_records

    logger.info(
        "NVD: %d CVEs, %d CWEs, %d refs, %d CPE groups",
        len(cves), len(cwes), len(cve_references), len(cpe_records),
    )
    return result
