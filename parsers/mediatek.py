"""
Parser for MediaTek chipset CVE data.

Source file: mediatek_cves.json (1.4 MB)
Output tables: chipset, cve_affected_chipset, cwe, cve_cwe, security_bulletin
"""
import logging
from pathlib import Path

from parsers.base import load_records, normalize_date, validate_cve_id, extract_cwe

logger = logging.getLogger(__name__)

FILES = ["mediatek_cves.json"]
VENDOR = "MediaTek"


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / FILES[0])
    if not records:
        return {}

    chipsets: dict[str, dict] = {}
    cve_affected: list[dict] = []
    cwes: dict[int, dict] = {}
    cve_cwes: list[dict] = []
    bulletins: dict[str, dict] = {}     # bulletin_id → record (dedup)

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        # ── chipset + cve_affected_chipset ────────────────────────
        for chip_name in r.get("affected_chipsets") or []:
            chip_name = str(chip_name).strip()
            if not chip_name:
                continue
            if chip_name not in chipsets:
                chipsets[chip_name] = {
                    "name":             chip_name,
                    "vendor":           VENDOR,
                    "model_number":     None,
                    "chipset_family":   None,
                    "release_date":     None,
                }
            cve_affected.append({
                "cve_id":       cve_id,
                "chipset_name": chip_name,
                "is_patched":   None,
            })

        # ── cwe from the "cwe" field ──────────────────────────────
        cwe_id, cwe_name = extract_cwe(r.get("cwe"))
        if cwe_id is not None:
            if cwe_id not in cwes:
                cwes[cwe_id] = {
                    "cwe_id":       cwe_id,
                    "name":         cwe_name,
                    "description":  None,
                }
            cve_cwes.append({"cve_id": cve_id, "cwe_id": cwe_id})

        # ── security_bulletin (one per bulletin_id) ───────────────
        bid = r.get("bulletin_id")
        if bid and bid not in bulletins:
            month = r.get("bulletin_month", "")
            year = r.get("bulletin_year", "")
            pub_date = normalize_date(f"{month} 1, {year}") if month and year else None
            bulletins[bid] = {
                "vendor_name":      VENDOR,
                "title":            f"MediaTek Product Security Bulletin — {month} {year}".strip(),
                "published_date":   pub_date,
                "severity_level":   None,
                "bulletin_url":     r.get("bulletin_url"),
            }

    result: dict[str, list[dict]] = {}
    if chipsets:
        result["chipset"] = list(chipsets.values())
    if cve_affected:
        result["cve_affected_chipset"] = cve_affected
    if cwes:
        result["cwe"] = list(cwes.values())
    if cve_cwes:
        result["cve_cwe"] = cve_cwes
    if bulletins:
        result["security_bulletin"] = list(bulletins.values())

    logger.info(
        "MediaTek: %d chipsets, %d cve_affected, %d CWEs, %d bulletins",
        len(chipsets), len(cve_affected), len(cwes), len(bulletins),
    )
    return result
