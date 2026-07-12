"""
Parser for Qualcomm chipset CVE data.

Source file: qualcomm_cves.json (5.2 MB)
Output tables: chipset, cve_affected_chipset, cwe, cve_cwe
"""
import logging
from pathlib import Path

from parsers.base import load_records, validate_cve_id, extract_cwe

logger = logging.getLogger(__name__)

FILES = ["qualcomm_cves.json"]
VENDOR = "Qualcomm"


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / FILES[0])
    if not records:
        return {}

    chipsets: dict[str, dict] = {}          # name → record (dedup)
    cve_affected: list[dict] = []
    cwes: dict[int, dict] = {}              # cwe_id → record (dedup)
    cve_cwes: list[dict] = []

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

        # ── cwe from vulnerability_type field ─────────────────────
        cwe_id, cwe_name = extract_cwe(r.get("vulnerability_type"))
        if cwe_id is not None:
            if cwe_id not in cwes:
                cwes[cwe_id] = {
                    "cwe_id":       cwe_id,
                    "name":         cwe_name,
                    "description":  None,
                }
            cve_cwes.append({"cve_id": cve_id, "cwe_id": cwe_id})

    result: dict[str, list[dict]] = {}
    if chipsets:
        result["chipset"] = list(chipsets.values())
    if cve_affected:
        result["cve_affected_chipset"] = cve_affected
    if cwes:
        result["cwe"] = list(cwes.values())
    if cve_cwes:
        result["cve_cwe"] = cve_cwes

    logger.info(
        "Qualcomm: %d chipsets, %d cve_affected_chipset, %d CWEs",
        len(chipsets), len(cve_affected), len(cwes),
    )
    return result
