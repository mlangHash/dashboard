"""
Tables populated:
  cve, cwe, cve_cwe, cve_reference, cpe, vendor, security_bulletin,
  vendor_cve, chipset, cve_affected_chipset, source_repository,
  cve_source_mapping, cve_timeline_event
"""
import logging
from collections import defaultdict
from pathlib import Path

from parsers.base import (
    load_records,
    normalize_date,
    validate_cve_id,
    extract_cwe,
    parse_severity_string,
)

logger = logging.getLogger(__name__)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Vendor canonical name mapping (shared across bulletin sources)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VENDOR_CANONICAL = {
    "google":   "Google",
    "samsung":  "Samsung",
    "motorola": "Motorola",
    "oppo":     "OPPO",
    "vivo":     "Vivo",
    "xiaomi":   "Xiaomi",
}


def _canonical_vendor(raw: str) -> str:
    return VENDOR_CANONICAL.get(raw.lower().strip(), raw.strip().title())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 1. nvd_parser.json  →  cve, cwe, cve_cwe, cve_reference, cpe
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_nvd(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "nvd_parser.json")
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 2. CWE-Fulllist_unique.json  →  cwe (with name + description)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_cwe_fulllist(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "CWE-Fulllist_unique.json")
    if not records:
        return {}

    cwes: list[dict] = []
    for r in records:
        raw_id = r.get("CWE-ID")
        if not raw_id:
            continue
        try:
            cwe_id = int(str(raw_id).strip())
        except ValueError:
            continue

        cwes.append({
            "cwe_id":       cwe_id,
            "name":         r.get("Name") or None,
            "description":  r.get("Description") or None,
        })

    logger.info("CWE full-list: %d CWE records with name & description", len(cwes))
    return {"cwe": cwes} if cwes else {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 3. asb_bulletins.json  →  security_bulletin, vendor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_asb_bulletins(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "asb_bulletins.json")
    if not records:
        return {}

    VENDOR_NAME = "Google"
    bulletins: list[dict] = []
    for r in records:
        bulletins.append({
            "vendor_name":      VENDOR_NAME,
            "title":            r.get("headline") or r.get("title", ""),
            "published_date":   normalize_date(r.get("published_date")),
            "severity_level":   None,
            "bulletin_url":     r.get("canonical_url"),
        })

    vendors = [{
        "name": VENDOR_NAME,
        "country": "US",
        "security_bulletin_url": "https://source.android.com/docs/security/bulletin",
    }]

    logger.info("ASB bulletins: %d security_bulletin records", len(bulletins))
    result: dict[str, list[dict]] = {}
    if bulletins:
        result["security_bulletin"] = bulletins
    result["vendor"] = vendors
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 4. asb_cves_raw.json  →  cve (enrichment), cve_cwe, cve_timeline_event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_asb_cves_raw(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "asb_cves_raw.json")
    if not records:
        return {}

    cves: list[dict] = []
    cwes: dict[int, dict] = {}
    cve_cwes: list[dict] = []
    timeline: list[dict] = []

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        severity_label, cvss_score = parse_severity_string(r.get("severity"))

        # ── cve enrichment (severity from ASB) ────────────────────
        cves.append({
            "cve_id":           cve_id,
            "description":      None,  # NVD has the canonical description
            "cvss_v2_score":    None,
            "cvss_v3_score":    cvss_score,
            "cvss_v4_score":    None,
            "severity":         severity_label,
            "publish_date":     None,
            "discovery_date":   None,
            "origin_type":      None,
            "exploited_in_wild": None,
        })

        # ── cwe from vulnerability_type ───────────────────────────
        vuln_type = r.get("vulnerability_type", "")
        # ASB uses short codes like "EoP", "DoS", "ID", "RCE"
        # These aren't CWE IDs, so only extract if it looks like CWE-xxx
        cwe_id, cwe_name = extract_cwe(vuln_type)
        if cwe_id is not None:
            if cwe_id not in cwes:
                cwes[cwe_id] = {
                    "cwe_id":       cwe_id,
                    "name":         cwe_name,
                    "description":  None,
                }
            cve_cwes.append({"cve_id": cve_id, "cwe_id": cwe_id})

        # ── cve_timeline_event from patch_level ───────────────────
        patch_level = r.get("patch_level")
        if patch_level:
            patch_date = normalize_date(patch_level)
            if patch_date:
                timeline.append({
                    "cve_id":           cve_id,
                    "event_type":       "patch_level_published",
                    "event_date":       patch_date,
                    "notes":            f"ASB bulletin {r.get('bulletin_id', '')}; "
                                        f"component: {r.get('component_group', '')}/{r.get('component', '')}",
                    "source_reference": r.get("bulletin_id"),
                })

    result: dict[str, list[dict]] = {}
    if cves:
        result["cve"] = cves
    if cwes:
        result["cwe"] = list(cwes.values())
    if cve_cwes:
        result["cve_cwe"] = cve_cwes
    if timeline:
        result["cve_timeline_event"] = timeline

    logger.info(
        "ASB CVEs raw: %d CVEs, %d CWEs, %d timeline events",
        len(cves), len(cwes), len(timeline),
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 5. asb_references_raw.json  →  cve_reference
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_asb_references(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "asb_references_raw.json")
    if not records:
        return {}

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
    return {"cve_reference": refs} if refs else {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 6. asb_exploited_cves.json  →  cve (exploited flag), cve_timeline_event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_asb_exploited(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "asb_exploited_cves.json")
    if not records:
        return {}

    cves: list[dict] = []
    timeline: list[dict] = []

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

        # ── cve_timeline_event: exploitation reported ─────────────
        note = r.get("exploitation_note") or r.get("exploitation_type", "")
        bulletin_id = r.get("bulletin_id", "")
        timeline.append({
            "cve_id":           cve_id,
            "event_type":       "exploitation_reported",
            "event_date":       None,   # no exact date in this file
            "notes":            f"{note} (bulletin: {bulletin_id})" if note else None,
            "source_reference": bulletin_id or r.get("source"),
        })

    result: dict[str, list[dict]] = {}
    if cves:
        result["cve"] = cves
    if timeline:
        result["cve_timeline_event"] = timeline

    logger.info("ASB exploited: %d CVEs flagged, %d timeline events", len(cves), len(timeline))
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 7. qualcomm_cves.json  →  cve, chipset, cve_affected_chipset, cwe, cve_cwe
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_qualcomm(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "qualcomm_cves.json")
    if not records:
        return {}

    VENDOR = "Qualcomm"
    cves: list[dict] = []
    chipsets: dict[str, dict] = {}
    cve_affected: list[dict] = []
    cwes: dict[int, dict] = {}
    cve_cwes: list[dict] = []

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        # ── cve enrichment (description from Qualcomm) ────────────
        desc = r.get("description")
        severity_label, cvss_score = parse_severity_string(r.get("severity"))
        if desc or severity_label:
            cves.append({
                "cve_id":           cve_id,
                "description":      desc,
                "cvss_v2_score":    None,
                "cvss_v3_score":    cvss_score,
                "cvss_v4_score":    None,
                "severity":         severity_label,
                "publish_date":     None,
                "discovery_date":   None,
                "origin_type":      None,
                "exploited_in_wild": None,
            })

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
    if cves:
        result["cve"] = cves
    if chipsets:
        result["chipset"] = list(chipsets.values())
    if cve_affected:
        result["cve_affected_chipset"] = cve_affected
    if cwes:
        result["cwe"] = list(cwes.values())
    if cve_cwes:
        result["cve_cwe"] = cve_cwes

    logger.info(
        "Qualcomm: %d CVEs, %d chipsets, %d cve_affected, %d CWEs",
        len(cves), len(chipsets), len(cve_affected), len(cwes),
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 8. mediatek_cves.json  →  cve, chipset, cve_affected_chipset, cwe,
#                            cve_cwe, security_bulletin, vendor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_mediatek(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "mediatek_cves.json")
    if not records:
        return {}

    VENDOR = "MediaTek"
    cves: list[dict] = []
    chipsets: dict[str, dict] = {}
    cve_affected: list[dict] = []
    cwes: dict[int, dict] = {}
    cve_cwes: list[dict] = []
    bulletins: dict[str, dict] = {}

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        # ── cve enrichment (description from MediaTek) ────────────
        desc = r.get("description")
        severity_label, cvss_score = parse_severity_string(r.get("severity"))
        if desc or severity_label:
            cves.append({
                "cve_id":           cve_id,
                "description":      desc,
                "cvss_v2_score":    None,
                "cvss_v3_score":    cvss_score,
                "cvss_v4_score":    None,
                "severity":         severity_label,
                "publish_date":     None,
                "discovery_date":   None,
                "origin_type":      None,
                "exploited_in_wild": None,
            })

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
    if cves:
        result["cve"] = cves
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
    result["vendor"] = [{
        "name": VENDOR,
        "country": None,
        "security_bulletin_url": "https://corp.mediatek.com/product-security-bulletin",
    }]

    logger.info(
        "MediaTek: %d CVEs, %d chipsets, %d cve_affected, %d CWEs, %d bulletins",
        len(cves), len(chipsets), len(cve_affected), len(cwes), len(bulletins),
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 9. samsung_security_cves.json  →  cve, cve_reference, vendor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_samsung(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "samsung_security_cves.json")
    if not records:
        return {}

    VENDOR = "Samsung"
    cves: list[dict] = []
    refs: list[dict] = []

    for r in records:
        cve_id = validate_cve_id(r.get("cve_id"))
        if not cve_id:
            continue

        severity_label, cvss_score = parse_severity_string(r.get("severity"))

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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 10. bulletins.json  →  vendor, security_bulletin
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_bulletins(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "bulletins.json")
    if not isinstance(records, list):
        records = []
    if not records:
        return {}

    vendors_seen: dict[str, dict] = {}
    bulletins: list[dict] = []

    for r in records:
        vendor_raw = r.get("vendor", "")
        vendor_name = _canonical_vendor(vendor_raw)

        if vendor_name not in vendors_seen:
            vendors_seen[vendor_name] = {
                "name":                     vendor_name,
                "country":                  None,
                "security_bulletin_url":    None,
            }

        bid = r.get("bulletin_id", "")
        bulletins.append({
            "vendor_name":      vendor_name,
            "title":            bid,
            "published_date":   normalize_date(r.get("published_date")),
            "severity_level":   None,
            "bulletin_url":     r.get("bulletin_url"),
        })

    result: dict[str, list[dict]] = {}
    if vendors_seen:
        result["vendor"] = list(vendors_seen.values())
    if bulletins:
        result["security_bulletin"] = bulletins

    logger.info("Bulletins: %d vendors, %d bulletins", len(vendors_seen), len(bulletins))
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 11. bulletin_cves.json  →  vendor_cve
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_bulletin_cves(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "bulletin_cves.json")
    if not isinstance(records, list):
        records = []
    if not records:
        return {}

    vendor_cves: list[dict] = []
    for r in records:
        cve_id = r.get("cve_id")
        if not cve_id:
            continue

        vendor_raw = r.get("vendor", "")
        vendor_name = _canonical_vendor(vendor_raw)
        bid = r.get("bulletin_id", "")

        vendor_cves.append({
            "vendor_name":      vendor_name,
            "cve_id":           cve_id,
            "bulletin_title":   bid,
            "published_date":   normalize_date(r.get("published_date")),
            "patched_date":     None,
        })

    logger.info("Bulletin CVEs: %d vendor_cve links", len(vendor_cves))
    return {"vendor_cve": vendor_cves} if vendor_cves else {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 12. aosp_patches.json  →  source_repository, cve_source_mapping,
#                            cve_timeline_event
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def parse_aosp_patches(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / "aosp_patches.json")
    if not records:
        return {}

    repos: dict[str, dict] = {}
    source_mappings: list[dict] = []
    timeline: list[dict] = []

    for r in records:
        cve_ids = r.get("cve_ids") or []
        if not cve_ids:
            continue

        repo_path = r.get("repo_path", "")
        commit_hash = r.get("commit_hash", "")

        # ── source_repository ─────────────────────────────────────
        if repo_path and repo_path not in repos:
            repos[repo_path] = {
                "name":         repo_path,
                "repo_type":    "git",
                "url":          f"https://android.googlesource.com/{repo_path}" if repo_path else None,
                "branch":       None,
            }

        # ── cve_source_mapping + cve_timeline_event ───────────────
        commit_date = normalize_date(r.get("commit_time"))

        for cve_raw in cve_ids:
            cve_id = validate_cve_id(cve_raw)
            if not cve_id:
                continue

            source_mappings.append({
                "cve_id":                   cve_id,
                "repo_name":                repo_path,
                "vulnerable_commit_hash":   None,
                "patch_commit_hash":        commit_hash,
                "vulnerable_file_path":     None,
                "vulnerable_function":      None,
                "vulnerable_variable":      None,
                "diff_patch":               None,
            })

            # Timeline event: patch committed
            if commit_date:
                msg = r.get("commit_message", "")
                # Truncate commit message for notes
                short_msg = (msg[:200] + "...") if len(msg) > 200 else msg
                timeline.append({
                    "cve_id":           cve_id,
                    "event_type":       "patch_committed",
                    "event_date":       commit_date,
                    "notes":            f"Repo: {repo_path}; {short_msg}".strip(),
                    "source_reference": r.get("url"),
                })

    result: dict[str, list[dict]] = {}
    if repos:
        result["source_repository"] = list(repos.values())
    if source_mappings:
        result["cve_source_mapping"] = source_mappings
    if timeline:
        result["cve_timeline_event"] = timeline

    logger.info(
        "AOSP: %d repos, %d cve_source_mapping, %d timeline events",
        len(repos), len(source_mappings), len(timeline),
    )
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Master dispatcher — called by parsers/__init__.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Order matters for CVE merge priority: NVD first, then enrichment sources.
ALL_PARSE_FUNCTIONS = [
    ("NVD",                 parse_nvd),
    ("CWE full-list",       parse_cwe_fulllist),
    ("ASB bulletins",       parse_asb_bulletins),
    ("ASB CVEs raw",        parse_asb_cves_raw),
    ("ASB references",      parse_asb_references),
    ("ASB exploited",       parse_asb_exploited),
    ("Qualcomm",            parse_qualcomm),
    ("MediaTek",            parse_mediatek),
    ("Samsung",             parse_samsung),
    ("Bulletins",           parse_bulletins),
    ("Bulletin CVEs",       parse_bulletin_cves),
    ("AOSP patches",        parse_aosp_patches),
]


def parse_all_files(data_dir: Path) -> dict[str, list[dict]]:
    """
    Run every parse function, merge results by table name.
    Returns a dict keyed by table name with lists of records.
    """
    merged: dict[str, list[dict]] = defaultdict(list)

    for name, parse_fn in ALL_PARSE_FUNCTIONS:
        logger.info("Running parser: %s", name)
        try:
            result = parse_fn(data_dir)
        except Exception:
            logger.exception("Parser %s failed", name)
            continue

        for table_name, records in result.items():
            merged[table_name].extend(records)

    return dict(merged)
