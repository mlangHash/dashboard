"""
Parser for multi-vendor bulletin data.

Source files:
  - bulletins.json      → vendor, security_bulletin
  - bulletin_cves.json  → vendor_cve
"""
import logging
from pathlib import Path

from parsers.base import load_records, normalize_date

logger = logging.getLogger(__name__)

FILES = ["bulletins.json", "bulletin_cves.json"]

# Map raw vendor names to canonical names
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


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    # ── bulletins.json ────────────────────────────────────────────
    bulletin_records = load_records(data_dir / "bulletins.json")
    if not isinstance(bulletin_records, list):
        bulletin_records = []

    vendors_seen: dict[str, dict] = {}
    bulletins: list[dict] = []
    # Build a lookup: bulletin_id → bulletin metadata for vendor_cve enrichment
    bulletin_lookup: dict[str, dict] = {}

    for r in bulletin_records:
        vendor_raw = r.get("vendor", "")
        vendor_name = _canonical_vendor(vendor_raw)

        if vendor_name not in vendors_seen:
            vendors_seen[vendor_name] = {
                "name":                     vendor_name,
                "country":                  None,
                "security_bulletin_url":    None,
            }

        bid = r.get("bulletin_id", "")
        pub_date = normalize_date(r.get("published_date"))
        bulletin_url = r.get("bulletin_url")
        title = bid  # bulletin_id serves as the title

        bulletins.append({
            "vendor_name":      vendor_name,
            "title":            title,
            "published_date":   pub_date,
            "severity_level":   None,
            "bulletin_url":     bulletin_url,
        })

        bulletin_lookup[bid] = {
            "vendor_name":      vendor_name,
            "title":            title,
            "published_date":   pub_date,
        }

    # ── bulletin_cves.json ────────────────────────────────────────
    cve_link_records = load_records(data_dir / "bulletin_cves.json")
    if not isinstance(cve_link_records, list):
        cve_link_records = []

    vendor_cves: list[dict] = []
    for r in cve_link_records:
        cve_id = r.get("cve_id")
        if not cve_id:
            continue

        bid = r.get("bulletin_id", "")
        vendor_raw = r.get("vendor", "")
        vendor_name = _canonical_vendor(vendor_raw)

        # Try to resolve bulletin metadata from the lookup
        meta = bulletin_lookup.get(bid, {})

        vendor_cves.append({
            "vendor_name":      meta.get("vendor_name", vendor_name),
            "cve_id":           cve_id,
            "bulletin_title":   meta.get("title", bid),
            "published_date":   meta.get("published_date") or normalize_date(r.get("published_date")),
            "patched_date":     None,
        })

    result: dict[str, list[dict]] = {}
    if vendors_seen:
        result["vendor"] = list(vendors_seen.values())
    if bulletins:
        result["security_bulletin"] = bulletins
    if vendor_cves:
        result["vendor_cve"] = vendor_cves

    logger.info(
        "Vendor bulletins: %d vendors, %d bulletins, %d vendor_cve links",
        len(vendors_seen), len(bulletins), len(vendor_cves),
    )
    return result
