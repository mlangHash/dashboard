import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from dateutil import parser as date_parser
from loadFiles import load_records

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
CWE_PATTERN = re.compile(r"CWE-(\d+)\s*(.*)")


def normalize_date(raw_date: Any) -> Optional[str]:
    """Standardizes date strings to ISO-8601 (YYYY-MM-DD), matching Postgres DATE columns."""
    if not raw_date:
        return None

    date_str = str(raw_date).strip()

    try:
        return date_parser.parse(date_str).date().isoformat()
    except (ValueError, OverflowError):
        pass

    match = re.search(r"(\d{4})[-/](\d{2})(?:[-/](\d{2}))?", date_str)
    if match:
        year, month = match.group(1), match.group(2)
        day = match.group(3) or "01"
        return f"{year}-{month}-{day}"

    logger.warning("Could not parse date: %r", raw_date)
    return None


def extract_cwe(raw: Optional[str]) -> tuple[Optional[int], Optional[str]]:
    """'CWE-703 Improper Check...' -> (703, 'Improper Check...'). Matches cwe.cwe_id (INTEGER)."""
    if not raw:
        return None, None
    match = CWE_PATTERN.match(str(raw).strip())
    if not match:
        return None, None
    return int(match.group(1)), (match.group(2).strip() or None)


def route_cvss_score(score: Any, version: Any) -> dict:
    """
    Routes a raw CVSS score into the correct versioned column
    (cve.cvss_v2_score / cvss_v3_score / cvss_v4_score) based on the
    version field. The schema has no generic "cvss score" column --
    it's always version-specific, unlike this data's raw shape.
    """
    result = {"cvss_v2_score": None, "cvss_v3_score": None, "cvss_v4_score": None}
    if score is None or version is None:
        return result

    version_str = str(version).strip()
    if version_str.startswith("2"):
        result["cvss_v2_score"] = score
    elif version_str.startswith("3"):
        result["cvss_v3_score"] = score
    elif version_str.startswith("4"):
        result["cvss_v4_score"] = score
    return result


def normalize_record(raw_record: dict[str, Any], source_file: str) -> Optional[dict[str, Any]]:
    """
    Normalizes one raw record into a dict whose keys match either an
    actual VulCrawlerDB column name (for cve-table scalars) or the
    exact input key a loader's parse_*/upsert_* function expects (for
    nested per-table lists). Fields with no matching column anywhere
    stay under "unmapped" -- visible, not invented as fake columns.
    """
    # --- cve_id: validation ---
    cve_raw = raw_record.get("cve_id") or raw_record.get("cve") or raw_record.get("CVE")
    if not cve_raw or not CVE_REGEX.match(str(cve_raw).strip()):
        logger.warning("Skipping malformed or missing CVE ID: %s in file: %s", cve_raw, source_file)
        return None
    cve_id = str(cve_raw).strip().upper()

    # --- cve.exploited_in_wild ---
    status_raw = (raw_record.get("exploitation_status") or raw_record.get("status") or "").strip().lower()
    if status_raw not in ("active", "limited", "targeted"):
        status_raw = "active" if "active" in source_file.lower() else "unknown"
    exploited_in_wild = True if status_raw in ("active", "limited", "targeted") else None

    desc = raw_record.get("description") or raw_record.get("summary") or ""
    clean_description = re.sub(r"\s+", " ", desc).strip() or None

    cvss_scores = route_cvss_score(
        raw_record.get("cvss_score") or raw_record.get("cvss_base"),
        raw_record.get("cvss_version"),
    )

    # --- cwe.cwe_id / cwe.name (cwe_loader.parse_cwe_record key names) ---
    cwe_id, cwe_name = extract_cwe(raw_record.get("cwe_id") or raw_record.get("cwe"))
    if cwe_id is None:
        cwe_id, cwe_name = extract_cwe(raw_record.get("vulnerability_type"))

    # --- cve_reference (reference_loader.insert_reference key names: cve_id, url, source, tags, is_patch) ---
    ref_urls = raw_record.get("references") or raw_record.get("urls") or []
    if isinstance(ref_urls, str):
        ref_urls = [ref_urls]
    cve_reference = [
        {"cve_id": cve_id, "url": url, "source": None, "tags": None, "is_patch": None}
        for url in ref_urls
    ]

    # --- cve_source_mapping (cve_source_mapping_loader.parse_cve_source_mapping_record key names) ---
    commits = raw_record.get("commits") or raw_record.get("patch_ids") or []
    repos = raw_record.get("repositories") or []
    if isinstance(commits, str):
        commits = [commits]
    if isinstance(repos, str):
        repos = [repos]
    cve_source_mapping = []
    for i, commit_hash in enumerate(commits):
        repo_name = repos[i] if i < len(repos) else (repos[0] if len(repos) == 1 else None)
        cve_source_mapping.append({
            "cve_id": cve_id,
            "repo_name": repo_name,
            "vulnerable_commit_hash": None,
            "patch_commit_hash": commit_hash,
            "vulnerable_file_path": None,
            "vulnerable_function": None,
            "vulnerable_variable": None,
            "diff_patch": None,
        })

    # --- vendor_cve (vendor_cve_loader.parse_vendor_cve_record key names) ---
    bulletin_id = raw_record.get("bulletin_id") or raw_record.get("bulletin") or raw_record.get("asb_id")
    vendor_name = raw_record.get("vendor") or raw_record.get("manufacturer")
    vendor_cve = []
    if bulletin_id or vendor_name:
        vendor_cve.append({
            "cve_id": cve_id,
            "vendor_name": vendor_name,
            "bulletin_id": str(bulletin_id).strip() if bulletin_id else None,
            "patched_date": None,
        })

    # --- cve_affected_chipset (cve_affected_chipset_loader key names: cve_id, chipset_name, is_patched) ---
    chipset_names = raw_record.get("soc_models") or raw_record.get("chips") or []
    if isinstance(chipset_names, str):
        chipset_names = [chipset_names]
    cve_affected_chipset = [
        {"cve_id": cve_id, "chipset_name": name, "is_patched": None}
        for name in chipset_names
    ]

    return {
        # --- cve (matches cve table column names exactly) ---
        "cve_id": cve_id,
        "description": clean_description,
        "cvss_v2_score": cvss_scores["cvss_v2_score"],
        "cvss_v3_score": cvss_scores["cvss_v3_score"],
        "cvss_v4_score": cvss_scores["cvss_v4_score"],
        "severity": str(raw_record.get("severity") or raw_record.get("risk") or "").strip().upper() or None,
        "publish_date": normalize_date(raw_record.get("publish_date") or raw_record.get("date")),
        "discovery_date": None,
        "exploited_in_wild": exploited_in_wild,
        "public_exploit_available": None,
        "origin_type": None,
        "layer_id": None,
        "sublayer_id": None,

        # --- cwe (cwe_loader key names) ---
        "cwe_id": cwe_id,
        "name": cwe_name,

        # --- nested per-table lists, each dict already loader-input-shaped ---
        "cve_reference": cve_reference,
        "cve_source_mapping": cve_source_mapping,
        "vendor_cve": vendor_cve,
        "cve_affected_chipset": cve_affected_chipset,

        # --- fields with NO matching column anywhere in the current schema ---
        "unmapped": {
            "last_updated_date": raw_record.get("updated_date") or raw_record.get("last_modified"),
            "vulnerability_type": raw_record.get("type") or raw_record.get("vulnerability_type"),
            "kev_date": raw_record.get("kev_date") or raw_record.get("added_to_kev"),
            "threat_actors": raw_record.get("threat_actors") or raw_record.get("actors"),
            "malware_families": raw_record.get("malware") or raw_record.get("campaigns"),
            "affected_aosp_versions": raw_record.get("updated_aosp_versions") or raw_record.get("versions"),
            "patched_aosp_versions": raw_record.get("patched_versions"),
            "attack_vector": raw_record.get("attack_vector") or raw_record.get("av"),
            "attack_complexity": raw_record.get("attack_complexity") or raw_record.get("ac"),
            "privileges_required": raw_record.get("privileges_required") or raw_record.get("pr"),
            "user_interaction": raw_record.get("user_interaction") or raw_record.get("ui"),
            "affected_device_models": raw_record.get("devices") or raw_record.get("models"),
            "oem_bulletin_mappings": raw_record.get("oem_bulletins") or raw_record.get("oem_id"),
            "mitigation_text": raw_record.get("mitigation") or raw_record.get("workaround"),
            "remediation_deadline": normalize_date(raw_record.get("deadline") or raw_record.get("remediation_date")),
            "discovered_by_researcher": raw_record.get("discovered_by") or raw_record.get("credits"),
            "regulatory_compliance_tags": raw_record.get("compliance") or raw_record.get("regulatory_tags"),
            "google_bug_id": raw_record.get("bug_id") or raw_record.get("google_bug"),
        },

        "source_lineage": [source_file],
        "ingestion_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def prepare_master_dataset(data_dir: str | Path) -> list[dict[str, Any]]:
    """Compiles, normalizes, and merges records from every *.json file in data_dir into one record per unique CVE."""
    data_dir = Path(data_dir)
    master_map: dict[str, dict[str, Any]] = {}

    for filepath in sorted(data_dir.glob("*.json")):
        try:
            raw_records = load_records(filepath)
        except Exception as e:
            logger.error("Critical failure loading source file %s: %s", filepath.name, e)
            continue

        for raw_record in raw_records:
            normalized = normalize_record(raw_record, source_file=filepath.name)
            if not normalized:
                continue

            cve_id = normalized["cve_id"]
            if cve_id not in master_map:
                master_map[cve_id] = normalized
                continue

            existing = master_map[cve_id]

            existing["cve_reference"].extend(
                r for r in normalized["cve_reference"]
                if r["url"] not in {ex["url"] for ex in existing["cve_reference"]}
            )
            existing["cve_source_mapping"].extend(
                m for m in normalized["cve_source_mapping"]
                if m["patch_commit_hash"] not in {ex["patch_commit_hash"] for ex in existing["cve_source_mapping"]}
            )
            existing["vendor_cve"].extend(
                v for v in normalized["vendor_cve"]
                if (v["vendor_name"], v["bulletin_id"])
                not in {(ex["vendor_name"], ex["bulletin_id"]) for ex in existing["vendor_cve"]}
            )
            existing["cve_affected_chipset"].extend(
                c for c in normalized["cve_affected_chipset"]
                if c["chipset_name"] not in {ex["chipset_name"] for ex in existing["cve_affected_chipset"]}
            )
            existing["source_lineage"] = sorted(set(existing["source_lineage"]) | set(normalized["source_lineage"]))

            if existing["cwe_id"] is None and normalized["cwe_id"] is not None:
                existing["cwe_id"], existing["name"] = normalized["cwe_id"], normalized["name"]
            elif existing["name"] is None and normalized["name"] is not None:
                existing["name"] = normalized["name"]

            for field in ("publish_date", "description", "severity",
                          "cvss_v2_score", "cvss_v3_score", "cvss_v4_score"):
                if not existing[field] and normalized[field]:
                    existing[field] = normalized[field]

            if existing["exploited_in_wild"] is None and normalized["exploited_in_wild"] is not None:
                existing["exploited_in_wild"] = normalized["exploited_in_wild"]

            if normalized["description"] and existing["description"]:
                if len(normalized["description"]) > len(existing["description"]):
                    existing["description"] = normalized["description"]

    return list(master_map.values())