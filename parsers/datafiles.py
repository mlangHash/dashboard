import logging
import re
from datetime import datetime
from dateutil import parser, tz
from pathlib import Path
from typing import Any, Optional
from loadFiles import load_records

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def normalize_date(raw_date: Any) -> Optional[str]:
    """Standardizes all variation of date strings into ISO-8601 format (YYYY-MM-DD)."""

    if not raw_date:
        return None
    date_str = str(raw_date).strip()
    print(parser.parse(date_str).date().strftime("%d-%m-%Y"))
    return parser.parse(date_str).date().strftime("%d-%m-%Y")

    # Rollback for messy dates through regex 

    # Checking for 4 digits, 2 digits and then optionally for trainling 2-digits day.     
    match = re.search(r"(\d{4})[-/](\d{2})(?:[-/](\d{2}))?", date_str)

    if match:
        year = match.group(1)
        month = match.group(2)

        # Use the extracted day if it exists, otherwise fall back to "01"
        day = match.group(3) if match.group(3) else "01"
        
        return f"{day}-{month}-{year}"
    return None



def extract_component_group(description: str, technical_component: str) -> str:
    """Categorizes raw components into standard high-level platform groups."""

    combined = f"{description} {technical_component}".lower()

    if any(k in combined for k in ["qualcomm", "qcom"]):
        return "QUALCOMM"
    if any(k in combined for k in ["mediatek", "mtk"]):
        return "MEDIATEK"
    if "kernel" in combined:
        return "LINUX_KERNEL"
    if any(k in combined for k in ["framework", "libgui", "binder"]):
        return "ANDROID_FRAMEWORK"
    if "system" in combined:
        return "ANDROID_SYSTEM"
    return "OTHER_COMPONENTS"


def normalize_record(raw_record: dict[str, Any], source_file: str) -> Optional[dict[str, Any]]:
    

    # 1. Base Validation
    cve_raw = raw_record.get("cve_id") or raw_record.get("cve") or raw_record.get("CVE")
    if not cve_raw or not CVE_REGEX.match(str(cve_raw).strip()):
        logger.warning("Skipping malformed or missing CVE ID: %s in file: %s", cve_raw, source_file)
        return None
    cve_id = str(cve_raw).strip().upper()

    # 2. Extract and Normalize values with flexible aliases
    bulletin = raw_record.get("bulletin_id") or raw_record.get("bulletin") or raw_record.get("asb_id")
    status_raw = raw_record.get("exploitation_status") or raw_record.get("status") or ""
    status = status_raw.strip().lower()
    if status not in ["active", "limited", "targeted"]:
        status = "active" if "active" in source_file.lower() else "unknown"

    desc = raw_record.get("description") or raw_record.get("summary") or ""
    clean_description = re.sub(r"\s+", " ", desc).strip()
    comp = raw_record.get("component") or raw_record.get("subsystem") or ""

    # 3. Master Mapping Matrix (Guarantees every field exists for all tables)
    return {
        # --- TABLE 1-3: CORE VULNERABILITY & BULLETIN MAPS ---
        "cve_id": cve_id,
        "bulletin_ids": [str(bulletin).strip()] if bulletin else [],
        "publish_date": normalize_date(raw_record.get("publish_date") or raw_record.get("date")),
        "last_updated_date": normalize_date(raw_record.get("updated_date") or raw_record.get("last_modified")),
        "description": clean_description or None,

        # --- TABLE 4: EXPLOITATION & THREAT INTEL ---
        "exploitation_status": status,
        "is_actively_exploited": True if status in ["active", "limited", "targeted"] else False,
        "date_added_to_kev": normalize_date(raw_record.get("kev_date") or raw_record.get("added_to_kev")),
        "associated_threat_actors": raw_record.get("threat_actors") or raw_record.get("actors"),
        "associated_malware_families": raw_record.get("malware") or raw_record.get("campaigns"),

        # --- TABLE 5-7: SEVERITIES, TYPES & VENDORS ---
        "severity_rating": str(raw_record.get("severity") or raw_record.get("risk") or "UNKNOWN").strip().upper(),
        "vulnerability_type": str(raw_record.get("type") or raw_record.get("vulnerability_type") or "UNKNOWN").strip().upper(),
        "component_raw": str(comp).strip() if comp else None,
        "component_group": extract_component_group(clean_description, str(comp)),
        "vendor_name": raw_record.get("vendor") or raw_record.get("manufacturer"),

        # --- TABLE 8-10: VERSIONS & PATCHES ---
        "affected_aosp_versions": raw_record.get("updated_aosp_versions") or raw_record.get("versions") or [],
        "patched_aosp_versions": raw_record.get("patched_versions") or [],
        "git_commit_shas": raw_record.get("commits") or raw_record.get("patch_ids") or [],
        "git_repository_urls": raw_record.get("repositories") or [],

        # --- TABLE 11-12: REFERENCES & TRACKERS ---
        "reference_urls": raw_record.get("references") or raw_record.get("urls") or [],
        "google_bug_id": str(raw_record.get("bug_id") or raw_record.get("google_bug") or ""),

        # --- TABLE 13-15: CVSS BASIC & METRIC BREAKDOWNS ---
        "cvss_base_score": raw_record.get("cvss_score") or raw_record.get("cvss_base"),
        "cvss_version": raw_record.get("cvss_version"),
        "cvss_vector_string": raw_record.get("cvss_vector") or raw_record.get("vector"),
        "attack_vector": raw_record.get("attack_vector") or raw_record.get("av"),
        "attack_complexity": raw_record.get("attack_complexity") or raw_record.get("ac"),
        "privileges_required": raw_record.get("privileges_required") or raw_record.get("pr"),
        "user_interaction": raw_record.get("user_interaction") or raw_record.get("ui"),
        "scope_change": raw_record.get("scope") or raw_record.get("s"),
        "confidentiality_impact": raw_record.get("confidentiality") or raw_record.get("c"),
        "integrity_impact": raw_record.get("integrity") or raw_record.get("i"),
        "availability_impact": raw_record.get("availability") or raw_record.get("a"),

        # --- TABLE 16-18: CWE CLASSIFICATIONS & SOC IMPACT ---
        "cwe_id": str(raw_record.get("cwe_id") or raw_record.get("cwe") or ""),
        "cwe_name": raw_record.get("cwe_name"),
        "affected_soc_models": raw_record.get("soc_models") or raw_record.get("chips") or [],
        "affected_device_models": raw_record.get("devices") or raw_record.get("models") or [],

        # --- TABLE 19-21: OEM BULLETINS & REMEDIATION ---
        "oem_bulletin_mappings": raw_record.get("oem_bulletins") or raw_record.get("oem_id") or [],
        "mitigation_text": raw_record.get("mitigation") or raw_record.get("workaround"),
        "remediation_deadline": normalize_date(raw_record.get("deadline") or raw_record.get("remediation_date")),

        # --- TABLE 22-24: INGESTION METADATA & COMPLIANCE ---
        "discovered_by_researcher": raw_record.get("discovered_by") or raw_record.get("credits"),
        "regulatory_compliance_tags": raw_record.get("compliance") or raw_record.get("regulatory_tags") or [],
        "source_lineage": [source_file],
        "ingestion_timestamp": datetime.now(tz.tzutc()).isoformat().replace("+00:00", "Z")
    }


def prepare_master_dataset(data_dir: str | Path) -> list[dict[str, Any]]:
    """Compiles, normalizes, and merges records from all source files into the unified dataset."""
    data_dir = Path(data_dir)
    master_map: dict[str, dict[str, Any]] = {}

    source_files = sorted(list(data_dir.glob("*.json")))
    
    for filepath in source_files:
        try:
            raw_records = load_records(filepath)
            for raw_record in raw_records:
                normalized = normalize_record(raw_record, source_file=filepath.name)
                if not normalized:
                    continue
                
                cve_id = normalized["cve_id"]

                # --- LOSSLESS DEDUPLICATION & MERGING ---
                if cve_id in master_map:
                    existing = master_map[cve_id]
                    
                    # Merge unique values into structural list fields
                    list_fields = [
                        "bulletin_ids", "associated_threat_actors", "associated_malware_families",
                        "affected_aosp_versions", "patched_aosp_versions", "git_commit_shas",
                        "git_repository_urls", "reference_urls", "affected_soc_models",
                        "affected_device_models", "oem_bulletin_mappings", "regulatory_compliance_tags",
                        "source_lineage"
                    ]
                    for field in list_fields:
                        if normalized[field]:
                            # Ensure clean type handling if raw entry was an isolated string
                            norm_val = normalized[field] if isinstance(normalized[field], list) else [normalized[field]]
                            exis_val = existing[field] if isinstance(existing[field], list) else [existing[field]]
                            existing[field] = sorted(list(set(exis_val + norm_val)))

                    # Update scalar fields only if existing is empty/unknown and incoming contains valid data
                    scalar_priority_fields = [
                        "publish_date", "last_updated_date", "description", "severity_rating", 
                        "vulnerability_type", "component_raw", "vendor_name", "google_bug_id", 
                        "cvss_base_score", "cvss_version", "cvss_vector_string", "attack_vector", 
                        "attack_complexity", "privileges_required", "user_interaction", "scope_change", 
                        "confidentiality_impact", "integrity_impact", "availability_impact", "cwe_id", 
                        "cwe_name", "mitigation_text", "remediation_deadline", "discovered_by_researcher"
                    ]
                    for field in scalar_priority_fields:
                        if (not existing[field] or existing[field] == "UNKNOWN") and normalized[field]:
                            existing[field] = normalized[field]

                    # Prioritize active exploitation statuses over static/unknown states
                    if existing["exploitation_status"] == "unknown" and normalized["exploitation_status"] != "unknown":
                        existing["exploitation_status"] = normalized["exploitation_status"]
                        existing["is_actively_exploited"] = normalized["is_actively_exploited"]

                    # Keep the richer text description if they conflict
                    if normalized["description"] and existing["description"]:
                        if len(str(normalized["description"])) > len(str(existing["description"])):
                            existing["description"] = normalized["description"]
                else:
                    master_map[cve_id] = normalized

        except Exception as e:
            logger.error("Critical failure parsing source file %s: %s", filepath.name, e)

    return list(master_map.values())