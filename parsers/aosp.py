"""
Parser for AOSP (Android Open Source Project) patch data.

Source file: aosp_patches.json
Output tables: source_repository, cve_source_mapping
"""
import logging
from pathlib import Path

from parsers.base import load_records, validate_cve_id

logger = logging.getLogger(__name__)

FILES = ["aosp_patches.json"]


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    records = load_records(data_dir / FILES[0])
    if not records:
        return {}

    repos: dict[str, dict] = {}         # repo_path → record (dedup)
    source_mappings: list[dict] = []

    for r in records:
        cve_ids = r.get("cve_ids") or []
        if not cve_ids:
            continue

        repo_path = r.get("repo_path", "")
        commit_hash = r.get("commit_hash", "")
        url = r.get("url", "")

        # ── source_repository ─────────────────────────────────────
        if repo_path and repo_path not in repos:
            repos[repo_path] = {
                "name":         repo_path,
                "repo_type":    "git",
                "url":          f"https://android.googlesource.com/{repo_path}" if repo_path else None,
                "branch":       None,
            }

        # ── cve_source_mapping (one row per CVE × commit) ─────────
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

    result: dict[str, list[dict]] = {}
    if repos:
        result["source_repository"] = list(repos.values())
    if source_mappings:
        result["cve_source_mapping"] = source_mappings

    logger.info(
        "AOSP: %d repositories, %d cve_source_mapping records",
        len(repos), len(source_mappings),
    )
    return result
