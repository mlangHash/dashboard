import logging
from loaders.source_repository import get_or_create_source_repository_id

logger = logging.getLogger(__name__)

MAPPING_COLUMNS = [
    "vulnerable_commit_hash", "patch_commit_hash", "vulnerable_file_path",
    "vulnerable_function", "vulnerable_variable", "diff_patch",
]

def parse_cve_source_mapping_record(rec: dict) -> dict:
    parsed = {col: rec.get(col) for col in MAPPING_COLUMNS}
    parsed["cve_id"] = rec.get("cve_id")
    parsed["repo_name"] = rec.get("repo_name")
    return parsed

def upsert_cve_source_mapping(conn, rec: dict) -> None:
    parsed = parse_cve_source_mapping_record(rec)
    repository_id = get_or_create_source_repository_id(conn, parsed["repo_name"])

    values = {c: parsed[c] for c in MAPPING_COLUMNS}
    values["cve_id"] = parsed["cve_id"]
    values["repository_id"] = repository_id

    cols = ", ".join(values.keys())
    placeholders = ", ".join(f"%({k})s" for k in values)
    update_clause = ", ".join(f"{k} = EXCLUDED.{k}" for k in values if k not in ("cve_id", "patch_commit_hash"))

    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO cve_source_mapping ({cols}) VALUES ({placeholders})
            ON CONFLICT (cve_id, patch_commit_hash) DO UPDATE SET {update_clause}
            """,
            values,
        )
    logger.info("Upserted cve_source_mapping for %s", parsed["cve_id"])

def load_all_cve_source_mappings(conn, records: list) -> None:
    for rec in records:
        upsert_cve_source_mapping(conn, rec)