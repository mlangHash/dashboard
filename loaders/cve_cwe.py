import logging

logger = logging.getLogger(__name__)


def parse_cve_cwe_record(rec: dict) -> dict:
    """Extract cve_cwe junction fields from a raw record."""
    return {
        "cve_id": rec.get("cve_id", None),
        "cwe_id": rec.get("cwe_id", None),
    }


def upsert_cve_cwe(conn, rec: dict) -> None:
    """
    Insert a single (cve_id, cwe_id) link. Idempotent -- cve_cwe's
    """
    parsed = parse_cve_cwe_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_cwe (cve_id, cwe_id)
            VALUES (%(cve_id)s, %(cwe_id)s)
            ON CONFLICT (cve_id, cwe_id) DO NOTHING
            """,
            parsed,
        )
    logger.info("Upserted cve_cwe %s / %s", parsed["cve_id"], parsed["cwe_id"])


def load_all_cve_cwe(conn, records: list) -> None:
    """Loop over all parsed cve_cwe records and upsert each."""
    for rec in records:
        upsert_cve_cwe(conn, rec)