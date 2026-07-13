import logging

logger = logging.getLogger(__name__)

def parse_cwe_record(rec: dict) -> dict:
    """Extract cwe table fields from a raw record."""
    return {
        "cwe_id": rec.get("cwe_id"),
        "name": rec.get("name", None),
        "description": rec.get("description", "Not Available"),
    }


def upsert_cwe(conn, rec: dict) -> None:
    """Insert or update a single cwe row. Idempotent via ON CONFLICT (cwe_id)."""
    parsed = parse_cwe_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cwe (cwe_id, name, description)
            VALUES (%(cwe_id)s, %(name)s, %(description)s)
            ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description
            """,
            parsed,
        )
    logger.info("Upserted cwe %s", parsed["cwe_id"])


def load_all_cwes(conn, records: list) -> None:
    """Loop over all parsed CWE records and upsert each."""
    for rec in records:
        upsert_cwe(conn, rec)