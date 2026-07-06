import logging

logger = logging.getLogger(__name__)

def parse_cwe_record(rec: dict) -> dict:
    """Extract cwe table fields from a raw NVD record."""
    return {
        "id": rec["id"],
        "name": rec["name"],
        "description": rec.get("description"),
    }

def upsert_cwe(conn, rec:dict) -> None:
    """Insert the CWE record into the cwe table. Idempotent."""
    parsed_rec = parse_cwe_record(rec)
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO cwe (cwe_id, name, description)
            VALUES (%(id)s, %(name)s, %(description)s)
            ON CONFLICT (cwe_id) DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description
        """, parsed_rec
        )
    logger.info("Upserted cwe %s", parsed_rec["id"])

def load_all_cwes(conn, records: list) -> None:
    """Loop over all parsed CWE records and upsert each."""
    for rec in records:
        upsert_cwe(conn, rec)