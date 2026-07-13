import logging

logger = logging.getLogger(__name__)


def parse_cve_reference_record(rec: dict) -> dict:
    """
    Extract cve_reference table fields from a standardised record.

    """
    return {
        "cve_id":   rec.get("cve_id"),
        "url":      rec.get("url", None),
        "source":   rec.get("source", None),
        "tags":     rec.get("tags", None),
        "is_patch": rec.get("is_patch", None),
    }


def upsert_reference(conn, rec: dict) -> None:
    """
    Insert or update one cve_reference row.
    Uses ON CONFLICT on (cve_id, uri) — requires the unique constraint:
        ALTER TABLE cve_reference ADD CONSTRAINT uq_cve_reference UNIQUE (cve_id, uri);
    """
    parsed = parse_cve_reference_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_reference (cve_id, uri, source, tags, is_patch)
            VALUES (%(cve_id)s, %(url)s, %(source)s, %(tags)s, %(is_patch)s)
            ON CONFLICT (cve_id, uri) DO UPDATE SET
                source  = COALESCE(EXCLUDED.source,  cve_reference.source),
                tags    = COALESCE(EXCLUDED.tags,    cve_reference.tags),
                is_patch = COALESCE(EXCLUDED.is_patch, cve_reference.is_patch)
            """,
            parsed,
        )
    logger.info("Upserted reference for %s (%s)", parsed["cve_id"], parsed["url"])


def load_all_references(conn, records: list) -> None:
    """Load cve_reference rows from standardised records."""
    for rec in records:
        upsert_reference(conn, rec)
    logger.info("Loaded %d references", len(records))