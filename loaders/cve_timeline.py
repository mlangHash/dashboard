import logging

logger = logging.getLogger(__name__)

def parse_cve_timeline_event_record(rec: dict) -> dict:
    return {
        "cve_id": rec.get("cve_id"),
        "event_type": rec.get("event_type"),
        "event_date": rec.get("event_date"),
        "notes": rec.get("notes"),
        "source_reference": rec.get("source_reference"),
    }


def upsert_cve_timeline_event(conn, rec: dict) -> None:
    parsed = parse_cve_timeline_event_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_timeline_event (cve_id, event_type, event_date, notes, source_reference)
            VALUES (%(cve_id)s, %(event_type)s, %(event_date)s, %(notes)s, %(source_reference)s)
            ON CONFLICT (cve_id, event_type, event_date) DO UPDATE SET
                notes = EXCLUDED.notes,
                source_reference = EXCLUDED.source_reference
            """,
            parsed,
        )
    logger.info("Upserted cve_timeline_event for %s (%s)", parsed["cve_id"], parsed["event_type"])


def load_all_cve_timeline_events(conn, records: list) -> None:
    for rec in records:
        upsert_cve_timeline_event(conn, rec)