import logging
from loaders.vendor import get_or_create_vendor_id

logger = logging.getLogger(__name__)


def parse_security_bulletin_record(rec: dict) -> dict:
    return {
        "vendor_name": rec.get("vendor_name"),
        "title": rec.get("title"),
        "published_date": rec.get("published_date"),
        "severity_level": rec.get("severity_level"),
        "bulletin_url": rec.get("bulletin_url"),
    }


def upsert_security_bulletin(conn, rec: dict) -> int:
    parsed = parse_security_bulletin_record(rec)
    vendor_id = get_or_create_vendor_id(conn, parsed["vendor_name"])

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO security_bulletin (vendor_id, title, published_date, severity_level, bulletin_url)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (vendor_id, bulletin_url) DO UPDATE SET
                title = EXCLUDED.title,
                severity_level = EXCLUDED.severity_level
            RETURNING id
            """,
            (vendor_id, parsed["title"], parsed["published_date"],
             parsed["severity_level"], parsed["bulletin_url"]),
        )
        bulletin_id = cur.fetchone()[0]
    logger.info("Upserted security_bulletin %s", parsed["title"])
    return bulletin_id


def load_all_security_bulletins(conn, records: list) -> None:
    for rec in records:
        upsert_security_bulletin(conn, rec)