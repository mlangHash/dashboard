import logging 
from loaders.vendor import get_or_create_vendor_id
from loaders.security_bulletin import get_bulletin_ids

logger = logging.getLogger(__name__)

def parse_vendor_cve_records(rec: dict) -> dict:
    return {
        "vendor_name": rec.get("vendor_name"),
        "cve_id": rec.get("cve_id"),
        "bulletin_title": rec.get("bulletin_title", None),
        "published_date": rec.get("published_date", None),
        "patched_date": rec.get("patched_date"),
    }

def upsert_vendor_cve(conn, rec: dict) -> None:
    """Inserting the records also checking for conflicts simulataneously. """
    parsed = parse_vendor_cve_records(rec)
    vendor_id = get_or_create_vendor_id(conn, parsed["vendor_name"])
    bulletin_id = get_bulletin_ids(conn, vendor_id, parsed["bulletin_title"], parsed["published_date"])

    with conn.cursor() as cur:
        cur.execute(
            """
                INSERT INTO vendor_cve (vendor_id, cve_id, bulletin_id, patched_date) 
                VALUES (%s, %s, %s, %s) ON CONFLICT(vendor_id, cve_id, bulletin_id)
                DO UPDATE SET
                    patched_date = EXCLUDED.patched_date
            """,
            (vendor_id, parsed["cve_id"], bulletin_id, parsed["patched_id"])
        )
        logger.info("Upserted vendor_cve %s / %s", parsed["vendor_name"], parsed["cve_id"])


def load_all_vendor_cves(conn, records: list) -> None:
    for rec in records:
        upsert_vendor_cve(conn, rec)