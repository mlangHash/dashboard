# loaders/cve_loader.py
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def parse_cve_record(rec: dict) -> dict:
    """Extract cve table fields from a raw NVD record."""
    cvss = rec.get("cvss") or {}
    v3_0 = cvss.get("v3_0") or {}
    v3_1 = cvss.get("v3_1") or {}
    v2 = cvss.get("v2") or {}

    publish_date = rec["published"][:10]

    return {
        "id": rec["cve_id"],
        "description": rec["description"],
        "cvss_v2_score": v2.get("base_score"),
        "cvss_v3_score": v3_0.get("base_score"),   
        "cvss_v4_score": v3_1.get("base_score"),   
        "severity": v3_1.get("severity"),
        "publish_date": publish_date,
        "discovery_date": publish_date,            
        "origin_type": rec.get("source_identifier"),
    }


def upsert_cve(conn, rec: dict) -> None:
    """
    Insert or update a single CVE's core fields. Idempotent.
    """
    parsed = parse_cve_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve (
                id, description, cvss_v2_score, cvss_v3_score, cvss_v4_score,
                severity, publish_date, discovery_date, origin_type
            ) VALUES (
                %(id)s, %(description)s, %(cvss_v2_score)s, %(cvss_v3_score)s,
                %(cvss_v4_score)s, %(severity)s, %(publish_date)s,
                %(discovery_date)s, %(origin_type)s
            )
            ON CONFLICT (id) DO UPDATE SET
                description    = EXCLUDED.description,
                cvss_v2_score  = EXCLUDED.cvss_v2_score,
                cvss_v3_score  = EXCLUDED.cvss_v3_score,
                cvss_v4_score  = EXCLUDED.cvss_v4_score,
                severity       = EXCLUDED.severity,
                publish_date   = EXCLUDED.publish_date,
                discovery_date = EXCLUDED.discovery_date,
                origin_type    = EXCLUDED.origin_type
            """,
            parsed,
        )
    logger.info("Upserted cve %s", parsed["id"])

def load_all_cves(conn, records: list) -> None:
    """Loop over all parsed CVE records and upsert each."""
    for rec in records:
        upsert_cve(conn, rec)

def update_severity(conn, cve_id: str, severity: str) -> None:
    """Manually correct severity for a CVE once better data is available."""
    with conn.cursor() as cur:
        cur.execute("UPDATE cve SET severity = %s WHERE id = %s", (severity, cve_id))
    logger.info("Updated severity for %s -> %s", cve_id, severity)


def update_discovery_date(conn, cve_id: str, discovery_date: str) -> None:
    """Manually correct discovery_date once a real source (not publish_date) is available."""
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE cve SET discovery_date = %s WHERE id = %s",
            (discovery_date, cve_id),
        )
    logger.info("Updated discovery_date for %s -> %s", cve_id, discovery_date)