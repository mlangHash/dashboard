# loaders/cve_loader.py
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_cve_record(rec: dict) -> dict:
    """
    Extract cve table fields from a standardised record.

    CONTRACT — parsers must supply dicts with these keys:
        cve_id, description, cvss_v2_score, cvss_v3_score, cvss_v4_score,
        severity, publish_date, discovery_date, origin_type, exploited_in_wild

    Any missing key defaults to None via .get().
    """
    return {
        "id":                   rec.get("cve_id"),
        "description":          rec.get("description", None),
        "cvss_v2_score":        rec.get("cvss_v2_score", None),
        "cvss_v3_score":        rec.get("cvss_v3_score", None),
        "cvss_v4_score":        rec.get("cvss_v4_score", None),
        "severity":             rec.get("severity", None),
        "publish_date":         rec.get("publish_date", None),
        "discovery_date":       rec.get("discovery_date", None),
        "origin_type":          rec.get("origin_type", None),
        "exploited_in_wild":    rec.get("exploited_in_wild", None),
    }


def upsert_cve(conn, rec: dict) -> None:
    """Insert or update a single CVE's core fields. Idempotent."""
    parsed = parse_cve_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve (
                id, description, cvss_v2_score, cvss_v3_score, cvss_v4_score,
                severity, publish_date, discovery_date, origin_type,
                exploited_in_wild
            ) VALUES (
                %(id)s, %(description)s, %(cvss_v2_score)s, %(cvss_v3_score)s,
                %(cvss_v4_score)s, %(severity)s, %(publish_date)s,
                %(discovery_date)s, %(origin_type)s, %(exploited_in_wild)s
            )
            ON CONFLICT (id) DO UPDATE SET
                description        = COALESCE(EXCLUDED.description,        cve.description),
                cvss_v2_score      = COALESCE(EXCLUDED.cvss_v2_score,      cve.cvss_v2_score),
                cvss_v3_score      = COALESCE(EXCLUDED.cvss_v3_score,      cve.cvss_v3_score),
                cvss_v4_score      = COALESCE(EXCLUDED.cvss_v4_score,      cve.cvss_v4_score),
                severity           = COALESCE(EXCLUDED.severity,           cve.severity),
                publish_date       = COALESCE(EXCLUDED.publish_date,       cve.publish_date),
                discovery_date     = COALESCE(EXCLUDED.discovery_date,     cve.discovery_date),
                origin_type        = COALESCE(EXCLUDED.origin_type,        cve.origin_type),
                exploited_in_wild  = COALESCE(EXCLUDED.exploited_in_wild,  cve.exploited_in_wild)
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