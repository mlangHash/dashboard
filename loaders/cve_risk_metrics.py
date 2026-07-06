import logging

logger = logging.getLogger(__name__)

def parse_cve_risk_metrics_record(rec: dict) -> dict:
    return {
        "cve_id": rec.get("cve_id"),
        "epss_score": rec.get("epss_score"),
        "epss_percentile": rec.get("epss_percentile"),
        "kev_listed": rec.get("kev_listed"),
        "ransomware_use": rec.get("ransomware_use"),
    }


def upsert_cve_risk_metrics(conn, rec: dict) -> None:
    """last_updated is trigger-managed; never set it here."""
    parsed = parse_cve_risk_metrics_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_risk_metrics (cve_id, epss_score, epss_percentile, kev_listed, ransomware_use)
            VALUES (%(cve_id)s, %(epss_score)s, %(epss_percentile)s, %(kev_listed)s, %(ransomware_use)s)
            ON CONFLICT (cve_id) DO UPDATE SET
                epss_score = EXCLUDED.epss_score,
                epss_percentile = EXCLUDED.epss_percentile,
                kev_listed = EXCLUDED.kev_listed,
                ransomware_use = EXCLUDED.ransomware_use
            """,
            parsed,
        )
    logger.info("Upserted cve_risk_metrics for %s", parsed["cve_id"])


def load_all_cve_risk_metrics(conn, records: list) -> None:
    for rec in records:
        upsert_cve_risk_metrics(conn, rec)