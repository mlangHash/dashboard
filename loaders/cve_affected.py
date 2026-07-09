import logging
from loaders.fk_helpers import get_id_only
from loaders.chipset_and_components import get_or_create_chipset_id

logger = logging.getLogger(__name__)

def upsert_cve_affected_device(conn, rec: dict) -> None:
    cve_id = rec.get("cve_id")
    device_id = get_id_only(conn, "device", "codename", rec.get("device_codename"))
    if device_id is None:
        logger.warning("Skipping %s: unknown device %s", cve_id, rec.get("device_codename"))
        return
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_affected_device (cve_id, device_id, is_patched)
            VALUES (%s, %s, %s)
            ON CONFLICT (cve_id, device_id) DO UPDATE SET is_patched = EXCLUDED.is_patched
            """,
            (cve_id, device_id, rec.get("is_patched")),
        )
    logger.info("Upserted cve_affected_device %s / %s", cve_id, rec.get("device_codename"))

def load_all_cve_affected_devices(conn, records: list) -> None:
    for rec in records:
        upsert_cve_affected_device(conn, rec)

def upsert_cve_affected_chipset(conn, rec: dict) -> None:
    cve_id = rec.get("cve_id")
    chipset_id = get_or_create_chipset_id(conn, rec.get("chipset_name"))
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_affected_chipset (cve_id, chipset_id, is_patched)
            VALUES (%s, %s, %s)
            ON CONFLICT (cve_id, chipset_id) DO UPDATE SET is_patched = EXCLUDED.is_patched
            """,
            (cve_id, chipset_id, rec.get("is_patched")),
        )
    logger.info("Upserted cve_affected_chipset %s / %s", cve_id, rec.get("chipset_name"))

def load_all_cve_affected_chipsets(conn, records: list) -> None:
    for rec in records:
        upsert_cve_affected_chipset(conn, rec)

def upsert_cve_affected_component(conn, rec: dict) -> None:
    """component_id here must already resolve to chipset_component.id (hardware side)."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_affected_component (cve_id, component_id)
            VALUES (%s, %s)
            ON CONFLICT (cve_id, component_id) DO NOTHING
            """,
            (rec.get("cve_id"), rec.get("component_id")),
        )
    logger.info("Upserted cve_affected_component %s / %s", rec.get("cve_id"), rec.get("component_id"))

def load_all_cve_affected_components(conn, records: list) -> None:
    for rec in records:
        upsert_cve_affected_component(conn, rec)