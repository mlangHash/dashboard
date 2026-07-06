import logging
from loaders.fk_helpers import get_id_only

logger = logging.getLogger(__name__)


def parse_preinstalled_app_record(rec: dict) -> dict:
    """ Return a dict of preinstalled_app table fields from a raw record. """
    
    return {
        "device_codename": rec.get("device_codename"),
        "layer_name": rec.get("layer_name"),
        "package_name": rec.get("package_name"),
        "version": rec.get("version"),
    }


def upsert_preinstalled_app(conn, rec: dict) -> None:
    """ Insert or update a preinstalled_app record in the database. """

    parsed = parse_preinstalled_app_record(rec)
    device_id = get_id_only(conn, "device", "codename", parsed["device_codename"])
    if device_id is None:
        logger.warning("Skipping preinstalled_app %s: unknown device", parsed["package_name"])
        return

    layer_id = get_id_only(conn, "layer", "name", parsed["layer_name"]) if parsed["layer_name"] else None

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO preinstalled_app (device_id, layer_id, package_name, version)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (device_id, package_name) DO UPDATE SET
                layer_id = EXCLUDED.layer_id,
                version = EXCLUDED.version
            """,
            (device_id, layer_id, parsed["package_name"], parsed["version"]),
        )
    logger.info("Upserted preinstalled_app %s", parsed["package_name"])


def load_all_preinstalled_apps(conn, records: list) -> None:
    """ Loop over all parsed preinstalled_app records and upsert each. """

    for rec in records:
        upsert_preinstalled_app(conn, rec)