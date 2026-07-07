import logging
from loaders.component_loader import resolve_layer_and_sublayer_ids, find_component_id

logger = logging.getLogger(__name__)


def parse_cve_component_layer_mapping_record(rec: dict) -> dict:
    return {
        "cve_id": rec.get("cve_id", None),
        "layer_name": rec.get("layer", None),
        "sublayer_name": rec.get("sublayer", None),
        "component_name": rec.get("component", None),
        "component_description": rec.get("description", "Not Available"),
    }


def upsert_cve_component_layer_mapping(conn, rec: dict) -> None:
    parsed = parse_cve_component_layer_mapping_record(rec)

    if not parsed["cve_id"] or not parsed["layer_name"]:
        logger.warning("Skipping cve_component_layer_mapping: missing cve_id or layer (%s)", rec)
        return

    layer_id, sublayer_id = resolve_layer_and_sublayer_ids(conn, parsed["layer_name"], parsed["sublayer_name"])
    if layer_id is None:
        logger.warning(
            "Skipping cve_component_layer_mapping for %s: unresolved layer '%s'",
            parsed["cve_id"], parsed["layer_name"],
        )
        return

    component_id = None
    if parsed["component_name"]:
        component_id = find_component_id(
            conn, layer_id, sublayer_id, parsed["component_name"], parsed["component_description"]
        )

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_component_layer_mapping (cve_id, layer_id, sublayer_id, component_id)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (cve_id, layer_id, sublayer_id, component_id) DO NOTHING
            """,
            (parsed["cve_id"], layer_id, sublayer_id, component_id),
        )
    logger.info("Upserted cve_component_layer_mapping for %s", parsed["cve_id"])


def load_all_cve_component_layer_mappings(conn, records: list) -> None:
    for rec in records:
        upsert_cve_component_layer_mapping(conn, rec)