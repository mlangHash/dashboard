# loaders/component_loader.py
import logging
from loaders.fk_helpers import get_id_only
from loaders.layer import get_sublayer_id

logger = logging.getLogger(__name__)


def parse_component_record(rec: dict) -> dict:
    return {
        "layer_name": rec.get("layer", None),
        "sublayer_name": rec.get("sublayer", None),
        "name": rec.get("name", None),
        "description": rec.get("description", "Not Available"),
    }


def resolve_layer_and_sublayer_ids(conn, layer_name: str, sublayer_name: str = None) -> tuple[int | None, int | None]:

    layer_id = get_id_only(conn, "layer", "name", layer_name)
    if layer_id is None:
        return None, None

    sublayer_id = get_sublayer_id(conn, layer_id, sublayer_name) if sublayer_name else None
    return layer_id, sublayer_id


def insert_component(conn, layer_id: int, sublayer_id: int, name: str, description: str = None) -> int:
    """Inserts a new component row and returns its id."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO component (layer_id, sublayer_id, name, description)
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (layer_id, sublayer_id, name, description),
        )
        component_id = cur.fetchone()[0]
    logger.info("Inserted component '%s' (id=%s)", name, component_id)
    return component_id


def find_component_id(conn, layer_id: int, sublayer_id: int | None, name: str, description: str = None) -> int:
    """
    Checks whether a component row already exists for this exact
    (layer_id, sublayer_id, name); inserts it via insert_component if
    missing.
    """
    with conn.cursor() as cur:
        if sublayer_id is None:
            cur.execute(
                "SELECT id FROM component WHERE layer_id = %s AND sublayer_id IS NULL AND name = %s",
                (layer_id, name),
            )
        else:
            cur.execute(
                "SELECT id FROM component WHERE layer_id = %s AND sublayer_id = %s AND name = %s",
                (layer_id, sublayer_id, name),
            )
        row = cur.fetchone()

    if row:
        return row[0]

    return insert_component(conn, layer_id, sublayer_id, name, description)


def upsert_component(conn, rec: dict) -> None:

    parsed = parse_component_record(rec)

    if not parsed["layer_name"] or not parsed["name"]:
        logger.warning("Skipping component record: missing layer or name (%s)", rec)
        return

    layer_id, sublayer_id = resolve_layer_and_sublayer_ids(conn, parsed["layer_name"], parsed["sublayer_name"])
    if layer_id is None:
        logger.warning(
            "Skipping component '%s': unresolved layer '%s'",
            parsed["name"], parsed["layer_name"],
        )
        return

    find_component_id(conn, layer_id, sublayer_id, parsed["name"], parsed["description"])


def load_all_components(conn, records: list) -> None:
    for rec in records:
        upsert_component(conn, rec)