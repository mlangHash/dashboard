import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def parse_layers(records: list) -> dict:
    """
    Build a nested layer -> sublayer structure from raw classification records.
    """
    layers = defaultdict(lambda: {"description": "", "sublayers": []})

    for rec in records:
        layer_name = rec.get("layer")
        if not layer_name:
            continue

        layer_description = rec.get("layer_description", "Not Available")
        if layer_description:
            layers[layer_name]["description"] = layer_description

        raw_sublayers = rec.get("sublayers") or []
        for sub_rec in raw_sublayers:
            sublayer_name = sub_rec.get("sublayer")
            if sublayer_name:
                sublayer_description = sub_rec.get("sublayer_description", "Not Available")
                existing = next((sub for sub in layers[layer_name]["sublayers"] if sub["sublayer"] == sublayer_name), None)
                if not existing:
                    layers[layer_name]["sublayers"].append({
                        "sublayer": sublayer_name,
                        "sublayer_description": sublayer_description
                    })
                elif sublayer_description and sublayer_description != "Not Available":
                    existing["sublayer_description"] = sublayer_description

    return dict(layers)

def get_sublayer_id(conn, layer_id: int, name: str) -> int | None:
    """
    Lookup-only, scoped to a specific layer_id -- sublayer names are
    NOT globally unique (e.g. "System Application" exists under both
    "Applications" and "Application Framework"), so layer_id is required
    to avoid matching the wrong sublayer.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM sublayer WHERE layer_id = %s AND name = %s",
            (layer_id, name),
        )
        row = cur.fetchone()
        if row is None:
            logger.warning("No sublayer found for layer_id=%s name=%s", layer_id, name)
            return None
        return row[0]
        
def load_all_layers(conn, layers: dict) -> dict[str, int]:
    """
    Upsert all layer rows. 
    """
    layer_ids = {}
    with conn.cursor() as cur:
        for name, data in layers.items():
            cur.execute(
                """
                INSERT INTO layer (name, description)
                VALUES (%s, %s)
                ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description
                RETURNING id
                """,
                (name, data["description"]),
            )
            layer_ids[name] = cur.fetchone()[0]
            logger.info("Upserted layer '%s' (id=%s)", name, layer_ids[name])
    return layer_ids


def load_all_sublayers(conn, layers: dict, layer_ids: dict[str, int]) -> None:
    """
    Upsert all sublayer rows.
    """
    with conn.cursor() as cur:
        for layer_name, data in layers.items():
            layer_id = layer_ids[layer_name]

            for sublayer in data["sublayers"]:
                sublayer_name = sublayer["sublayer"]
                sublayer_description = sublayer["sublayer_description"]
                cur.execute(
                    "SELECT id FROM sublayer WHERE layer_id = %s AND name = %s",
                    (layer_id, sublayer_name),
                )
                row = cur.fetchone()

                if row is None:
                    cur.execute(
                        """
                        INSERT INTO sublayer (layer_id, name, description)
                        VALUES (%s, %s, %s)
                        """,
                        (layer_id, sublayer_name, sublayer_description),
                    )
                    logger.info(
                        "Inserted sublayer '%s' under layer '%s'", sublayer_name, layer_name
                    )
                else:
                    cur.execute(
                        "UPDATE sublayer SET description = %s WHERE id = %s",
                        (sublayer_description, row[0]),
                    )
                    logger.info(
                        "Updated sublayer '%s' under layer '%s'", sublayer_name, layer_name
                    )


def load_layers_and_sublayers(conn, records: list) -> None:
    """Full pipeline: parse raw records, then upsert layer then sublayer rows."""
    layers = parse_layers(records)
    layer_ids = load_all_layers(conn, layers)
    load_all_sublayers(conn, layers, layer_ids)
    logger.info("Loaded %d layers and their sublayers", len(layers))