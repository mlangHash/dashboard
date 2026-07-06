import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


def parse_layers(records: list) -> dict:
    """
    Build a nested layer -> sublayer structure from raw classification records.
    """
    layers = defaultdict(lambda: {"description": "", "sublayers": {}})

    for rec in records:
        layer_name = rec.get("layer")
        if not layer_name:
            continue

        layer_description = rec.get("layer_description", "")
        if layer_description:
            layers[layer_name]["description"] = layer_description

        sublayer_name = rec.get("sublayer")
        if sublayer_name:
            sublayer_description = rec.get("sublayer_description", "")
            existing = layers[layer_name]["sublayers"].get(sublayer_name, "")
            layers[layer_name]["sublayers"][sublayer_name] = sublayer_description or existing

    return dict(layers)


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

            for sublayer_name, sublayer_description in data["sublayers"].items():
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