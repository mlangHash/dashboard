# chipset + chipset_component tables 
import logging

logger = logging.getLogger(__name__)

def parse_chipset_record(rec: dict) -> dict:
    return {
        "vendor": rec.get("vendor"),
        "name": rec.get("name"),
        "model_number": rec.get("model_number"),
        "chipset_family": rec.get("chipset_family"),
        "release_date": rec.get("release_date"),
    }


def get_or_create_chipset_id(conn, name: str) -> int:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chipset (name) VALUES (%s)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            """,
            (name,),
        )
        return cur.fetchone()[0]


def upsert_chipset(conn, rec: dict) -> None:
    parsed = parse_chipset_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chipset (vendor, name, model_number, chipset_family, release_date)
            VALUES (%(vendor)s, %(name)s, %(model_number)s, %(chipset_family)s, %(release_date)s)
            ON CONFLICT (name) DO UPDATE SET
                vendor = EXCLUDED.vendor, model_number = EXCLUDED.model_number,
                chipset_family = EXCLUDED.chipset_family, release_date = EXCLUDED.release_date
            """,
            parsed,
        )
    logger.info("Upserted chipset %s", parsed["name"])


def load_all_chipsets(conn, records: list) -> None:
    for rec in records:
        upsert_chipset(conn, rec)
_loader

def parse_chipset_component_record(rec: dict) -> dict:
    return {
        "chipset_name": rec.get("chipset_name"),
        "name": rec.get("name"),
        "description": rec.get("description"),
    }


def upsert_chipset_component(conn, rec: dict) -> None:
    parsed = parse_chipset_component_record(rec)
    chipset_id = get_or_create_chipset_id(conn, parsed["chipset_name"])
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO chipset_component (chipset_id, name, description)
            VALUES (%s, %s, %s)
            ON CONFLICT (chipset_id, name) DO UPDATE SET description = EXCLUDED.description
            """,
            (chipset_id, parsed["name"], parsed["description"]),
        )
    logger.info("Upserted chipset_component %s under %s", parsed["name"], parsed["chipset_name"])


def load_all_chipset_components(conn, records: list) -> None:
    for rec in records:
        upsert_chipset_component(conn, rec)