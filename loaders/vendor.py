import logging

logger = logging.getLogger(__name__)

def parse_vendor_record(rec: dict) -> dict:
    """ Return a dict of vendor table fields from a raw NVD record. """
    return {
        "name": rec.get("name"),
        "country": rec.get("country"),
        "security_bulletin_url": rec.get("security_bulletin_url"),
    }


def get_or_create_vendor_id(conn, name: str) -> int:
    """ Get the ID of an existing vendor or create a new one. """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vendor (name) VALUES (%s)
            ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name
            RETURNING id
            """,
            (name,),
        )
        return cur.fetchone()[0]


def upsert_vendor(conn, rec: dict) -> None:
    """ Insert or update a vendor record in the database. """
    parsed = parse_vendor_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO vendor (name, country, security_bulletin_url)
            VALUES (%(name)s, %(country)s, %(security_bulletin_url)s)
            ON CONFLICT (name) DO UPDATE SET
                country = EXCLUDED.country,
                security_bulletin_url = EXCLUDED.security_bulletin_url
            """,
            parsed,
        )
    logger.info("Upserted vendor %s", parsed["name"])


def load_all_vendors(conn, records: list) -> None:
    """ Loop over all parsed vendor records and upsert each. """
    for rec in records:
        upsert_vendor(conn, rec)