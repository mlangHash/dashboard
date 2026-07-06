import logging

logger = logging.getLogger(__name__)

def parse_android_version_record(rec: dict) -> dict:
    """ Return a dict of android_version table fields from a raw NVD record. """
    return {
        "version_name": rec.get("version_name"),
        "api_level": rec.get("api_level"),
        "release_date": rec.get("release_date"),
    }


def get_or_create_android_version_id(conn, version_name: str) -> int:
    """ Get the ID of an existing android_version or create a new one. """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO android_version (version_name) VALUES (%s)
            ON CONFLICT (version_name) DO UPDATE SET version_name = EXCLUDED.version_name
            RETURNING id
            """,
            (version_name,),
        )
        return cur.fetchone()[0]


def upsert_android_version(conn, rec: dict) -> None:
    """ Insert or update an android_version record in the database. """
    parsed = parse_android_version_record(rec)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO android_version (version_name, api_level, release_date)
            VALUES (%(version_name)s, %(api_level)s, %(release_date)s)
            ON CONFLICT (version_name) DO UPDATE SET
                api_level = EXCLUDED.api_level,
                release_date = EXCLUDED.release_date
            """,
            parsed,
        )
    logger.info("Upserted android_version %s", parsed["version_name"])


def load_all_android_versions(conn, records: list) -> None:
    """ Loop over all parsed android_version records and upsert each. """
    for rec in records:
        upsert_android_version(conn, rec)