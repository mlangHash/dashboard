import logging

logger = logging.getLogger(__name__)


def get_or_create(conn, table: str, lookup_column: str, lookup_value,
                   insert_columns: list[str], insert_values: tuple) -> int:
    """
    Atomic upsert-and-return-id. Requires a UNIQUE constraint on
    lookup_column in `table` -- without one, ON CONFLICT has nothing
    to target and Postgres will raise an error.
    """
    cols = ", ".join(insert_columns)
    placeholders = ", ".join(["%s"] * len(insert_values))
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO {table} ({cols})
            VALUES ({placeholders})
            ON CONFLICT ({lookup_column}) DO UPDATE SET {lookup_column} = EXCLUDED.{lookup_column}
            RETURNING id
            """,
            insert_values,
        )
        return cur.fetchone()[0]


def get_id_only(conn, table: str, lookup_column: str, lookup_value):
    """
    This is about ownership (don't silently create a new layer/sublayer/device from a loader that doesn't own that table), not about race safety.
    """
    with conn.cursor() as cur:
        cur.execute(
            f"SELECT id FROM {table} WHERE {lookup_column} = %s", (lookup_value,))
        row = cur.fetchone()
        if row is None:
            logger.warning("No %s found for %s=%s", table, lookup_column, lookup_value)
            return None
        return row[0]


def alembic_version(conn, record: dict) -> None:
    with conn.cursor() as cur:
        cur.execute(
            " INSERT INTO alembic_version (version_num) VALUES (%(version_num)s)",
            record,
        )