# loaders/device_loader.py
import logging
from loaders.vendor import get_or_create_vendor_id
from loaders.chipset_and_components import get_or_create_chipset_id

logger = logging.getLogger(__name__)

DEVICE_COLUMNS = [
    "name", "codename", "model_number", "device_type", "launch_os", "current_os",
    "launch_user_interface", "current_user_interface", "source", "region",
    "launch_date", "eol_date", "is_flagship",
]


def parse_device_record(rec: dict) -> dict:
    parsed = {col: rec.get(col, "") for col in DEVICE_COLUMNS}
    parsed["vendor_name"] = rec.get("vendor_name", "")
    parsed["chipset_name"] = rec.get("chipset_name", "")
    return parsed


def upsert_device(conn, rec: dict) -> None:
    parsed = parse_device_record(rec)
    vendor_id = get_or_create_vendor_id(conn, parsed["vendor_name"]) if parsed["vendor_name"] else None
    chipset_id = get_or_create_chipset_id(conn, parsed["chipset_name"]) if parsed["chipset_name"] else None

    values = {c: parsed[c] for c in DEVICE_COLUMNS}
    values["vendor_id"] = vendor_id
    values["chipset_id"] = chipset_id

    cols = ", ".join(values.keys())
    placeholders = ", ".join(f"%({k})s" for k in values)
    update_clause = ", ".join(f"{k} = EXCLUDED.{k}" for k in values if k != "codename")

    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO device ({cols}) VALUES ({placeholders})
            ON CONFLICT (codename) DO UPDATE SET {update_clause}
            """,
            values,
        )
    logger.info("Upserted device %s", parsed["codename"])


def load_all_devices(conn, records: list) -> None:
    for rec in records:
        upsert_device(conn, rec)