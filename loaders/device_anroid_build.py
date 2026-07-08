import logging
from loaders.fk_helpers import get_id_only
from loaders.android_version import get_or_create_android_version_id

logger = logging.getLogger(__name__)


def parse_device_android_build_record(rec: dict) -> dict:
    return {
        "device_codename": rec.get("device_codename"),
        "android_version_name": rec.get("android_version_name"),
        "build_number": rec.get("build_number"),
        "firmware_version": rec.get("firmware_version"),
        "release_date": rec.get("release_date"),
        "security_patch_level": rec.get("security_patch_level"),
    }


def upsert_device_android_build(conn, rec: dict) -> None:
    parsed = parse_device_android_build_record(rec)
    device_id = get_id_only(conn, "device", "codename", parsed["device_codename"])
    if device_id is None:
        logger.warning("Skipping build %s: unknown device", parsed["build_number"])
        return

    android_version_id = get_or_create_android_version_id(conn, parsed["android_version_name"])

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO device_android_build
                (device_id, android_version_id, build_number, firmware_version,
                 release_date, security_patch_level)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (device_id, build_number) DO UPDATE SET
                firmware_version = EXCLUDED.firmware_version,
                security_patch_level = EXCLUDED.security_patch_level
            """,
            (device_id, android_version_id, parsed["build_number"], parsed["firmware_version"],
             parsed["release_date"], parsed["security_patch_level"]),
        )
    logger.info("Upserted device_android_build %s", parsed["build_number"])


def load_all_device_android_builds(conn, records: list) -> None:
    for rec in records:
        upsert_device_android_build(conn, rec)