import logging

logger = logging.getLogger(__name__)


def parse_cpe_criteria(criteria: str) -> dict:
    """cpe:2.3:a:vendor:product:version:... -> {part, vendor, product, version}."""
    parts = criteria.split(":")
    return {
        "cpe_uri": criteria,
        "part": parts[2] if len(parts) > 2 else None,
        "vendor": parts[3] if len(parts) > 3 else None,
        "product": parts[4] if len(parts) > 4 else None,
        "version": parts[5] if len(parts) > 5 else None,
    }


def get_or_create_cpe_id(conn, criteria: str) -> int:
    """
    Atomic upsert-and-return-id, relies on the uq_cpe_cpe_uri UNIQUE constraint on cpe.cpe_uri.
    """
    parsed = parse_cpe_criteria(criteria)
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cpe (cpe_uri, part, vendor, product, version)
            VALUES (%(cpe_uri)s, %(part)s, %(vendor)s, %(product)s, %(version)s)
            ON CONFLICT (cpe_uri) DO UPDATE SET
                part = EXCLUDED.part,
                vendor = EXCLUDED.vendor,
                product = EXCLUDED.product,
                version = EXCLUDED.version
            RETURNING id
            """,
            parsed,
        )
        return cur.fetchone()[0]


def load_cpe_configurations_for_cve(conn, cve_id: str, cpe_configurations: list) -> None:
    """
    For a single CVE's cpe_configurations[] list: resolve/create each cpe row, link it via cve_product, and record any version range info.
    """
    with conn.cursor() as cur:
        for entry in cpe_configurations:
            cpe_id = get_or_create_cpe_id(conn, entry["criteria"])

            # cve_product has no unique constraint -- manual check to avoid duplicates
            cur.execute(
                "SELECT id FROM cve_product WHERE cve_id = %s AND cpe_id = %s",
                (cve_id, cpe_id),
            )
            row = cur.fetchone()
            if row is None:
                cur.execute(
                    "INSERT INTO cve_product (cve_id, cpe_id, vulnerable) VALUES (%s, %s, %s) RETURNING id",
                    (cve_id, cpe_id, entry.get("vulnerable")),
                )
                cve_product_id = cur.fetchone()[0]
                logger.info("Inserted cve_product for %s / %s", cve_id, entry["criteria"])
            else:
                cve_product_id = row[0]
                cur.execute(
                    "UPDATE cve_product SET vulnerable = %s WHERE id = %s",
                    (entry.get("vulnerable"), cve_product_id),
                )

            ranges = (
                entry.get("version_start_including"),
                entry.get("version_start_excluding"),
                entry.get("version_end_including"),
                entry.get("version_end_excluding"),
            )
            if any(ranges):
                # avoid duplicate range rows on re-run -- no unique constraint here either
                cur.execute(
                    "SELECT id FROM cve_product_version_range WHERE cve_product_id = %s",
                    (cve_product_id,),
                )
                range_row = cur.fetchone()
                if range_row is None:
                    cur.execute(
                        """
                        INSERT INTO cve_product_version_range
                            (cve_product_id, version_start_including, version_start_excluding,
                             version_end_including, version_end_excluding)
                        VALUES (%s, %s, %s, %s, %s)
                        """,
                        (cve_product_id, *ranges),
                    )
                    logger.info("Inserted cve_product_version_range for cve_product_id=%s", cve_product_id)
                else:
                    cur.execute(
                        """
                        UPDATE cve_product_version_range
                        SET version_start_including = %s, version_start_excluding = %s,
                            version_end_including = %s, version_end_excluding = %s
                        WHERE id = %s
                        """,
                        (*ranges, range_row[0]),
                    )


def load_all_cpe_data(conn, records: list) -> None:
    """ Loop over all raw NVD records and load their cpe_configurations.
    Requires cve rows to already exist (cve_product.cve_id is a FK to cve.id). """

    processed = 0
    for rec in records:
        cve_id = rec.get("cve_id")
        cpe_configurations = rec.get("cpe_configurations") or []
        if cpe_configurations:
            load_cpe_configurations_for_cve(conn, cve_id, cpe_configurations)
            processed += 1
    logger.info("Loaded cpe/cve_product/cve_product_version_range for %d/%d records", processed, len(records))