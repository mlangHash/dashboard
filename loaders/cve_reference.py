import logging

logger = logging.getLogger(__name__)

def parse_reference_records(records: list) -> list:
    """
    Extract cve_reference data from a list of raw NVD records.
    Tags are concatenated into a single comma-separated string
    """
    parsed_records = []
    for rec in records:
        cve_id = rec.get("cve_id")
        references = rec.get("references", [])
        for ref in references:
            tags = ref.get("tags", [])
            parsed_records.append({
                "cve_id": cve_id,
                "url": ref.get("url"),
                "source": ref.get("source"),
                "tags": ",".join(tags),
                "is_patch": "Patch" in tags,
            })
    return parsed_records


def insert_reference(conn, parsed_ref: dict) -> None:
    """
    Insert one cve_reference row. 
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO cve_reference (cve_id, uri, source, tags, is_patch)
            VALUES (%(cve_id)s, %(url)s, %(source)s, %(tags)s, %(is_patch)s)
            """,
            parsed_ref
        )
    logger.info("Inserted reference for %s (%s)", parsed_ref["cve_id"], parsed_ref["url"])


def load_all_references(conn, records: list) -> None:
    """Parse and insert cve_reference rows for all raw NVD records."""
    parsed_records = parse_reference_records(records)
    for parsed_ref in parsed_records:
        insert_reference(conn, parsed_ref)
    logger.info("Loaded %d references", len(parsed_records))