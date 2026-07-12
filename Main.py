"""
Main entry point — orchestrates parsing all JSON data files and loading
them into the VulCrawlerDB PostgreSQL database.
"""
import logging
from pathlib import Path

from DBConnection import get_db
from parsers import prepare_all
import loaders as lds

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

DATA_DIR = Path("files")


def main() -> None:
    # ── Phase 1: Parse all source files into a unified dataset ────
    logger.info("Phase 1: Parsing all data files from %s", DATA_DIR)
    dataset = prepare_all(DATA_DIR)

    if not dataset:
        logger.warning("No data parsed. Exiting.")
        return

    # ── Phase 2: Load into database (respecting FK dependency order) ──
    logger.info("Phase 2: Loading into database")
    with get_db() as conn:

        # 1. Reference/lookup tables (no FKs to other app tables)
        lds.load_all_vendors(conn, dataset.get("vendor", []))
        lds.load_all_cwes(conn, dataset.get("cwe", []))

        # 2. Core CVE table
        lds.load_all_cves(conn, dataset.get("cve", []))

        # 3. CVE junction/detail tables (FK → cve)
        lds.load_all_cve_cwe(conn, dataset.get("cve_cwe", []))
        lds.load_all_references(conn, dataset.get("cve_reference", []))
        lds.load_all_cpe_data(conn, dataset.get("cpe", []))

        # 4. Hardware tables
        lds.load_all_chipsets(conn, dataset.get("chipset", []))
        lds.load_all_cve_affected_chipsets(conn, dataset.get("cve_affected_chipset", []))

        # 5. Bulletin / vendor-CVE tables
        lds.load_all_security_bulletins(conn, dataset.get("security_bulletin", []))
        lds.load_all_vendor_cves(conn, dataset.get("vendor_cve", []))

        # 6. Source code tables
        lds.load_all_source_repositories(conn, dataset.get("source_repository", []))
        lds.load_all_cve_source_mappings(conn, dataset.get("cve_source_mapping", []))

    total_records = sum(len(v) for v in dataset.values())
    logger.info("Ingestion complete: %d total records across %d tables", total_records, len(dataset))


if __name__ == "__main__":
    main()