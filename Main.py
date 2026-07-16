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

        # 1. Independent lookup/reference tables (no FKs to other app tables)
        logger.info("Loading Phase 1 tables (independent references)...")
        lds.load_all_vendors(conn, dataset.get("vendor", []))
        lds.load_all_android_versions(conn, dataset.get("android_version", []))
        lds.load_all_cwes(conn, dataset.get("cwe", []))
        lds.load_layers_and_sublayers(conn, dataset.get("layer_sublayer", []))
        lds.load_all_exploit_sources(conn, dataset.get("exploit_source", []))
        lds.load_all_source_repositories(conn, dataset.get("source_repository", []))
        lds.load_all_chipsets(conn, dataset.get("chipset", []))

        # 2. First-level dependent tables (depend on independent tables)
        logger.info("Loading Phase 2 tables (first-level dependencies)...")
        lds.load_all_chipset_components(conn, dataset.get("chipset_component", []))
        lds.load_all_devices(conn, dataset.get("device", []))
        lds.load_all_components(conn, dataset.get("component", []))
        lds.load_all_security_bulletins(conn, dataset.get("security_bulletin", []))

        # 3. Second-level dependent tables (depend on first-level tables)
        logger.info("Loading Phase 3 tables (second-level dependencies)...")
        lds.load_all_device_android_builds(conn, dataset.get("device_android_build", []))
        lds.load_all_preinstalled_apps(conn, dataset.get("preinstalled_app", []))

        # 4. Core CVE table (depends on layer/sublayer tables)
        logger.info("Loading Phase 4 tables (core CVE)...")
        lds.load_all_cves(conn, dataset.get("cve", []))

        # 5. CVE junction/detail tables (depend on CVE table)
        logger.info("Loading Phase 5 tables (CVE junctions and details)...")
        lds.load_all_cve_cwe(conn, dataset.get("cve_cwe", []))
        lds.load_all_references(conn, dataset.get("cve_reference", []))
        lds.load_all_cpe_data(conn, dataset.get("cpe", []))
        lds.load_all_cve_timeline_events(conn, dataset.get("cve_timeline_event", []))
        lds.load_all_cve_source_mappings(conn, dataset.get("cve_source_mapping", []))
        lds.load_all_cve_risk_metrics(conn, dataset.get("cve_risk_metrics", []))
        lds.load_all_cve_exploits(conn, dataset.get("cve_exploit", []))
        lds.load_all_vendor_cves(conn, dataset.get("vendor_cve", []))

        # 6. CVE affected targets tables (depend on CVE and device/chipset/component/architecture)
        logger.info("Loading Phase 6 tables (CVE affected targets)...")
        lds.load_all_cve_affected_devices(conn, dataset.get("cve_affected_device", []))
        lds.load_all_cve_affected_chipsets(conn, dataset.get("cve_affected_chipset", []))
        lds.load_all_cve_affected_components(conn, dataset.get("cve_affected_component", []))
        lds.load_all_cve_component_layer_mappings(conn, dataset.get("cve_component_layer_mapping", []))

    total_records = sum(len(v) for v in dataset.values())
    logger.info("Ingestion complete: %d total records across %d tables", total_records, len(dataset))


if __name__ == "__main__":
    main()