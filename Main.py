import logging

from DBConnection import get_db
from parsers.loadFiles import load_records
import loaders as lds

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

NVD_FILE = "files/nvd_parser.json"
CLASSIFIED_PATCHES1 = "files/classified_patches1.json"

def main() -> None:
    nvd_records = load_records(NVD_FILE)
    classified_records = load_records(CLASSIFIED_PATCHES1)

    with get_db() as conn:
        lds.load_all_cves(conn, nvd_records)

        lds.load_all_references(conn, nvd_records)
        lds.load_layers_and_sublayers(conn, classified_records)

    logger.info("Ingestion complete: %d CVEs processed", len(nvd_records))


if __name__ == "__main__":
    main()