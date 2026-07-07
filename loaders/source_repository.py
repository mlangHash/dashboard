import logging

logger = logging.getLogger(__name__)


def parse_source_repository_record(rec: dict) -> dict:
    return {
        "name": rec.get("name"),
        "repo_type": rec.get("repo_type"),
        "url": rec.get("url"),
        "branch": rec.get("branch"),
    }
        
def get_or_create_source_repository_id(conn, name: str, repo_type: str = None,
                                        url: str = None, branch: str = None) -> int:
    """Relies on uq_source_repository_name UNIQUE constraint on source_repository.name."""
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO source_repository (name, repo_type, url, branch)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (name) DO UPDATE SET
                repo_type = EXCLUDED.repo_type,
                url = EXCLUDED.url,
                branch = EXCLUDED.branch
            RETURNING id
            """,
            (name, repo_type, url, branch),
        )
        return cur.fetchone()[0]


def upsert_source_repository(conn, rec: dict) -> None:
    parsed = parse_source_repository_record(rec)
    get_or_create_source_repository_id(conn, parsed["name"], parsed["repo_type"],
                                        parsed["url"], parsed["branch"])
    logger.info("Upserted source_repository %s", parsed["name"])


def load_all_source_repositories(conn, records: list) -> None:
    for rec in records:
        upsert_source_repository(conn, rec)