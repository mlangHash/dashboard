# db.py
import atexit
import contextlib
import logging
import os
from dotenv import load_dotenv
from psycopg_pool import ConnectionPool

load_dotenv()
logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL")
print(DATABASE_URL)
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is required")


def on_connect(connection):
    logger.info(
        "New physical connection established: %s",
        connection.info.dsn)

pool = ConnectionPool(
    conninfo=DATABASE_URL,
    min_size=1,
    max_size=10,
    open=False,
    configure=on_connect,
)
pool.open()
atexit.register(pool.close)

@contextlib.contextmanager
def get_db():
    """Borrow a connection from the pool. Commits on success, rolls back on exception."""
    with pool.connection() as connection:
        yield connection