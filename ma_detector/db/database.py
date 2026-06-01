"""MySQL connection pool for the ground-station database."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger(__name__)

_pool: Any = None
_db_available = False


def is_db_available() -> bool:
    """Return True when the MySQL pool initialized successfully."""
    try:
        return _db_available and _pool is not None
    except Exception as error:
        logger.error("db availability check failed: %s", error)
        return False


def require_db() -> None:
    """Raise when MySQL is unavailable (ground-station requires DB)."""
    if not is_db_available():
        raise RuntimeError(
            "MySQL is required for ground-station operation; check DB connection and matador_gs schema"
        )


def init_db(
    host: str,
    port: int,
    user: str,
    password: str,
    database: str,
    pool_size: int = 5,
) -> None:
    """Initialize the MySQL connection pool."""
    global _pool, _db_available
    try:
        import mysql.connector
        from mysql.connector import pooling

        _pool = pooling.MySQLConnectionPool(
            pool_name="matador_gs_pool",
            pool_size=pool_size,
            pool_reset_session=True,
            host=host,
            port=port,
            user=user,
            password=password,
            database=database,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
            autocommit=False,
        )
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
        _db_available = True
        logger.info("MySQL pool initialized for database %s", database)
    except ImportError as error:
        _pool = None
        _db_available = False
        logger.warning("mysql-connector-python not installed: %s", error)
    except Exception as error:
        _pool = None
        _db_available = False
        logger.warning("MySQL pool initialization failed: %s", error)


@contextmanager
def get_connection() -> Generator[Any, None, None]:
    """Yield a pooled MySQL connection."""
    if _pool is None:
        raise RuntimeError("database pool is not initialized")
    conn = None
    try:
        conn = _pool.get_connection()
        yield conn
        conn.commit()
    except Exception as error:
        if conn is not None:
            try:
                conn.rollback()
            except Exception as rollback_error:
                logger.error("connection rollback failed: %s", rollback_error)
        logger.error("database connection error: %s", error)
        raise
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception as close_error:
                logger.error("connection close failed: %s", close_error)
