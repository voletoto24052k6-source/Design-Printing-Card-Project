from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

load_dotenv()


def _connection_value(value: str) -> str:
    """Escape a value for an ODBC-style SQL Server connection string."""
    return "{" + value.replace("}", "}}") + "}"


def get_connection() -> Any:
    """Open SQL Server through Microsoft's mssql-python DB-API driver.

    Configure DB_SERVER and DB_NAME plus either DB_TRUSTED_CONNECTION=true
    or DB_USER/DB_PASSWORD in the process environment or a local .env file.
    The caller owns and must close the returned connection.
    """
    try:
        import mssql_python
    except ImportError as exc:
        raise RuntimeError(
            "The mssql-python driver is unavailable or Windows blocked one of "
            "its native files. Install requirements.txt and inspect CodeIntegrity "
            "events if Smart App Control blocks it."
        ) from exc

    server = os.getenv("DB_SERVER", "").strip()
    database = os.getenv("DB_NAME", "PrintCardDB").strip()
    trusted = os.getenv("DB_TRUSTED_CONNECTION", "false").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if not server or not database:
        raise ValueError("Set DB_SERVER and DB_NAME in the environment or .env.")

    parts = [
        f"Server={_connection_value(server)}",
        f"Database={_connection_value(database)}",
        "Encrypt=" + os.getenv("DB_ENCRYPT", "yes").strip(),
        "TrustServerCertificate="
        + os.getenv("DB_TRUST_SERVER_CERTIFICATE", "no").strip(),
    ]
    if trusted:
        parts.append("Trusted_Connection=yes")
    else:
        username = os.getenv("DB_USER", "")
        password = os.getenv("DB_PASSWORD", "")
        if not username or not password:
            raise ValueError(
                "Set DB_USER and DB_PASSWORD, or enable DB_TRUSTED_CONNECTION."
            )
        parts.extend(
            (f"UID={_connection_value(username)}", f"PWD={_connection_value(password)}")
        )

    try:
        timeout = int(os.getenv("DB_CONNECTION_TIMEOUT", "5"))
    except ValueError as exc:
        raise ValueError("DB_CONNECTION_TIMEOUT must be a positive integer.") from exc
    if timeout < 1:
        raise ValueError("DB_CONNECTION_TIMEOUT must be a positive integer.")

    return mssql_python.connect(";".join(parts), timeout=timeout)


def check_connection() -> dict[str, Any]:
    """Connect and return the SQL Server and database names."""
    connection = get_connection()
    try:
        cursor = connection.cursor()
        try:
            row = cursor.execute(
                "SELECT CAST(SERVERPROPERTY('ServerName') AS nvarchar(128)), DB_NAME()"
            ).fetchone()
            return {"server": row[0], "database": row[1]}
        finally:
            cursor.close()
    finally:
        connection.close()
