"""Authentication module for Aegis-Twin.

Provides a minimal, secure login layer for the Streamlit dashboard.

Uses an SQLite database to store user credentials (email + bcrypt hashed password).

Usage:
    from auth import create_user, verify_user, get_user, init_db

    init_db()
    create_user("admin@example.com", "StrongPassword123")
    assert verify_user("admin@example.com", "StrongPassword123")
"""

from __future__ import annotations

import datetime
import os
import sqlite3
from typing import Optional, Dict, Any

import bcrypt
import hashlib


# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

# Location of the authentication database (SQLite).
# Defaults to a file in the same directory as this module.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("AEGIS_AUTH_DB_PATH", os.path.join(BASE_DIR, "aegis_auth.db"))


# -----------------------------------------------------------------------------
# Password Helpers
# -----------------------------------------------------------------------------

def _hash_password(password: str) -> str:
    """Hash the password using SHA-256 + bcrypt.

    This avoids bcrypt's 72-byte password limit by pre-hashing the input.
    """
    if isinstance(password, str):
        password = password.encode("utf-8")
    digest = hashlib.sha256(password).digest()
    hashed = bcrypt.hashpw(digest, bcrypt.gensalt())
    return hashed.decode("utf-8")


def _verify_password(password: str, password_hash: str) -> bool:
    if isinstance(password, str):
        password = password.encode("utf-8")
    digest = hashlib.sha256(password).digest()
    if isinstance(password_hash, str):
        password_hash = password_hash.encode("utf-8")
    return bcrypt.checkpw(digest, password_hash)


# -----------------------------------------------------------------------------
# Database Utility Helpers
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Database Utility Helpers
# -----------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    """Return a connection to the auth database."""
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize the authentication database schema."""
    conn = _get_connection()
    with conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
    conn.close()


# -----------------------------------------------------------------------------
# User Management
# -----------------------------------------------------------------------------

def create_user(email: str, password: str) -> Dict[str, Any]:
    """Create a new user with a hashed password.

    Raises:
        ValueError: If the user already exists.
    """
    email = email.strip().lower()
    if not email or not password:
        raise ValueError("Email and password are required.")

    if get_user(email) is not None:
        raise ValueError(f"User already exists: {email}")

    password_hash = _hash_password(password)
    created_at = datetime.datetime.utcnow().isoformat()

    conn = _get_connection()
    with conn:
        conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, password_hash, created_at),
        )
    conn.close()

    return {"email": email, "created_at": created_at}


def has_users() -> bool:
    """Return True if at least one user exists in the database."""
    conn = _get_connection()
    row = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    conn.close()
    return row is not None


def get_user(email: str) -> Optional[Dict[str, Any]]:
    """Retrieve a user record by email."""
    email = email.strip().lower()
    conn = _get_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if row is None:
        return None
    return dict(row)


def verify_user(email: str, password: str) -> bool:
    """Verify a user's credentials."""
    user = get_user(email)
    if not user:
        return False
    return _verify_password(password, user["password_hash"])
