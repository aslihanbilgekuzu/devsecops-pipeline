"""
Demo: Clean and secure Python code
Expected result: LOW risk → AUTO APPROVED ✅
"""

import os
import hashlib
from datetime import datetime


def get_db_password():
    """Retrieve password from environment variable (secure)."""
    return os.getenv("DB_PASSWORD")


def hash_password(password: str) -> str:
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def get_user(conn, user_id: int):
    """Fetch user safely using parameterized query."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def log_event(event: str):
    """Log an event with a timestamp."""
    timestamp = datetime.utcnow().isoformat()
    print(f"[{timestamp}] {event}")


def calculate_total(prices: list) -> float:
    """Calculate total from a list of prices."""
    return sum(p for p in prices if isinstance(p, (int, float)))


if __name__ == "__main__":
    log_event("Application started")
    total = calculate_total([10.5, 20.0, 5.75])
    log_event(f"Total calculated: {total}")
# test
