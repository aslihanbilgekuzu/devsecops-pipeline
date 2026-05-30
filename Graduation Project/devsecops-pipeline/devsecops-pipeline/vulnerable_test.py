"""
Demo: Vulnerable Python code (intentional security issues)
Expected result: CRITICAL risk → BLOCKED 🔴

Issues:
  1. Hardcoded secrets
  2. SQL Injection
  3. Command Injection
"""

import os
import sqlite3

# ⚠️ Hardcoded secrets (should use env variables)
API_KEY = "sk-abc123secretkey9999"
DB_PASSWORD = "admin123"
SECRET_TOKEN = "supersecret-token-xyz"


def get_user(conn, username):
    """Fetch user — vulnerable to SQL Injection."""
    cursor = conn.cursor()
    # ⚠️ SQL Injection: user input directly in query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def run_command(user_input):
    """Run a system command — vulnerable to Command Injection."""
    # ⚠️ Command Injection: user input passed directly to os.system
    os.system("ls " + user_input)


def login(username, password):
    """Login check — insecure password comparison."""
    # ⚠️ Hardcoded admin credentials
    if username == "admin" and password == "admin123":
        return True
    return False


if __name__ == "__main__":
    run_command("/home")
    print(f"Using API key: {API_KEY}")
# gitleaks test
# semgrep test
# email test
# email test1
# email test 2
# email test 3
password = 'newpassword123'
# critical test
# critical test
# critical test
#email fix test
