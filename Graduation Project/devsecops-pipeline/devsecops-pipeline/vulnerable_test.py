import os
import sqlite3

# SQL Injection vulnerability
def get_user(username):
    conn = sqlite3.connect("users.db")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    return conn.execute(query)

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"
DB_PASSWORD = "admin123"

# Command injection
def run_command(user_input):
    os.system("ls " + user_input)
