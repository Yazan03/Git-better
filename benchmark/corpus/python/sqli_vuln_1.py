"""VULN: CWE-89 — SQL injection via string concatenation (sqlite3)."""
import sqlite3


def find_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()


def login(username, password):
    user = find_user(username)
    if user and user[2] == password:
        return True
    return False
