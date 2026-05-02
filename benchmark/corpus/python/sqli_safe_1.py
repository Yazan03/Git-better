"""SAFE: parameterized query prevents SQL injection."""
import sqlite3


def find_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchone()


def login(username, password):
    user = find_user(username)
    if user and user[2] == password:
        return True
    return False
