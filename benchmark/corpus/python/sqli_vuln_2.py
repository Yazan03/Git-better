"""VULN: CWE-89 — SQL injection via f-string inside execute() call."""
import sqlite3
import flask

app = flask.Flask(__name__)


@app.route("/search")
def search():
    name = flask.request.args.get("name", "")
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name = '{name}'")
    results = cursor.fetchall()
    return str(results)
