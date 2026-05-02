"""VULN: CWE-22 — Path traversal via open() with unsanitised user filename."""
import os
import flask

app = flask.Flask(__name__)
BASE_DIR = "/var/www/files"


@app.route("/download")
def download():
    filename = flask.request.args.get("file", "")
    filepath = os.path.join(BASE_DIR, filename)
    with open(filepath, "rb") as f:
        return f.read()
