"""VULN: CWE-22 — Path traversal via Flask send_file with user-controlled path."""
import flask

app = flask.Flask(__name__)


@app.route("/static/<path:filename>")
def serve_file(filename):
    user_path = flask.request.args.get("override", filename)
    return flask.send_file(user_path)
