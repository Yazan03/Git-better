"""VULN: CWE-78 — OS command injection via os.system() with user input."""
import os
import flask

app = flask.Flask(__name__)


@app.route("/ping")
def ping():
    host = flask.request.args.get("host", "localhost")
    result = os.system("ping -c 1 " + host)
    return str(result)
