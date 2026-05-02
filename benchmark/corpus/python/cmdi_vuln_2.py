"""VULN: CWE-78 — OS command injection via subprocess with shell=True."""
import subprocess
import flask

app = flask.Flask(__name__)


@app.route("/run")
def run_command():
    cmd = flask.request.args.get("cmd", "")
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()
