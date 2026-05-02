"""SAFE: realpath + prefix check prevents path traversal."""
import os
import flask

app = flask.Flask(__name__)
BASE_DIR = os.path.realpath("/var/www/files")


@app.route("/download")
def download():
    filename = flask.request.args.get("file", "")
    filepath = os.path.realpath(os.path.join(BASE_DIR, filename))
    if not filepath.startswith(BASE_DIR + os.sep):
        return flask.abort(403)
    with open(filepath, "rb") as f:
        return flask.Response(f.read(), content_type="application/octet-stream")
