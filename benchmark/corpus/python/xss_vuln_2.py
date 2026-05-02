"""VULN: CWE-79 — Reflected XSS via unescaped user input in Flask response."""
import flask

app = flask.Flask(__name__)


@app.route("/search")
def search():
    query = flask.request.args.get("q", "")
    html = "<html><body><h2>Results for: " + query + "</h2></body></html>"
    return flask.Response(html, content_type="text/html")
