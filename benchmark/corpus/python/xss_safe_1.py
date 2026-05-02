"""SAFE: user input escaped with markupsafe before embedding in HTML."""
import flask
from markupsafe import escape

app = flask.Flask(__name__)


@app.route("/search")
def search():
    query = escape(flask.request.args.get("q", ""))
    html = f"<html><body><h2>Results for: {query}</h2></body></html>"
    return flask.Response(html, content_type="text/html")
