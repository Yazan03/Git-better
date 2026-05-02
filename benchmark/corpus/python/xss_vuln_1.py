"""VULN: CWE-79 — XSS / SSTI via render_template_string with user input."""
import flask

app = flask.Flask(__name__)


@app.route("/greet")
def greet():
    name = flask.request.args.get("name", "World")
    template = f"<h1>Hello, {name}!</h1>"
    return flask.render_template_string(template)
