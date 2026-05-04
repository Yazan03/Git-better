"""
pytest test suite for vuln_scanner.py
Each test writes a tiny Python snippet to a temp file, scans it with the
relevant scanner function, and asserts the expected rule IDs fire (or don't).
"""

import sys
import os
import pathlib
import tempfile
import textwrap
import pytest

# Make the scripts directory importable
_SCRIPTS_DIR = pathlib.Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS_DIR))

import vuln_scanner as vs
from vuln_scanner import (
    scan_python_ast_taint,
    scan_structural_python,
    _build_func_summaries,
    scan_interprocedural,
    Path,
)


# ── helpers ──────────────────────────────────────────────────────────────────

def _write_tmp(code: str, suffix: int = 0) -> pathlib.Path:
    """Write *code* to a deterministic temp file and return its Path."""
    p = pathlib.Path(f"/tmp/test_scanner_{suffix}_{os.getpid()}.py")
    p.write_text(textwrap.dedent(code), encoding="utf-8")
    return p


def _rule_ids(findings) -> set:
    return {f.rule_id for f in findings}


def _cleanup(*paths):
    for p in paths:
        try:
            p.unlink()
        except FileNotFoundError:
            pass


# ── 1. Basic taint: request.args.get → cursor.execute → SQLi ─────────────────

def test_basic_taint_sqli():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            q = request.args.get("q")
            cursor.execute("SELECT * FROM t WHERE x = " + q)
    """
    p = _write_tmp(code, 1)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T in {ids}"
    finally:
        _cleanup(p)


# ── 2. Alias chain: tainted → var → sink ─────────────────────────────────────

def test_alias_chain_sqli():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            raw = request.args.get("id")
            processed = raw.strip()
            query = "SELECT * FROM users WHERE id = " + processed
            cursor.execute(query)
    """
    p = _write_tmp(code, 2)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T in {ids}"
    finally:
        _cleanup(p)


# ── 3. Container taint: tainted → list → extract → sink ───────────────────────

def test_container_taint_sqli():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            user_id = request.args.get("id")
            params = [user_id, "extra"]
            extracted = params[0]
            cursor.execute("SELECT * FROM t WHERE id = " + extracted)
    """
    p = _write_tmp(code, 3)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T in {ids}"
    finally:
        _cleanup(p)


# ── 4. Type sanitisation: int() should suppress taint for SQLi ───────────────

def test_int_sanitization_no_sqli():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            raw = request.args.get("id")
            safe_id = int(raw)
            cursor.execute("SELECT * FROM t WHERE id = " + str(safe_id))
    """
    p = _write_tmp(code, 4)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        # The int() call makes safe_id a numeric type; str(safe_id) then uses
        # safe_id — which _is_safe_transform handles at int() level.
        # The taint chain should be broken at int(raw) so SEC004T should not fire.
        assert "SEC004T" not in ids, (
            f"False positive: SEC004T fired even after int() sanitisation. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 5. pattern-not-inside: pickle.loads INSIDE try → should NOT fire SEC_PI001

def test_pickle_inside_try_no_pi001():
    code = """\
        import pickle

        def load_data(data):
            try:
                result = pickle.loads(data)
            except Exception:
                result = None
            return result
    """
    p = _write_tmp(code, 5)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC_PI001" not in ids, (
            f"False positive: SEC_PI001 fired for pickle.loads inside try. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 6. pattern-not-inside: pickle.loads OUTSIDE try → SHOULD fire SEC_PI001 ──

def test_pickle_outside_try_fires_pi001():
    code = """\
        import pickle

        def load_data(data):
            result = pickle.loads(data)
            return result
    """
    p = _write_tmp(code, 6)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC_PI001" in ids, (
            f"Expected SEC_PI001 for pickle.loads outside try. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 7. pattern-inside: requests.get(verify=False) inside function → SEC_PI008 ─

def test_requests_verify_false_inside_func_fires_pi008():
    code = """\
        import requests

        def fetch(url):
            resp = requests.get(url, verify=False)
            return resp.text
    """
    p = _write_tmp(code, 7)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC_PI008" in ids, (
            f"Expected SEC_PI008 for requests.get(verify=False) inside function. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 8a. Structural: yaml.load WITHOUT Loader → SHOULD fire SEC068S ────────────

def test_yaml_load_no_loader_fires():
    code = """\
        import yaml

        def parse(data):
            return yaml.load(data)
    """
    p = _write_tmp(code, 8)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC068S" in ids, (
            f"Expected SEC068S for yaml.load without Loader. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 8b. Structural: yaml.load WITH SafeLoader → should NOT fire SEC068S ───────

def test_yaml_load_with_safeloader_no_fire():
    code = """\
        import yaml

        def parse(data):
            return yaml.load(data, Loader=yaml.SafeLoader)
    """
    p = _write_tmp(code, 9)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC068S" not in ids, (
            f"False positive: SEC068S fired for yaml.load with SafeLoader. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 9. Structural: subprocess shell=True → SHOULD fire SEC080S ────────────────

def test_subprocess_shell_true_fires():
    code = """\
        import subprocess

        def run_cmd(cmd):
            subprocess.run(cmd, shell=True)
    """
    p = _write_tmp(code, 10)
    try:
        findings = scan_structural_python(p)
        ids = _rule_ids(findings)
        assert "SEC080S" in ids, (
            f"Expected SEC080S for subprocess.run(shell=True). ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 10. AugAssign alias: buf += tainted → buf tainted at sink ─────────────────

def test_augassign_taint_propagation():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            user = request.args.get("name")
            buf = "SELECT * FROM t WHERE name = '"
            buf += user
            cursor.execute(buf)
    """
    p = _write_tmp(code, 11)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T after AugAssign taint chain. ids={ids}"
    finally:
        _cleanup(p)


# ── 11. Container mutation: lst.append(tainted) → lst tainted ─────────────────

def test_list_append_taint_propagation():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            user = request.args.get("name")
            parts = []
            parts.append(user)
            query = "SELECT * FROM t WHERE name = " + parts[0]
            cursor.execute(query)
    """
    p = _write_tmp(code, 12)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T after list.append taint chain. ids={ids}"
    finally:
        _cleanup(p)


# ── 12. Conditional assign: x = tainted if cond else safe → x tainted ─────────

def test_conditional_assign_taint_propagation():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            raw = request.args.get("id")
            val = raw if raw else "default"
            cursor.execute("SELECT * FROM t WHERE id = " + val)
    """
    p = _write_tmp(code, 13)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, (
            f"Expected SEC004T after conditional assign taint chain. ids={ids}"
        )
    finally:
        _cleanup(p)


# ── 13. Cross-file / interprocedural: tainted arg passed to sink func ─────────

def test_interprocedural_taint():
    """
    File A defines process(user_input) which calls cursor.execute with the param.
    File B gets request input and calls process() — interprocedural should flag it.
    """
    code_a = """\
        import sqlite3

        def process(user_input):
            conn = sqlite3.connect("db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM t WHERE x = " + user_input)
    """
    code_b = """\
        from flask import request

        def view():
            name = request.args.get("name")
            process(name)
    """
    pa = _write_tmp(code_a, 14)
    pb = _write_tmp(code_b, 15)
    try:
        summaries = _build_func_summaries([pa, pb])
        findings = scan_interprocedural(pb, summaries)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, (
            f"Expected SEC004T in interprocedural analysis. ids={ids}, summaries={list(summaries.keys())}"
        )
    finally:
        _cleanup(pa, pb)


# ── JS taint tests ─────────────────────────────────────────────────────────────

import textwrap

def _write_js_tmp(code: str, n: int) -> pathlib.Path:
    p = pathlib.Path(f"/tmp/test_scanner_js_{n}.js")
    p.write_text(textwrap.dedent(code))
    return p


def _cleanup_js(*paths):
    for p in paths:
        try:
            p.unlink()
        except FileNotFoundError:
            pass


def _skip_if_no_esprima():
    try:
        import esprima  # noqa: F401
    except ImportError:
        pytest.skip("esprima not installed")


# ── JS 1: Basic Express SQLi ─────────────────────────────────────────────────

def test_js_basic_sqli():
    _skip_if_no_esprima()
    code = """\
        app.get('/user', function(req, res) {
            const id = req.query.id;
            db.query("SELECT * FROM users WHERE id = " + id);
        });
    """
    p = _write_js_tmp(code, 1)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T for basic JS SQLi. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 2: Destructuring taint ─────────────────────────────────────────────────

def test_js_destructuring_sqli():
    _skip_if_no_esprima()
    code = """\
        app.post('/login', (req, res) => {
            const { username } = req.body;
            db.execute(`SELECT * FROM users WHERE name='${username}'`);
        });
    """
    p = _write_js_tmp(code, 2)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T via destructuring. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 3: parseInt suppresses taint (no SQLi) ─────────────────────────────────

def test_js_parseint_suppresses_taint():
    _skip_if_no_esprima()
    code = """\
        app.get('/safe', function(req, res) {
            const rawId = req.query.id;
            const safeId = parseInt(rawId, 10);
            db.query("SELECT * FROM users WHERE id = " + safeId);
        });
    """
    p = _write_js_tmp(code, 3)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC004T" not in ids, f"Expected no SQLi after parseInt. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 4: innerHTML XSS ────────────────────────────────────────────────────────

def test_js_innerhtml_xss():
    _skip_if_no_esprima()
    code = """\
        function renderName(req) {
            const name = req.query.name;
            document.getElementById('out').innerHTML = name;
        }
    """
    p = _write_js_tmp(code, 4)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC006T" in ids, f"Expected SEC006T for innerHTML XSS. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 5: Command injection ───────────────────────────────────────────────────

def test_js_command_injection():
    _skip_if_no_esprima()
    code = """\
        app.post('/ping', (req, res) => {
            const host = req.body.host;
            exec(`ping -c 1 ${host}`, (err, out) => res.send(out));
        });
    """
    p = _write_js_tmp(code, 5)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC003T" in ids, f"Expected SEC003T for command injection. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 6: Path traversal ──────────────────────────────────────────────────────

def test_js_path_traversal():
    _skip_if_no_esprima()
    code = """\
        app.get('/download', (req, res) => {
            const file = req.params.filename;
            fs.readFile('/uploads/' + file, (err, data) => res.send(data));
        });
    """
    p = _write_js_tmp(code, 6)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC035T" in ids, f"Expected SEC035T for path traversal. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 7: Open redirect ───────────────────────────────────────────────────────

def test_js_open_redirect():
    _skip_if_no_esprima()
    code = """\
        app.get('/redirect', (req, res) => {
            res.redirect(req.query.url);
        });
    """
    p = _write_js_tmp(code, 7)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC056T" in ids, f"Expected SEC056T for open redirect. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 8: Inter-procedural taint ─────────────────────────────────────────────

def test_js_interprocedural_taint():
    _skip_if_no_esprima()
    code = """\
        function buildQuery(input) {
            db.query("SELECT * FROM logs WHERE msg = '" + input + "'");
        }
        app.get('/log', (req, res) => {
            const msg = req.query.msg;
            buildQuery(msg);
        });
    """
    p = _write_js_tmp(code, 8)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T via JS inter-proc. ids={ids}"
    finally:
        _cleanup_js(p)


# ── JS 9: Nested if scope taint ───────────────────────────────────────────────

def test_js_nested_if_scope():
    _skip_if_no_esprima()
    code = """\
        app.get('/search', function(req, res) {
            const term = req.params.q;
            if (term) {
                db.query("SELECT * FROM items WHERE name LIKE '%" + term + "%'");
            }
        });
    """
    p = _write_js_tmp(code, 9)
    try:
        findings = vs.scan_js_ast(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T in nested if scope. ids={ids}"
    finally:
        _cleanup_js(p)


# ── Object / field taint tests ────────────────────────────────────────────────

# ── OBJ 1: within-method instance attribute taint ────────────────────────────

def test_within_method_attr_taint():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect('db')
            cursor = conn.cursor()
            obj = type('O', (), {})()
            obj.data = request.args.get('q')
            cursor.execute("SELECT * FROM t WHERE q = " + obj.data)
    """
    p = _write_tmp(code, 20)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T for within-method attr. ids={ids}"
    finally:
        _cleanup(p)


# ── OBJ 2: cross-method class field taint ────────────────────────────────────

def test_cross_method_class_field_taint():
    code = """\
        from flask import request
        import sqlite3

        class Handler:
            def set_input(self, req):
                self.query = req.args.get('q')

            def execute(self):
                conn = sqlite3.connect('db')
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM t WHERE q = " + self.query)
    """
    p = _write_tmp(code, 21)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T for cross-method class field. ids={ids}"
    finally:
        _cleanup(p)


# ── OBJ 3: subscript assignment taint ────────────────────────────────────────

def test_subscript_assignment_taint():
    code = """\
        from flask import request
        import sqlite3

        def view():
            conn = sqlite3.connect('db')
            cursor = conn.cursor()
            data = {}
            data['name'] = request.args.get('name')
            cursor.execute("SELECT * FROM users WHERE name = '" + data['name'] + "'")
    """
    p = _write_tmp(code, 22)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T for subscript assignment taint. ids={ids}"
    finally:
        _cleanup(p)


# ── OBJ 4: constructor stores field, another method uses it ──────────────────

def test_constructor_field_to_method_taint():
    code = """\
        from flask import request
        import subprocess

        class CmdHandler:
            def __init__(self, req):
                self.host = req.args.get('host')

            def ping(self):
                subprocess.run(['ping', '-c1', self.host])
    """
    p = _write_tmp(code, 23)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert ids, f"Expected a finding for constructor field → method. ids={ids}"
    finally:
        _cleanup(p)


# ── OBJ 5: multi-method chain (set → transform → use) ────────────────────────

def test_multi_method_field_chain():
    code = """\
        from flask import request
        import sqlite3

        class DataStore:
            def load(self, req):
                self.raw = req.args.get('search')

            def prepare(self):
                self.query_str = "SELECT * FROM t WHERE name = '" + self.raw + "'"

            def run(self):
                conn = sqlite3.connect('db')
                conn.cursor().execute(self.query_str)
    """
    p = _write_tmp(code, 24)
    try:
        findings = scan_python_ast_taint(p)
        ids = _rule_ids(findings)
        assert "SEC004T" in ids, f"Expected SEC004T for multi-method chain. ids={ids}"
    finally:
        _cleanup(p)
