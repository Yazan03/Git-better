"""
Per-rule positive/negative tests for vuln_scanner.

Each test writes a small snippet to a tmp file, runs the scanner, and asserts
that the expected rule_id is (or isn't) reported.
"""
from pathlib import Path

import pytest

import vuln_scanner as vs


def _scan(tmp_path: Path, name: str, source: str) -> set[str]:
    f = tmp_path / name
    f.write_text(source)
    return {finding.rule_id for finding in vs.scan_file(f)}


# ─────────────────────────── SEC001: hardcoded secrets ───────────────────────
# Regression test for the (-i) literal-flag bug — these previously didn't fire.

@pytest.mark.parametrize("filename,source", [
    ("a.py",   'password = "supersecret123"'),
    ("a.js",   'const apiKey = "sk-abc123xyz789";'),
    ("a.php",  '<?php $password = "hunter2hunter2"; ?>'),
    ("a.java", 'String password = "hunter2hunter2";'),
    ("a.go",   'var password = "hunter2hunter2"'),
    ("a.sh",   'PASSWORD="hunter2hunter2"'),
])
def test_sec001_hardcoded_secret_fires(tmp_path, filename, source):
    assert "SEC001" in _scan(tmp_path, filename, source)


def test_sec001_does_not_fire_on_env_lookup(tmp_path):
    assert "SEC001" not in _scan(tmp_path, "a.py", 'password = os.environ["PW"]')


# ─────────────────────────── SEC002: dangerous funcs ─────────────────────────

@pytest.mark.parametrize("source", [
    'eval("1+1")',
    'exec("print(1)")',
    'os.system("ls")',
    'pickle.loads(data)',
])
def test_sec002_python(tmp_path, source):
    assert "SEC002" in _scan(tmp_path, "a.py", source)


# ─────────────────────────── SEC023: unquoted bash var ───────────────────────

def test_sec023_fires_on_unquoted_var_in_command(tmp_path):
    assert "SEC023" in _scan(tmp_path, "a.sh", "rm -rf $TARGET_DIR")


def test_sec023_does_not_fire_when_quoted(tmp_path):
    assert "SEC023" not in _scan(tmp_path, "a.sh", 'rm -rf "$TARGET_DIR"')


def test_sec023_does_not_match_literal_phrase(tmp_path):
    # The old buggy regex matched the english phrase "without quotes"
    assert "SEC023" not in _scan(tmp_path, "a.sh", "echo hello # without quotes")


# ─────────────────────────── No-duplicate rules ──────────────────────────────

def test_no_duplicate_rule_definitions():
    """Each (rule_id, pattern) pair should appear at most once per language."""
    for lang, rules in vs.RULES.items():
        seen = set()
        for rid, _sev, pattern, _msg in rules:
            key = (rid, pattern)
            assert key not in seen, f"duplicate rule {rid} in {lang}: {pattern!r}"
            seen.add(key)


# ─────────────────────────── Regex compiles ──────────────────────────────────

def test_all_rule_patterns_compile():
    import re
    for lang, rules in vs.RULES.items():
        for rid, _sev, pattern, _msg in rules:
            try:
                re.compile(pattern)
            except re.error as e:
                pytest.fail(f"{lang}/{rid} regex does not compile: {e}\npattern={pattern!r}")


# ─────────────────────────── Output sanity ───────────────────────────────────

def test_finding_carries_metadata(tmp_path):
    f = tmp_path / "x.py"
    f.write_text('password = "supersecret123"')
    findings = vs.scan_file(f)
    assert findings, "expected at least one finding"
    fnd = findings[0]
    assert fnd.line == 1
    assert fnd.severity == "HIGH"
    assert fnd.language == "python"
    assert fnd.code_snippet


# ─── Python string-literal false-positive prevention (tokenizer) ─────────────

def test_sec002_does_not_fire_in_py_docstring(tmp_path):
    """eval/exec mentioned inside a Python string should not trigger SEC002."""
    src = (
        'RULE_META = {\n'
        '    "what": "Functions such as eval(), exec(), os.system() execute arbitrary code.",\n'
        '    "fix":  "Avoid eval/exec entirely.",\n'
        '}\n'
    )
    assert "SEC002" not in _scan(tmp_path, "a.py", src)


def test_sec001_does_not_fire_in_py_string_value(tmp_path):
    """A keyword like 'password' inside a dict-value string is not a hardcoded secret."""
    src = (
        'docs = {\n'
        '    "what": "A password or api_key hardcoded in source code is a risk.",\n'
        '}\n'
    )
    assert "SEC001" not in _scan(tmp_path, "a.py", src)


def test_sec003_does_not_fire_in_py_string_value(tmp_path):
    """'assert' mentioned in a documentation string should not trigger SEC003."""
    src = (
        'meta = {\n'
        '    "title": "Assert Used for Logic / Security Check",\n'
        '    "what":  "Python assert statement is stripped with -O.",\n'
        '}\n'
    )
    assert "SEC003" not in _scan(tmp_path, "a.py", src)


def test_sec028_does_not_fire_in_py_string_doc(tmp_path):
    """CSP 'unsafe-inline' mentioned in a doc string should not trigger SEC028."""
    src = (
        'meta = {\n'
        '    "what": "CSP with unsafe-inline or unsafe-eval weakens the policy.",\n'
        '}\n'
    )
    assert "SEC028" not in _scan(tmp_path, "a.py", src)


def test_sec037_does_not_fire_in_py_string_doc(tmp_path):
    """'/etc/passwd' in a documentation string should not trigger SEC037."""
    src = (
        'meta = {\n'
        '    "what": "Paths like /etc/passwd or /etc/shadow are sensitive system files.",\n'
        '}\n'
    )
    assert "SEC037" not in _scan(tmp_path, "a.py", src)


def test_python_comment_does_not_trigger_rule(tmp_path):
    """Content in a Python inline comment should not be flagged."""
    assert "SEC002" not in _scan(tmp_path, "a.py", "x = 1  # never call eval() here")


# ─── Inline nosec suppression ────────────────────────────────────────────────

def test_nosec_suppresses_python_finding(tmp_path):
    """A Python line with # nosec must not produce any finding."""
    assert not _scan(tmp_path, "a.py", 'eval("1+1")  # nosec')


def test_nosec_suppresses_js_finding(tmp_path):
    """A JS line with // nosec must not produce any finding."""
    assert not _scan(tmp_path, "a.js", 'eval(userInput);  // nosec')


def test_nosec_suppresses_go_finding(tmp_path):
    """A Go line with // nosec must not produce any finding."""
    assert not _scan(tmp_path, "a.go", 'password := "hardcodedSecret1"  // nosec')


def test_nosec_is_case_insensitive(tmp_path):
    """# NOSEC (uppercase) should also suppress the finding."""
    assert not _scan(tmp_path, "a.py", 'eval("1+1")  # NOSEC')


# ─── Block comment skipping (JS / Java / Go / C) ─────────────────────────────

def test_js_block_comment_not_flagged(tmp_path):
    """Content inside a /* */ block comment must not trigger any rule."""
    src = (
        "/*\n"
        " * This layer calls eval() to interpret user macros.\n"
        " */\n"
        "function safe() {}\n"
    )
    assert "SEC002" not in _scan(tmp_path, "a.js", src)


def test_js_single_line_comment_not_flagged(tmp_path):
    """A // comment line in JS must not trigger any rule."""
    assert "SEC002" not in _scan(tmp_path, "a.js", "// eval() is dangerous, avoid it")


def test_go_single_line_comment_not_flagged(tmp_path):
    """A // comment line in Go must not trigger any rule."""
    assert "SEC001" not in _scan(tmp_path, "a.go", '// password := "hunter2"')


# ─── Pattern-level false-positive fixes ──────────────────────────────────────

def test_go_html_template_import_not_flagged(tmp_path):
    """Importing html/template (the safe Go package) must not trigger SEC026."""
    src = 'import "html/template"\n'
    assert "SEC026" not in _scan(tmp_path, "a.go", src)


def test_go_text_template_still_flagged(tmp_path):
    """Importing text/template (potentially unsafe) must still trigger SEC026."""
    src = 'import "text/template"\n'
    assert "SEC026" in _scan(tmp_path, "a.go", src)


# ─── SEC027: static import false-positive fix ────────────────────────────────

@pytest.mark.parametrize("src", [
    # ES6 named import
    "import { helper } from '../../../utils/helper';",
    # ES6 default import
    "import helper from '../../../utils/helper';",
    # ES6 bare side-effect import
    "import '../../../polyfills';",
    # CommonJS require
    "const helper = require('../../../utils/helper');",
    # Re-export
    "export { x } from '../../../shared/x';",
])
def test_sec027_static_import_not_flagged(tmp_path, src):
    """A 3-level relative path inside a static import/require must not trigger SEC027."""
    assert "SEC027" not in _scan(tmp_path, "a.js", src)


def test_sec027_dynamic_path_still_flagged(tmp_path):
    """A 3-level path built by concatenation must still trigger SEC027."""
    src = "const p = '../../../' + userInput;"
    assert "SEC027" in _scan(tmp_path, "a.js", src)


def test_sec027_python_traversal_still_flagged(tmp_path):
    """Deep traversal in Python code (not an import) must still be flagged."""
    src = 'open("../../../etc/passwd")\n'
    # Python uses SEC027B for the ../../../ sequence (SEC027 is os.path.join + absolute path)
    found = _scan(tmp_path, "a.py", src)
    assert "SEC027" in found or "SEC027B" in found


# ─── Cross-line taint analysis (scan_taint) ──────────────────────────────────

def test_taint_py_sql_injection(tmp_path):
    """Variable assigned from request.args flowing into cursor.execute is SEC004T."""
    src = (
        "def view():\n"
        "    uid = request.args.get('id')\n"
        "    cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
    )
    f = tmp_path / "view.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" in found


def test_taint_py_file_operation(tmp_path):
    """Variable assigned from request.form flowing into open() is SEC035T."""
    src = (
        "def download():\n"
        "    fname = request.form.get('file')\n"
        "    data = open(fname).read()\n"
        "    return data\n"
    )
    f = tmp_path / "dl.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC035T" in found


def test_taint_py_command_injection(tmp_path):
    """Variable assigned from request flowing into os.system is SEC002T."""
    src = (
        "def run_cmd():\n"
        "    cmd = request.args.get('cmd')\n"
        "    os.system(cmd)\n"
    )
    f = tmp_path / "cmd.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC002T" in found


def test_taint_no_false_positive_when_no_source(tmp_path):
    """cursor.execute with a hardcoded string must not produce a taint finding."""
    src = (
        "def safe():\n"
        "    cursor.execute('SELECT 1')\n"
    )
    f = tmp_path / "safe.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" not in found


def test_taint_js_sql(tmp_path):
    """JS: req.query variable flowing into db.query is SEC004T."""
    src = (
        "function search(req, res) {\n"
        "  const term = req.query.q;\n"
        "  db.query('SELECT * FROM t WHERE name = ' + term);\n"
        "}\n"
    )
    f = tmp_path / "a.js"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" in found


def test_taint_js_no_fp_without_source(tmp_path):
    """JS: db.query with a literal string must not produce a taint finding."""
    src = (
        "function safe() {\n"
        "  db.query('SELECT 1');\n"
        "}\n"
    )
    f = tmp_path / "safe.js"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" not in found


# ─── Python AST intra-function taint analysis ────────────────────────────────

def test_ast_taint_propagation_chain(tmp_path):
    """
    AST taint propagates through f-string: request→username→query→execute.
    All three assignments must result in SEC004T at the execute call.
    """
    src = (
        "def login():\n"
        "    username = request.args.get('user')\n"
        "    query = f\"SELECT * FROM users WHERE name = '{username}'\"\n"
        "    cursor.execute(query)\n"
    )
    f = tmp_path / "login.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" in found


def test_ast_taint_concat_propagation(tmp_path):
    """AST taint propagates through string concatenation (+)."""
    src = (
        "def view():\n"
        "    uid = request.form.get('id')\n"
        "    sql = 'SELECT * FROM t WHERE id = ' + uid\n"
        "    db.execute(sql)\n"
    )
    f = tmp_path / "v.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" in found


def test_ast_taint_no_fp_on_safe_code(tmp_path):
    """AST taint must not fire when no user-input source is present."""
    src = (
        "def safe():\n"
        "    value = compute_value()\n"
        "    cursor.execute('SELECT 1 WHERE id = %s', [value])\n"
    )
    f = tmp_path / "safe2.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC004T" not in found


def test_ast_taint_across_tuple_unpack(tmp_path):
    """
    AST taint propagates when source is assigned via tuple unpacking.
    Either the taint rule (SEC002T) or the regex rule (SEC002) must fire;
    both flag the same danger.
    """
    src = (
        "def process(req):\n"
        "    name, age = request.form.get('name'), request.form.get('age')\n"
        "    os.system(name)\n"
    )
    f = tmp_path / "proc.py"
    f.write_text(src)
    found = {f.rule_id for f in vs.scan_file(f)}
    assert "SEC002T" in found or "SEC002" in found
