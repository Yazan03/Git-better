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
