#!/usr/bin/env python3
"""
Multi-language vulnerability scanner.
Supports: Python, JavaScript/TypeScript, PHP, Java, Go, Bash, C, Dockerfile, GitHub Actions
"""
import ast
import concurrent.futures
import io
import math
import re
import json
import subprocess
import threading
import tokenize
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, asdict, field


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    rule_id: str
    language: str
    message: str
    code_snippet: str = ""
    confidence: str = "LOW"
    cwe: str = ""
    owasp: str = ""
    ai_explanation: str = ""


# ── CWE + OWASP mapping ───────────────────────────────────────────────────────

RULE_META: dict[str, tuple[str, str]] = {
    "SEC001":  ("CWE-798", "A07:2021"),
    "SEC002":  ("CWE-78",  "A03:2021"),
    "SEC002T": ("CWE-78",  "A03:2021"),
    "SEC003":  ("CWE-617", "A05:2021"),
    "SEC004":  ("CWE-89",  "A03:2021"),
    "SEC004T": ("CWE-89",  "A03:2021"),
    "SEC005":  ("CWE-327", "A02:2021"),
    "SEC006":  ("CWE-79",  "A03:2021"),
    "SEC006T": ("CWE-79",  "A03:2021"),
    "SEC007":  ("CWE-79",  "A03:2021"),
    "SEC008":  ("CWE-338", "A02:2021"),
    "SEC009":  ("CWE-319", "A02:2021"),
    "SEC010":  ("CWE-532", "A09:2021"),
    "SEC011":  ("CWE-20",  "A03:2021"),
    "SEC012":  ("CWE-78",  "A03:2021"),
    "SEC013":  ("CWE-327", "A02:2021"),
    "SEC014":  ("CWE-209", "A05:2021"),
    "SEC015":  ("CWE-78",  "A03:2021"),
    "SEC016":  ("CWE-502", "A08:2021"),
    "SEC017":  ("CWE-209", "A05:2021"),
    "SEC018":  ("CWE-338", "A02:2021"),
    "SEC019":  ("CWE-532", "A09:2021"),
    "SEC020":  ("CWE-295", "A02:2021"),
    "SEC021":  ("CWE-78",  "A03:2021"),
    "SEC022":  ("CWE-732", "A01:2021"),
    "SEC023":  ("CWE-78",  "A03:2021"),
    "SEC024":  ("CWE-176", "A03:2021"),
    "SEC025":  ("CWE-176", "A03:2021"),
    "SEC026":  ("CWE-94",  "A03:2021"),
    "SEC026B": ("CWE-94",  "A03:2021"),
    "SEC026C": ("CWE-94",  "A03:2021"),
    "SEC026T": ("CWE-94",  "A03:2021"),
    "SEC027":  ("CWE-22",  "A01:2021"),
    "SEC027B": ("CWE-22",  "A01:2021"),
    "SEC028":  ("CWE-693", "A05:2021"),
    "SEC029":  ("CWE-502", "A08:2021"),
    "SEC030":  ("CWE-502", "A08:2021"),
    "SEC031":  ("CWE-502", "A08:2021"),
    "SEC031B": ("CWE-502", "A08:2021"),
    "SEC032":  ("CWE-502", "A08:2021"),
    "SEC033":  ("CWE-434", "A04:2021"),
    "SEC033B": ("CWE-434", "A04:2021"),
    "SEC034":  ("CWE-434", "A04:2021"),
    "SEC035":  ("CWE-22",  "A01:2021"),
    "SEC035B": ("CWE-22",  "A01:2021"),
    "SEC035C": ("CWE-22",  "A01:2021"),
    "SEC035T": ("CWE-22",  "A01:2021"),
    "SEC036":  ("CWE-73",  "A01:2021"),
    "SEC037":  ("CWE-22",  "A01:2021"),
    "SEC038":  ("CWE-22",  "A01:2021"),
    "SEC039":  ("CWE-22",  "A01:2021"),
    "SEC040":  ("CWE-22",  "A01:2021"),
    "SEC041":  ("CWE-22",  "A01:2021"),
    "SEC041B": ("CWE-22",  "A01:2021"),
    "SEC042":  ("CWE-22",  "A01:2021"),
    "SEC043":  ("CWE-347", "A02:2021"),
    "SEC044":  ("CWE-347", "A02:2021"),
    "SEC044B": ("CWE-347", "A02:2021"),
    "SEC044C": ("CWE-347", "A02:2021"),
    "SEC046":  ("CWE-347", "A02:2021"),
    "SEC046B": ("CWE-347", "A02:2021"),
    "SEC048":  ("CWE-20",  "A03:2021"),
    "SEC049":  ("CWE-20",  "A03:2021"),
    "SEC050":  ("CWE-347", "A02:2021"),
    "SEC051":  ("CWE-90",  "A03:2021"),
    "SEC051B": ("CWE-90",  "A03:2021"),
    "SEC052":  ("CWE-90",  "A03:2021"),
    "SEC053":  ("CWE-90",  "A03:2021"),
    "SEC053B": ("CWE-90",  "A03:2021"),
    "SEC054":  ("CWE-943", "A03:2021"),
    "SEC055":  ("CWE-943", "A03:2021"),
    "SEC056":  ("CWE-601", "A01:2021"),
    "SEC056T": ("CWE-601", "A01:2021"),
    "SEC057":  ("CWE-943", "A03:2021"),
    "SEC057B": ("CWE-943", "A03:2021"),
    "SEC060":  ("CWE-119", "A05:2021"),
    "SEC060B": ("CWE-119", "A05:2021"),
    "SEC060C": ("CWE-119", "A05:2021"),
    "SEC060D": ("CWE-119", "A05:2021"),
    "SEC061":  ("CWE-134", "A03:2021"),
    "SEC062":  ("CWE-693", "A05:2021"),
    "SEC062B": ("CWE-693", "A05:2021"),
    "SEC062C": ("CWE-693", "A05:2021"),
    "SEC062D": ("CWE-693", "A05:2021"),
    "SEC063":  ("CWE-693", "A05:2021"),
    "SEC063B": ("CWE-693", "A05:2021"),
    "SEC064":  ("CWE-693", "A05:2021"),
    "SEC064B": ("CWE-693", "A05:2021"),
    "SEC064C": ("CWE-693", "A05:2021"),
    "SEC064D": ("CWE-693", "A05:2021"),
    "SEC064E": ("CWE-693", "A05:2021"),
    "SEC065":  ("CWE-416", "A06:2021"),
    # SEC066-SEC200: New rules from Semgrep open-source conversions
    "SEC066":  ("CWE-918", "A10:2021"),   # SSRF - Python requests with user input
    "SEC067":  ("CWE-611", "A05:2021"),   # XXE - xml import without defusedxml
    "SEC068":  ("CWE-502", "A08:2021"),   # YAML injection - yaml.load unsafe
    "SEC069":  ("CWE-502", "A08:2021"),   # Pickle/marshal unsafe
    "SEC070":  ("CWE-352", "A01:2021"),   # Django CSRF exempt
    "SEC071":  ("CWE-89",  "A03:2021"),   # Django raw SQL
    "SEC072":  ("CWE-798", "A07:2021"),   # Django DEBUG=True
    "SEC073":  ("CWE-798", "A07:2021"),   # Flask debug=True
    "SEC074":  ("CWE-327", "A02:2021"),   # ECB mode cipher
    "SEC075":  ("CWE-327", "A02:2021"),   # Weak key size RSA/AES
    "SEC076":  ("CWE-327", "A02:2021"),   # DES/3DES/RC4/Blowfish
    "SEC077":  ("CWE-208", "A02:2021"),   # Timing attack - non-constant-time comparison
    "SEC078":  ("CWE-400", "A05:2021"),   # ReDoS - user-controlled regex
    "SEC079":  ("CWE-377", "A01:2021"),   # Insecure temp file (mktemp)
    "SEC080":  ("CWE-78",  "A03:2021"),   # subprocess with shell=True
    "SEC081":  ("CWE-295", "A02:2021"),   # SSL weak protocols
    "SEC082":  ("CWE-295", "A02:2021"),   # requests verify=False / check_hostname=False
    "SEC083":  ("CWE-611", "A05:2021"),   # XXE - lxml/xml.sax without safe settings
    "SEC084":  ("CWE-776", "A05:2021"),   # XML bomb / billion laughs
    "SEC085":  ("CWE-327", "A02:2021"),   # hashlib.new with weak algorithm
    "SEC086":  ("CWE-94",  "A03:2021"),   # Prototype pollution JS
    "SEC087":  ("CWE-400", "A05:2021"),   # ReDoS - JS new RegExp with user input
    "SEC088":  ("CWE-611", "A05:2021"),   # XXE - JS DOMParser/xml2js
    "SEC089":  ("CWE-502", "A08:2021"),   # JS insecure deserialization node-serialize
    "SEC090":  ("CWE-346", "A07:2021"),   # CORS wildcard with credentials
    "SEC091":  ("CWE-327", "A02:2021"),   # JS crypto createCipher deprecated
    "SEC092":  ("CWE-918", "A10:2021"),   # PHP SSRF curl_init with user URL
    "SEC093":  ("CWE-502", "A08:2021"),   # PHP type juggling loose comparison
    "SEC094":  ("CWE-89",  "A03:2021"),   # PHP extract/parse_str injection
    "SEC095":  ("CWE-94",  "A03:2021"),   # PHP preg_replace /e modifier
    "SEC096":  ("CWE-327", "A02:2021"),   # PHP openssl ECB / mcrypt
    "SEC097":  ("CWE-295", "A02:2021"),   # PHP curl SSL verification disabled
    "SEC098":  ("CWE-611", "A05:2021"),   # Java XXE - DocumentBuilderFactory
    "SEC099":  ("CWE-918", "A10:2021"),   # Java SSRF - new URL(userInput)
    "SEC100":  ("CWE-502", "A08:2021"),   # Java XMLDecoder/XStream deserialization
    "SEC101":  ("CWE-117", "A09:2021"),   # Java log injection
    "SEC102":  ("CWE-327", "A02:2021"),   # Java AES/ECB cipher
    "SEC103":  ("CWE-918", "A10:2021"),   # Go SSRF http.Get with variable
    "SEC104":  ("CWE-327", "A02:2021"),   # Go DES/RC4/MD5 usage
    "SEC105":  ("CWE-295", "A02:2021"),   # Go TLS InsecureSkipVerify
    "SEC106":  ("CWE-94",  "A03:2021"),   # Go text/template with user input
    "SEC107":  ("CWE-117", "A09:2021"),   # Go log injection
    "SEC108":  ("CWE-918", "A10:2021"),   # Bash curl/wget to variable URL
    "SEC109":  ("CWE-20",  "A03:2021"),   # Bash IFS tampering
    "SEC110":  ("CWE-78",  "A03:2021"),   # Bash command substitution with user input
    "SEC111":  ("CWE-502", "A08:2021"),   # JS yaml.load unsafe (js-yaml)
    "SEC112":  ("CWE-22",  "A01:2021"),   # Express path traversal sendFile
    "SEC113":  ("CWE-208", "A02:2021"),   # JS timing attack token comparison
    "SEC114":  ("CWE-346", "A07:2021"),   # CORS Access-Control-Allow-Origin wildcard
    "SEC115":  ("CWE-776", "A05:2021"),   # xmlrpc import
    "SEC116":  ("CWE-327", "A02:2021"),   # MD4/DES in Python cryptography library
    "SEC117":  ("CWE-377", "A01:2021"),   # Go insecure tmp file creation
    "SEC118":  ("CWE-502", "A08:2021"),   # Java Jackson enableDefaultTyping
    "SEC119":  ("CWE-502", "A08:2021"),   # Java SnakeYAML unsafe constructor
    "SEC120":  ("CWE-94",  "A03:2021"),   # Java SpEL injection
    "SEC121":  ("CWE-798", "A07:2021"),   # Django/Flask SECRET_KEY hardcoded
    "SEC122":  ("CWE-117", "A09:2021"),   # Python log injection
    "SEC123":  ("CWE-327", "A02:2021"),   # Python ssl weak protocol
    "SEC124":  ("CWE-78",  "A03:2021"),   # Python os.execv/os.execl family
    "SEC125":  ("CWE-22",  "A01:2021"),   # PHP phpinfo exposure
    "SEC126":  ("CWE-611", "A05:2021"),   # PHP XXE simplexml_load_string with LIBXML_NOENT
    "SEC127":  ("CWE-94",  "A03:2021"),   # PHP mb_ereg_replace with /e modifier
    "SEC128":  ("CWE-400", "A05:2021"),   # Go decompression bomb
    "SEC129":  ("CWE-451", "A04:2021"),   # JS X-Frame-Options misconfiguration
    "SEC130":  ("CWE-502", "A08:2021"),   # Python marshal.loads
    "SEC131":  ("CWE-327", "A02:2021"),   # Python Cryptography: weak algorithms
    "SEC132":  ("CWE-352", "A01:2021"),   # Flask/Django missing CSRF protection
    "SEC133":  ("CWE-918", "A10:2021"),   # Python urllib SSRF with user input
    "SEC134":  ("CWE-94",  "A03:2021"),   # PHP backtick operator
    "SEC135":  ("CWE-327", "A02:2021"),   # PHP crypt/rot13 weak crypto
    "SEC136":  ("CWE-94",  "A03:2021"),   # expr-eval CVE-2025-12735: RCE via evaluate() context injection
    # SEC001E: entropy-based secret detection
    "SEC001E": ("CWE-798", "A07:2021"),   # High-entropy string literal — possible secret
    # SEC2xx: Dockerfile security rules
    "SEC201":  ("CWE-269", "A05:2021"),   # Container runs as root
    "SEC202":  ("CWE-78",  "A03:2021"),   # curl/wget piped to shell
    "SEC203":  ("CWE-269", "A05:2021"),   # Privileged container
    "SEC204":  ("CWE-1104","A06:2021"),   # :latest tag — no version pinning
    "SEC205":  ("CWE-494", "A08:2021"),   # ADD with remote URL — no integrity check
    "SEC206":  ("CWE-732", "A01:2021"),   # chmod 777 in container layer
    "SEC207":  ("CWE-798", "A07:2021"),   # Secret in ENV instruction
    "SEC208":  ("CWE-295", "A02:2021"),   # TLS verification disabled in Dockerfile
    # SEC3xx: GitHub Actions security rules
    "SEC301":  ("CWE-78",  "A03:2021"),   # Script injection via github.event
    "SEC302":  ("CWE-269", "A05:2021"),   # pull_request_target pwn-request
    "SEC303":  ("CWE-1104","A06:2021"),   # Action pinned to mutable ref
    "SEC304":  ("CWE-78",  "A03:2021"),   # Shell step with injected expression
    "SEC305":  ("CWE-266", "A05:2021"),   # Self-hosted runner
    "SEC306":  ("CWE-532", "A09:2021"),   # Secret echoed in workflow log
    "SEC307":  ("CWE-732", "A05:2021"),   # write-all permissions
    "SEC308":  ("CWE-78",  "A03:2021"),   # env variable injection in run step
    # SEC*TS: Tree-sitter AST taint findings — PHP, Java, Go (HIGH confidence)
    "SEC004TS": ("CWE-89",  "A03:2021"),   # SQL injection (tree-sitter)
    "SEC002TS": ("CWE-78",  "A03:2021"),   # Command injection (tree-sitter)
    "SEC006TS": ("CWE-79",  "A03:2021"),   # XSS (tree-sitter)
    "SEC035TS": ("CWE-22",  "A01:2021"),   # Path traversal / LFI (tree-sitter)
    "SEC056TS": ("CWE-601", "A01:2021"),   # Open redirect (tree-sitter)
    "SEC066TS": ("CWE-918", "A10:2021"),   # SSRF (tree-sitter)
}

EXTENSION_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "javascript",
    ".jsx":  "javascript",
    ".tsx":  "javascript",
    ".php":  "php",
    ".java": "java",
    ".go":   "go",
    ".sh":   "bash",
    ".bash": "bash",
    ".mk":   "build",
    ".mak":  "build",
    ".make": "build",
    ".cmake": "build",
    ".c":    "c",
    ".h":    "c",
    # IaC formats detected via content/path in scan_file; listed here so
    # rglob in main() picks them up.
    ".yml":  "yaml_generic",
    ".yaml": "yaml_generic",
}

FILENAME_MAP = {
    "makefile": "build",
    "gnumakefile": "build",
    "cmakelists.txt": "build",
    # Dockerfile variants
    "dockerfile": "dockerfile",
    "dockerfile.dev": "dockerfile",
    "dockerfile.prod": "dockerfile",
    "dockerfile.test": "dockerfile",
    "dockerfile.ci": "dockerfile",
}


# ── Structural pattern engine ─────────────────────────────────────────────────
#
# Patterns are written in the target language syntax with two extensions:
#   $VAR   — metavariable: matches any AST node, binds to VAR
#   ...    — ellipsis: matches any sequence of arguments or statements
#
# Examples (Python):
#   eval($X)                       matches eval(anything)
#   $OBJ.execute($Q)               matches cursor.execute(q), db.execute(s), ...
#   subprocess.call($CMD, shell=True)  matches with literal shell=True kwarg
#   $X + $Y                        matches any binary addition
#   pickle.loads(...)              matches pickle.loads with any args
# ─────────────────────────────────────────────────────────────────────────────

_MV_PREFIX = "__mv_"          # prefix for metavariable sentinels in parsed AST
_ELLIPSIS_CALL = "__ell__"    # sentinel function name for ellipsis in arg lists


@dataclass
class StructuralRule:
    id: str
    language: str
    severity: str
    message: str
    cwe: str = ""
    owasp: str = ""
    # Compiled patterns (ast.AST for python, dict for javascript)
    pattern: object = None           # primary pattern
    pattern_not: list = field(default_factory=list)
    pattern_either: list = field(default_factory=list)
    pattern_inside: object = None
    pattern_not_inside: object = None
    stmt_pattern: object = None          # list[ast.stmt] for multi-line patterns
    # Metavariable conditions
    metavar_regex: dict = field(default_factory=dict)   # var -> compiled re.Pattern
    metavar_pattern: dict = field(default_factory=dict) # var -> compiled sub-pattern


def _norm_py_pattern(src: str) -> str:
    """
    Normalise a Python structural pattern string so ast.parse() accepts it.
    - $VAR  → __mv_VAR__
    - ...   (as a function argument) → __ell__()
    - try:  shorthand → try: ...\nexcept: ... (syntactically valid)
    """
    # Replace $VARNAME with __mv_VARNAME__ (metavariable)
    src = re.sub(r'\$([A-Z_][A-Z0-9_]*)', r'__mv_\1__', src)
    # Replace standalone ... in argument/element position with __ell__()
    src = re.sub(r'(?<![.\w])\.\.\.(?![.\w])', '__ell__()', src)
    return src




def _parse_py_pattern(src: str) -> ast.AST:
    """Parse a Python structural pattern string into an AST node."""
    normalised = _norm_py_pattern(src.strip())
    try:
        return ast.parse(normalised, mode='eval').body
    except SyntaxError as e:
        raise ValueError(f"Invalid structural pattern {src!r}: {e}") from e


def _is_mv(node: ast.AST) -> str | None:
    """Return the metavariable name if node is a metavariable, else None."""
    if isinstance(node, ast.Name) and node.id.startswith(_MV_PREFIX):
        return node.id[len(_MV_PREFIX):-2]  # strip __mv_ prefix and __ suffix
    return None


def _is_ellipsis_node(node: ast.AST) -> bool:
    """Return True if node is the ellipsis sentinel __ell__()."""
    return (isinstance(node, ast.Call) and
            isinstance(node.func, ast.Name) and
            node.func.id == _ELLIPSIS_CALL)


def _ast_equal(a: ast.AST, b: ast.AST) -> bool:
    """Structural equality of two AST nodes (for metavariable rebinding check)."""
    if type(a) != type(b):
        return False
    for field_name, val_a in ast.iter_fields(a):
        val_b = getattr(b, field_name, None)
        if isinstance(val_a, list):
            if not isinstance(val_b, list) or len(val_a) != len(val_b):
                return False
            if not all(_ast_equal(x, y) for x, y in zip(val_a, val_b)):
                return False
        elif isinstance(val_a, ast.AST):
            if not isinstance(val_b, ast.AST) or not _ast_equal(val_a, val_b):
                return False
        else:
            if val_a != val_b:
                return False
    return True


def match_py_pattern(
    pattern: ast.AST,
    node: ast.AST,
    bindings: dict | None = None,
) -> dict | None:
    """
    Try to match `pattern` against `node`.
    Returns updated bindings dict on success, None on failure.
    Bindings map metavariable names (without $ prefix) to matched AST nodes.
    """
    if bindings is None:
        bindings = {}

    # ── Metavariable ─────────────────────────────────────────────────────────
    mv_name = _is_mv(pattern)
    if mv_name is not None:
        if mv_name in bindings:
            # Metavar already bound — require structural equality
            return bindings if _ast_equal(bindings[mv_name], node) else None
        return {**bindings, mv_name: node}

    # ── Ellipsis sentinel ─────────────────────────────────────────────────────
    if _is_ellipsis_node(pattern):
        return bindings  # matches any single node

    # ── Constant / literal ────────────────────────────────────────────────────
    if isinstance(pattern, ast.Constant):
        if not isinstance(node, ast.Constant):
            return None
        return bindings if pattern.value == node.value else None

    # ── Type must match ───────────────────────────────────────────────────────
    if type(pattern) != type(node):
        return None

    # ── Recurse into fields ───────────────────────────────────────────────────
    current = bindings
    for field_name, pat_val in ast.iter_fields(pattern):
        code_val = getattr(node, field_name, None)

        if isinstance(pat_val, list):
            result = _match_py_sequence(pat_val, code_val or [], current)
            if result is None:
                return None
            current = result

        elif isinstance(pat_val, ast.AST):
            # Ellipsis in field position — wildcard, skip
            if _is_ellipsis_node(pat_val):
                pass
            else:
                mv = _is_mv(pat_val)
                if mv is not None:
                    # Metavar in field position — bind to whatever code_val is
                    if mv in current:
                        existing = current[mv]
                        ok = (existing is code_val) or (
                            isinstance(existing, ast.AST)
                            and isinstance(code_val, ast.AST)
                            and _ast_equal(existing, code_val)
                        )
                        if not ok:
                            return None
                    else:
                        current = {**current, mv: code_val}
                elif not isinstance(code_val, ast.AST):
                    return None
                else:
                    result = match_py_pattern(pat_val, code_val, current)
                    if result is None:
                        return None
                    current = result

        else:
            # Scalar field (str, int, bool, None…)
            # None in a pattern scalar field is a wildcard (matches anything)
            if pat_val is None:
                pass
            # String fields may encode metavariables as __mv_NAME__ strings
            elif (isinstance(pat_val, str)
                    and pat_val.startswith(_MV_PREFIX)
                    and pat_val.endswith('__')):
                mv = pat_val[len(_MV_PREFIX):-2]
                if mv in current:
                    if current[mv] != code_val:
                        return None
                else:
                    current = {**current, mv: code_val}
            elif pat_val != code_val:
                return None

    return current


def _match_py_sequence(
    pat_seq: list,
    code_seq: list,
    bindings: dict,
) -> dict | None:
    """
    Match a pattern sequence against a code sequence.
    Ellipsis nodes in the pattern match zero-or-more code elements.
    """
    if not pat_seq and not code_seq:
        return bindings

    if not pat_seq:
        return None  # pattern exhausted but code remains

    # Leading ellipsis (expression OR statement form) — try all prefix lengths
    if _is_ellipsis_node(pat_seq[0]) or (
        isinstance(pat_seq[0], ast.stmt) and _is_stmt_ellipsis(pat_seq[0])
    ):
        for skip in range(len(code_seq) + 1):
            result = _match_py_sequence(pat_seq[1:], code_seq[skip:], bindings)
            if result is not None:
                return result
        return None

    if not code_seq:
        return None  # code exhausted but pattern remains (no leading ellipsis)

    result = match_py_pattern(pat_seq[0], code_seq[0], bindings)
    if result is None:
        return None
    return _match_py_sequence(pat_seq[1:], code_seq[1:], result)


def find_py_pattern(
    pattern: ast.AST,
    tree: ast.AST,
) -> list[tuple[ast.AST, dict]]:
    """
    Walk `tree` and return all (node, bindings) pairs where `pattern` matches.
    """
    matches = []
    for node in ast.walk(tree):
        b = match_py_pattern(pattern, node)
        if b is not None:
            matches.append((node, b))
    return matches


# ── pattern-inside helpers ────────────────────────────────────────────────────

def _collect_inside_nodes(inside_pat, tree: ast.AST) -> list[ast.AST]:
    """Return every node in tree that matches inside_pat (expression or stmt list)."""
    if isinstance(inside_pat, list):
        # Statement sequence pattern — find_py_stmt_pattern returns (first_stmt, bindings)
        # The first_stmt is the compound statement node itself (Try, FunctionDef, etc.)
        return [first_stmt for first_stmt, _ in find_py_stmt_pattern(inside_pat, tree)]
    return [n for n in ast.walk(tree) if match_py_pattern(inside_pat, n) is not None]


def _is_descendant_of_any(node: ast.AST, ancestors: list[ast.AST]) -> bool:
    """Return True if node is a descendant (or is equal to) any node in ancestors."""
    for anc in ancestors:
        for desc in ast.walk(anc):
            if desc is node:
                return True
    return False


# ── Statement-level pattern matching ─────────────────────────────────────────

def _parse_py_pattern_flex(src: str) -> "tuple[ast.AST | None, list | None]":
    """
    Try parsing a pattern as an expression first, then as a statement sequence.
    Returns (expr_node, None) or (None, stmt_list).
    """
    normalised = _norm_py_pattern(src.strip())
    try:
        return ast.parse(normalised, mode='eval').body, None
    except SyntaxError:
        pass
    try:
        stmts = ast.parse(normalised, mode='exec').body
        if stmts:
            return None, stmts
    except SyntaxError:
        pass
    raise ValueError(f"Cannot parse structural pattern: {src!r}")


def _is_stmt_ellipsis(stmt: ast.stmt) -> bool:
    """Return True if a statement is a bare `...` — used as gap in stmt patterns."""
    if not isinstance(stmt, ast.Expr):
        return False
    v = stmt.value
    return (isinstance(v, ast.Constant) and v.value is ...) or _is_ellipsis_node(v)


def match_py_stmt_sequence(
    pat_stmts: list,
    code_stmts: list,
    bindings: dict,
) -> "dict | None":
    """
    Match a pattern statement list against a code statement list.
    Bare `...` statements match zero-or-more code statements (gap).
    """
    if not pat_stmts:
        # Pattern exhausted — matched the required subsequence
        return bindings
    if _is_stmt_ellipsis(pat_stmts[0]):
        for skip in range(len(code_stmts) + 1):
            result = match_py_stmt_sequence(pat_stmts[1:], code_stmts[skip:], bindings)
            if result is not None:
                return result
        return None
    if not code_stmts:
        return None
    result = match_py_pattern(pat_stmts[0], code_stmts[0], bindings)
    if result is None:
        return None
    return match_py_stmt_sequence(pat_stmts[1:], code_stmts[1:], result)


def find_py_stmt_pattern(
    pat_stmts: list,
    tree: ast.AST,
) -> "list[tuple[ast.stmt, dict]]":
    """
    Search all statement lists in the AST for the pattern sequence.
    Returns (first_matched_stmt, bindings) for each match.
    """
    results: list = []

    def _search(stmts: list) -> None:
        for start in range(len(stmts)):
            b = match_py_stmt_sequence(pat_stmts, stmts[start:], {})
            if b is not None:
                results.append((stmts[start], b))

    for node in ast.walk(tree):
        for _, val in ast.iter_fields(node):
            if isinstance(val, list) and val and isinstance(val[0], ast.stmt):
                _search(val)

    return results


# ── JS structural pattern matching ────────────────────────────────────────────

def _norm_js_pattern(src: str) -> str:
    """Normalise JS pattern: $VAR → __mv_VAR__, ... → __ell__()"""
    src = re.sub(r'\$([A-Z_][A-Z0-9_]*)', r'__mv_\1__', src)
    src = re.sub(r'(?<![.\w])\.\.\.(?![.\w])', '__ell__()', src)
    return src


def _parse_js_pattern(src: str) -> dict | None:
    """Parse a JS structural pattern string using esprima."""
    esp = _get_esprima()
    if esp is None:
        return None
    normalised = _norm_js_pattern(src.strip())
    try:
        tree = esp.parseScript(normalised, tolerant=True)
        body = tree.toDict()["body"]
        if body and body[0]["type"] == "ExpressionStatement":
            return body[0]["expression"]
        return body[0] if body else None
    except Exception:
        return None


def _js_is_mv(node: dict) -> str | None:
    """Return metavar name if this JS AST node is a metavar sentinel."""
    if node.get("type") == "Identifier":
        name = node.get("name", "")
        if name.startswith("__mv_") and name.endswith("__"):
            return name[5:-2]
    return None


def _js_is_ellipsis(node: dict) -> bool:
    return (node.get("type") == "CallExpression" and
            node.get("callee", {}).get("type") == "Identifier" and
            node.get("callee", {}).get("name") == "__ell__")


def match_js_pattern(
    pattern: dict,
    node: dict,
    bindings: dict | None = None,
) -> dict | None:
    """Match a JS pattern dict against a JS AST node dict."""
    if not isinstance(pattern, dict) or not isinstance(node, dict):
        return None
    if bindings is None:
        bindings = {}

    mv = _js_is_mv(pattern)
    if mv is not None:
        if mv in bindings:
            return bindings if bindings[mv] == node else None
        return {**bindings, mv: node}

    if _js_is_ellipsis(pattern):
        return bindings

    if pattern.get("type") != node.get("type"):
        return None

    current = bindings
    for key, pat_val in pattern.items():
        if key in ("type", "loc", "range", "start", "end"):
            continue
        code_val = node.get(key)
        if isinstance(pat_val, dict) and "type" in pat_val:
            if not isinstance(code_val, dict):
                return None
            result = match_js_pattern(pat_val, code_val, current)
            if result is None:
                return None
            current = result
        elif isinstance(pat_val, list):
            result = _match_js_sequence(pat_val, code_val or [], current)
            if result is None:
                return None
            current = result
        else:
            if pat_val != code_val:
                return None
    return current


def _match_js_sequence(pat_seq: list, code_seq: list, bindings: dict) -> dict | None:
    if not pat_seq and not code_seq:
        return bindings
    if not pat_seq:
        return None
    if isinstance(pat_seq[0], dict) and _js_is_ellipsis(pat_seq[0]):
        for skip in range(len(code_seq) + 1):
            result = _match_js_sequence(pat_seq[1:], code_seq[skip:], bindings)
            if result is not None:
                return result
        return None
    if not code_seq:
        return None
    result = match_js_pattern(pat_seq[0], code_seq[0], bindings)
    if result is None:
        return None
    return _match_js_sequence(pat_seq[1:], code_seq[1:], result)


def find_js_pattern(pattern: dict, root: dict) -> list[tuple[dict, dict]]:
    """Walk a JS AST dict and return all (node, bindings) matches."""
    matches = []
    def walk(node):
        if not isinstance(node, dict):
            return
        b = match_js_pattern(pattern, node)
        if b is not None:
            matches.append((node, b))
        for v in node.values():
            if isinstance(v, dict):
                walk(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        walk(item)
    walk(root)
    return matches


# ── Built-in structural rules ─────────────────────────────────────────────────
# These rules use the structural pattern engine instead of regex.
# Confidence is HIGH because structural matches are AST-precise.
# ─────────────────────────────────────────────────────────────────────────────

_RAW_STRUCTURAL_RULES: list[dict] = [
    # ── Python ────────────────────────────────────────────────────────────────
    {"id": "SEC002S",  "language": "python", "severity": "HIGH",
     "pattern": "eval($ARG)",
     "message": "eval() called with dynamic argument — code injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC002S",  "language": "python", "severity": "HIGH",
     "pattern": "exec($ARG)",
     "message": "exec() called with dynamic argument — code injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC002S",  "language": "python", "severity": "HIGH",
     "pattern": "os.system($CMD)",
     "message": "os.system() — shell injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC080S",  "language": "python", "severity": "HIGH",
     "pattern": "subprocess.call($CMD, shell=True)",
     "message": "subprocess.call with shell=True — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC080S",  "language": "python", "severity": "HIGH",
     "pattern": "subprocess.run($CMD, shell=True)",
     "message": "subprocess.run with shell=True — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC080S",  "language": "python", "severity": "HIGH",
     "pattern": "subprocess.Popen($CMD, shell=True)",
     "message": "subprocess.Popen with shell=True — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC069S",  "language": "python", "severity": "HIGH",
     "pattern": "pickle.loads($DATA)",
     "message": "pickle.loads() — unsafe deserialization",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC069S",  "language": "python", "severity": "HIGH",
     "pattern": "pickle.load($FILE)",
     "message": "pickle.load() — unsafe deserialization",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC068S",  "language": "python", "severity": "HIGH",
     "pattern": "yaml.load($DATA)",
     "message": "yaml.load() without Loader — unsafe deserialization",
     "pattern_not": ["yaml.load($DATA, Loader=$L)"],
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC005S",  "language": "python", "severity": "MEDIUM",
     "pattern": "hashlib.md5($DATA)",
     "message": "MD5 is cryptographically weak — use SHA-256 or better",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC005S",  "language": "python", "severity": "MEDIUM",
     "pattern": "hashlib.sha1($DATA)",
     "message": "SHA-1 is cryptographically weak — use SHA-256 or better",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC008S",  "language": "python", "severity": "MEDIUM",
     "pattern": "random.random()",
     "message": "random.random() is not cryptographically secure — use secrets module",
     "cwe": "CWE-338", "owasp": "A02:2021"},

    {"id": "SEC008S",  "language": "python", "severity": "MEDIUM",
     "pattern": "random.randint($A, $B)",
     "message": "random.randint() is not cryptographically secure — use secrets.randbelow()",
     "cwe": "CWE-338", "owasp": "A02:2021"},

    {"id": "SEC082S",  "language": "python", "severity": "HIGH",
     "pattern": "requests.get($URL, verify=False)",
     "message": "SSL certificate verification disabled",
     "cwe": "CWE-295", "owasp": "A02:2021"},

    {"id": "SEC082S",  "language": "python", "severity": "HIGH",
     "pattern": "requests.post($URL, verify=False)",
     "message": "SSL certificate verification disabled",
     "cwe": "CWE-295", "owasp": "A02:2021"},

    {"id": "SEC082S",  "language": "python", "severity": "HIGH",
     "pattern": "requests.request($METHOD, $URL, verify=False)",
     "message": "SSL certificate verification disabled",
     "cwe": "CWE-295", "owasp": "A02:2021"},

    {"id": "SEC073S",  "language": "python", "severity": "HIGH",
     "pattern": "app.run(debug=True)",
     "message": "Flask debug mode enabled in production — exposes interactive debugger",
     "cwe": "CWE-798", "owasp": "A05:2021"},

    {"id": "SEC070S",  "language": "python", "severity": "MEDIUM",
     "pattern": "csrf_exempt($VIEW)",
     "message": "CSRF protection disabled on this view",
     "cwe": "CWE-352", "owasp": "A01:2021"},

    {"id": "SEC079S",  "language": "python", "severity": "MEDIUM",
     "pattern": "tempfile.mktemp()",
     "message": "tempfile.mktemp() is insecure — use tempfile.mkstemp() or NamedTemporaryFile",
     "cwe": "CWE-377", "owasp": "A01:2021"},

    {"id": "SEC130S",  "language": "python", "severity": "HIGH",
     "pattern": "marshal.loads($DATA)",
     "message": "marshal.loads() — unsafe deserialization",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # ── JavaScript ────────────────────────────────────────────────────────────
    {"id": "SEC002S",  "language": "javascript", "severity": "HIGH",
     "pattern": "eval($ARG)",
     "message": "eval() — code injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC089S",  "language": "javascript", "severity": "HIGH",
     "pattern": "unserialize($DATA)",
     "message": "node-serialize unserialize() — remote code execution risk",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC091S",  "language": "javascript", "severity": "MEDIUM",
     "pattern": "crypto.createCipher($ALG, $KEY)",
     "message": "crypto.createCipher is deprecated — use createCipheriv with explicit IV",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC087S",  "language": "javascript", "severity": "MEDIUM",
     "pattern": "new RegExp($PATTERN)",
     "message": "RegExp from variable — potential ReDoS if pattern is user-controlled",
     "cwe": "CWE-400", "owasp": "A05:2021"},

    {"id": "SEC111S",  "language": "javascript", "severity": "HIGH",
     "pattern": "yaml.load($DATA)",
     "message": "js-yaml load() without safeLoad — unsafe deserialization",
     "pattern_not": ["yaml.safeLoad($DATA)"],
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # ════════════════════════════════════════════════════════════════
    # DJANGO
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_DJ001", "language": "python", "severity": "HIGH",
     "pattern": "$MODEL.objects.raw($SQL)",
     "message": "Django ORM raw() — SQL injection risk if $SQL contains user input",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_DJ002", "language": "python", "severity": "HIGH",
     "pattern": "RawSQL($SQL, $PARAMS)",
     "message": "Django RawSQL() — verify $SQL does not contain user-controlled fragments",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_DJ003", "language": "python", "severity": "HIGH",
     "pattern": "connection.execute($SQL)",
     "message": "Raw SQL via connection.execute() — use parameterized queries",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_DJ004", "language": "python", "severity": "MEDIUM",
     "pattern": "csrf_exempt($FUNC)",
     "message": "Django @csrf_exempt disables CSRF protection on this view",
     "cwe": "CWE-352", "owasp": "A01:2021"},

    {"id": "SEC_DJ005", "language": "python", "severity": "HIGH",
     "pattern": "render_template_string($TMPL)",
     "message": "render_template_string() with dynamic template — SSTI risk",
     "cwe": "CWE-94", "owasp": "A03:2021"},

    {"id": "SEC_DJ006", "language": "python", "severity": "HIGH",
     "pattern": "Markup($X)",
     "message": "Markup() marks content as safe HTML — XSS if $X is user-controlled",
     "cwe": "CWE-79", "owasp": "A03:2021"},

    {"id": "SEC_DJ007", "language": "python", "severity": "MEDIUM",
     "pattern": "$MODEL.objects.extra(where=$COND)",
     "message": "Django ORM extra(where=...) — SQL injection risk in raw where clause",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # FLASK / WERKZEUG
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_FL002", "language": "python", "severity": "MEDIUM",
     "pattern": "app.run(host='0.0.0.0')",
     "message": "Flask app listening on all interfaces — ensure this is intentional",
     "cwe": "CWE-668", "owasp": "A05:2021"},

    {"id": "SEC_FL003", "language": "python", "severity": "HIGH",
     "pattern": "send_file($PATH)",
     "message": "send_file() with dynamic path — path traversal risk",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_FL004", "language": "python", "severity": "MEDIUM",
     "pattern": "make_response($CONTENT)",
     "message": "make_response() with dynamic content — XSS if $CONTENT is user-controlled",
     "cwe": "CWE-79", "owasp": "A03:2021"},

    {"id": "SEC_FL005", "language": "python", "severity": "HIGH",
     "pattern": "redirect($URL)",
     "message": "redirect() with dynamic URL — open redirect risk",
     "cwe": "CWE-601", "owasp": "A01:2021"},

    # ════════════════════════════════════════════════════════════════
    # SQLALCHEMY
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_SA001", "language": "python", "severity": "HIGH",
     "pattern": "db.session.execute(text($SQL))",
     "message": "SQLAlchemy text() — SQL injection if $SQL contains user input",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_SA002", "language": "python", "severity": "HIGH",
     "pattern": "session.execute(text($SQL))",
     "message": "SQLAlchemy text() — SQL injection if $SQL contains user input",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_SA003", "language": "python", "severity": "HIGH",
     "pattern": "engine.execute($SQL)",
     "message": "SQLAlchemy engine.execute() with raw SQL — use text() with bound params",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # PYTHON CRYPTO
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_CR001", "language": "python", "severity": "HIGH",
     "pattern": "Cipher(algorithms.AES($KEY), modes.ECB(), ...)",
     "message": "AES-ECB mode — ECB is deterministic and reveals plaintext patterns",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_CR002", "language": "python", "severity": "HIGH",
     "pattern": "Cipher(algorithms.TripleDES($KEY), ...)",
     "message": "3DES is deprecated — use AES-256-GCM",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_CR003", "language": "python", "severity": "HIGH",
     "pattern": "Cipher(algorithms.Blowfish($KEY), ...)",
     "message": "Blowfish is deprecated — use AES-256-GCM",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_CR004", "language": "python", "severity": "HIGH",
     "pattern": "Cipher(algorithms.ARC4($KEY), ...)",
     "message": "RC4/ARC4 is broken — use AES-256-GCM",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_CR006", "language": "python", "severity": "HIGH",
     "pattern": "hashlib.new('md5')",
     "message": "MD5 is cryptographically broken",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_CR007", "language": "python", "severity": "HIGH",
     "pattern": "hashlib.new('sha1')",
     "message": "SHA-1 is cryptographically weak — use SHA-256 or better",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    # ════════════════════════════════════════════════════════════════
    # JWT (PYTHON)
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_JW001", "language": "python", "severity": "HIGH",
     "pattern": "jwt.decode($TOKEN, algorithms=['none'])",
     "message": "JWT algorithm 'none' accepted — allows unsigned tokens",
     "cwe": "CWE-347", "owasp": "A02:2021"},

    {"id": "SEC_JW003", "language": "python", "severity": "HIGH",
     "pattern": "jwt.encode($PAYLOAD, '', ...)",
     "message": "JWT signed with empty secret key",
     "cwe": "CWE-321", "owasp": "A02:2021"},

    # ════════════════════════════════════════════════════════════════
    # SUBPROCESS / OS (PYTHON)
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_OS001", "language": "python", "severity": "HIGH",
     "pattern": "subprocess.check_output($CMD, shell=True)",
     "message": "subprocess.check_output with shell=True — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_OS002", "language": "python", "severity": "HIGH",
     "pattern": "subprocess.check_call($CMD, shell=True)",
     "message": "subprocess.check_call with shell=True — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_OS003", "language": "python", "severity": "HIGH",
     "pattern": "os.popen($CMD)",
     "message": "os.popen() — command injection risk if $CMD is user-controlled",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_OS004", "language": "python", "severity": "HIGH",
     "pattern": "os.execv($PATH, $ARGS)",
     "message": "os.execv() — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # DESERIALIZATION (PYTHON)
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_DS001", "language": "python", "severity": "HIGH",
     "pattern": "yaml.load($DATA, Loader=yaml.Loader)",
     "message": "yaml.load with full Loader — use yaml.safe_load() instead",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC_DS002", "language": "python", "severity": "HIGH",
     "pattern": "yaml.load($DATA, Loader=yaml.UnsafeLoader)",
     "message": "yaml.load with UnsafeLoader — use yaml.safe_load() instead",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC_DS003", "language": "python", "severity": "HIGH",
     "pattern": "jsonpickle.decode($DATA)",
     "message": "jsonpickle.decode() — unsafe deserialization, can execute arbitrary code",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC_DS004", "language": "python", "severity": "HIGH",
     "pattern": "dill.loads($DATA)",
     "message": "dill.loads() — unsafe deserialization (superset of pickle)",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    {"id": "SEC_DS005", "language": "python", "severity": "HIGH",
     "pattern": "shelve.open($PATH)",
     "message": "shelve.open() uses pickle internally — path traversal + deserialization risk",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # ════════════════════════════════════════════════════════════════
    # FILE / PATH (PYTHON)
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_FI001", "language": "python", "severity": "HIGH",
     "pattern": "open($PATH, $MODE)",
     "message": "open() with dynamic path — path traversal risk",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_FI002", "language": "python", "severity": "HIGH",
     "pattern": "open($PATH)",
     "message": "open() with dynamic path — path traversal risk",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_FI003", "language": "python", "severity": "MEDIUM",
     "pattern": "shutil.move($SRC, $DST)",
     "message": "shutil.move() with dynamic paths — verify inputs are sanitized",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / EXPRESS
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_EX001", "language": "javascript", "severity": "HIGH",
     "pattern": "app.use(cors())",
     "message": "cors() without options — allows all origins (wildcard CORS)",
     "cwe": "CWE-346", "owasp": "A07:2021"},

    {"id": "SEC_EX002", "language": "javascript", "severity": "HIGH",
     "pattern": "cors({origin: '*'})",
     "message": "CORS wildcard origin — allows any domain to make credentialed requests",
     "cwe": "CWE-346", "owasp": "A07:2021"},

    {"id": "SEC_EX003", "language": "javascript", "severity": "HIGH",
     "pattern": "app.use(session({secret: $S}))",
     "message": "Express session — verify $S is a strong random secret, not hardcoded",
     "cwe": "CWE-798", "owasp": "A07:2021"},

    {"id": "SEC_EX005", "language": "javascript", "severity": "MEDIUM",
     "pattern": "res.setHeader('Access-Control-Allow-Origin', '*')",
     "message": "CORS wildcard origin set via header",
     "cwe": "CWE-346", "owasp": "A07:2021"},

    {"id": "SEC_EX006", "language": "javascript", "severity": "HIGH",
     "pattern": "res.redirect($URL)",
     "message": "res.redirect() — open redirect risk if $URL is user-controlled",
     "cwe": "CWE-601", "owasp": "A01:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / JWT
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_JW010", "language": "javascript", "severity": "HIGH",
     "pattern": "jwt.sign($PAYLOAD, $SECRET, {algorithm: 'none'})",
     "message": "JWT signed with algorithm 'none' — no cryptographic protection",
     "cwe": "CWE-347", "owasp": "A02:2021"},

    {"id": "SEC_JW011", "language": "javascript", "severity": "HIGH",
     "pattern": "jwt.verify($TOKEN, $SECRET, {algorithms: ['none']})",
     "message": "JWT verification allows 'none' algorithm — unsigned tokens accepted",
     "cwe": "CWE-347", "owasp": "A02:2021"},

    {"id": "SEC_JW012", "language": "javascript", "severity": "HIGH",
     "pattern": "jwt.decode($TOKEN)",
     "message": "jwt.decode() without verification — signature is not checked",
     "cwe": "CWE-347", "owasp": "A02:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / NODE.JS
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_ND001", "language": "javascript", "severity": "HIGH",
     "pattern": "Function($CODE)",
     "message": "Function() constructor with dynamic code — code injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_ND002", "language": "javascript", "severity": "HIGH",
     "pattern": "vm.runInNewContext($CODE)",
     "message": "vm.runInNewContext() — sandbox escape risk with untrusted code",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_ND003", "language": "javascript", "severity": "HIGH",
     "pattern": "vm.runInThisContext($CODE)",
     "message": "vm.runInThisContext() — executes code in current V8 context",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_ND004", "language": "javascript", "severity": "HIGH",
     "pattern": "child_process.exec($CMD, $CB)",
     "message": "child_process.exec() — command injection if $CMD is user-controlled",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_ND005", "language": "javascript", "severity": "HIGH",
     "pattern": "child_process.execSync($CMD)",
     "message": "child_process.execSync() — command injection risk",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    {"id": "SEC_ND006", "language": "javascript", "severity": "MEDIUM",
     "pattern": "Buffer($INPUT)",
     "message": "Buffer() constructor is deprecated — use Buffer.from() or Buffer.alloc()",
     "cwe": "CWE-119", "owasp": "A06:2021"},

    {"id": "SEC_ND007", "language": "javascript", "severity": "MEDIUM",
     "pattern": "Buffer.allocUnsafe($N)",
     "message": "Buffer.allocUnsafe() — contains uninitialized memory, may leak data",
     "cwe": "CWE-119", "owasp": "A06:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / CRYPTO
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_JC001", "language": "javascript", "severity": "MEDIUM",
     "pattern": "Math.random()",
     "message": "Math.random() is not cryptographically secure — use crypto.getRandomValues()",
     "cwe": "CWE-338", "owasp": "A02:2021"},

    {"id": "SEC_JC002", "language": "javascript", "severity": "HIGH",
     "pattern": "crypto.createHash('md5')",
     "message": "MD5 hash — cryptographically broken, use SHA-256",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_JC003", "language": "javascript", "severity": "HIGH",
     "pattern": "crypto.createHash('sha1')",
     "message": "SHA-1 hash — cryptographically weak, use SHA-256",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_JC004", "language": "javascript", "severity": "HIGH",
     "pattern": "crypto.createCipheriv('des', $KEY, $IV)",
     "message": "DES cipher — broken, use AES-256-GCM",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / XSS
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_XS001", "language": "javascript", "severity": "HIGH",
     "pattern": "document.write($X)",
     "message": "document.write() — XSS sink if $X contains user-controlled data",
     "cwe": "CWE-79", "owasp": "A03:2021"},

    {"id": "SEC_XS003", "language": "javascript", "severity": "HIGH",
     "pattern": "$EL.insertAdjacentHTML($POS, $HTML)",
     "message": "insertAdjacentHTML() — XSS sink if $HTML is user-controlled",
     "cwe": "CWE-79", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / SQL
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_SQ002", "language": "javascript", "severity": "HIGH",
     "pattern": "knex.raw($SQL)",
     "message": "knex.raw() — SQL injection if $SQL contains user input",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_SQ003", "language": "javascript", "severity": "HIGH",
     "pattern": "sequelize.query($SQL)",
     "message": "Sequelize raw query — SQL injection if $SQL contains user input",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    {"id": "SEC_SQ004", "language": "javascript", "severity": "HIGH",
     "pattern": "$MODEL.find($QUERY)",
     "message": "Mongoose find() — NoSQL injection if $QUERY contains user-controlled operators",
     "cwe": "CWE-943", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / PROTOTYPE POLLUTION
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_PP001", "language": "javascript", "severity": "HIGH",
     "pattern": "Object.assign($TARGET, $SRC)",
     "message": "Object.assign() — prototype pollution if $SRC is user-controlled",
     "cwe": "CWE-1321", "owasp": "A03:2021"},

    {"id": "SEC_PP003", "language": "javascript", "severity": "HIGH",
     "pattern": "_.merge($TARGET, $SRC)",
     "message": "lodash _.merge() — prototype pollution if $SRC is user-controlled",
     "cwe": "CWE-1321", "owasp": "A03:2021"},

    {"id": "SEC_PP004", "language": "javascript", "severity": "HIGH",
     "pattern": "$.extend($TARGET, $SRC)",
     "message": "jQuery.extend() — prototype pollution if $SRC is user-controlled",
     "cwe": "CWE-1321", "owasp": "A03:2021"},

    # ════════════════════════════════════════════════════════════════
    # JAVASCRIPT / SSRF + PATH TRAVERSAL
    # ════════════════════════════════════════════════════════════════
    {"id": "SEC_SR001", "language": "javascript", "severity": "HIGH",
     "pattern": "fetch($URL)",
     "message": "fetch() — SSRF risk if $URL is user-controlled",
     "cwe": "CWE-918", "owasp": "A10:2021"},

    {"id": "SEC_SR002", "language": "javascript", "severity": "HIGH",
     "pattern": "axios.get($URL)",
     "message": "axios.get() — SSRF risk if $URL is user-controlled",
     "cwe": "CWE-918", "owasp": "A10:2021"},

    {"id": "SEC_SR004", "language": "javascript", "severity": "HIGH",
     "pattern": "http.get($URL, $CB)",
     "message": "http.get() — SSRF risk if $URL is user-controlled",
     "cwe": "CWE-918", "owasp": "A10:2021"},

    {"id": "SEC_PT001", "language": "javascript", "severity": "HIGH",
     "pattern": "fs.readFile($PATH, $CB)",
     "message": "fs.readFile() — path traversal risk if $PATH is user-controlled",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_PT002", "language": "javascript", "severity": "HIGH",
     "pattern": "fs.readFileSync($PATH)",
     "message": "fs.readFileSync() — path traversal risk",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_PT003", "language": "javascript", "severity": "HIGH",
     "pattern": "fs.writeFile($PATH, $DATA, $CB)",
     "message": "fs.writeFile() — path traversal risk if $PATH is user-controlled",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_PT004", "language": "javascript", "severity": "HIGH",
     "pattern": "fs.createReadStream($PATH)",
     "message": "fs.createReadStream() — path traversal risk",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    {"id": "SEC_PT005", "language": "javascript", "severity": "HIGH",
     "pattern": "path.join($BASE, $INPUT)",
     "message": "path.join() — validate $INPUT to prevent directory traversal",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    # ── Python pattern-inside / pattern-not-inside rules ──────────────────────

    # pickle.loads outside a try block is especially dangerous (no error handling)
    {"id": "SEC_PI001", "language": "python", "severity": "CRITICAL",
     "pattern": "pickle.loads($DATA)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "pickle.loads() outside try/except — deserialization with no error handling",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # marshal.loads outside try
    {"id": "SEC_PI002", "language": "python", "severity": "HIGH",
     "pattern": "marshal.loads($DATA)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "marshal.loads() outside try/except — unsafe deserialization",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # shelve.open outside try
    {"id": "SEC_PI003", "language": "python", "severity": "HIGH",
     "pattern": "shelve.open($PATH)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "shelve.open() outside try/except — shelve uses pickle internally",
     "cwe": "CWE-502", "owasp": "A08:2021"},

    # os.system() only dangerous outside a sanitisation wrapper
    {"id": "SEC_PI004", "language": "python", "severity": "HIGH",
     "pattern": "os.system($CMD)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "os.system() outside try/except — command injection risk with no error handling",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    # eval() is bad everywhere, but especially outside try
    {"id": "SEC_PI005", "language": "python", "severity": "CRITICAL",
     "pattern": "eval($EXPR)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "eval() outside try/except — arbitrary code execution with no containment",
     "cwe": "CWE-94", "owasp": "A03:2021"},

    # exec() outside try
    {"id": "SEC_PI006", "language": "python", "severity": "CRITICAL",
     "pattern": "exec($EXPR)",
     "pattern-not-inside": "try:\n    ...\nexcept $E:\n    ...",
     "message": "exec() outside try/except — arbitrary code execution with no containment",
     "cwe": "CWE-94", "owasp": "A03:2021"},

    # Hardcoded secret assignment inside function (not in test file context)
    # Rule: password/secret/key = "..." inside a function
    {"id": "SEC_PI007", "language": "python", "severity": "HIGH",
     "pattern": "$VAR = $SECRET",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "metavar_regex": {"$VAR": r"(?i)(password|passwd|secret|api_key|token|private_key|access_key)",
                       "$SECRET": r'^["\'][^"\']{8,}["\']$'},
     "message": "Hardcoded secret '$VAR' inside function — use environment variables or a secrets manager",
     "cwe": "CWE-798", "owasp": "A07:2021"},

    # requests.get/post without verify=False check — inside functions only to reduce noise
    {"id": "SEC_PI008", "language": "python", "severity": "MEDIUM",
     "pattern": "requests.get($URL, verify=False)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "message": "TLS verification disabled in requests.get() — remove verify=False",
     "cwe": "CWE-295", "owasp": "A02:2021"},

    {"id": "SEC_PI009", "language": "python", "severity": "MEDIUM",
     "pattern": "requests.post($URL, verify=False)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "message": "TLS verification disabled in requests.post() — remove verify=False",
     "cwe": "CWE-295", "owasp": "A02:2021"},

    # SQL cursor.execute with % formatting — only flag inside functions (not at module level)
    {"id": "SEC_PI010", "language": "python", "severity": "HIGH",
     "pattern": "$CURSOR.execute($QUERY % $ARGS)",
     "pattern-inside": "def $F($ARGS2):\n    ...",
     "message": "SQL injection via % string formatting in cursor.execute()",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    # Django raw() inside class-based view methods
    {"id": "SEC_PI011", "language": "python", "severity": "HIGH",
     "pattern": "$MODEL.objects.raw($QUERY)",
     "pattern-not": "$MODEL.objects.raw($QUERY, $PARAMS)",
     "pattern-inside": "def $METHOD(self, $ARGS):\n    ...",
     "message": "Django raw() without parameters inside class method — SQL injection risk",
     "cwe": "CWE-89", "owasp": "A03:2021"},

    # Flask route handler returning user input directly
    {"id": "SEC_PI012", "language": "python", "severity": "HIGH",
     "pattern": "return $USER_INPUT",
     "pattern-inside": "@app.route($PATH)\ndef $F($ARGS):\n    ...",
     "message": "Flask route directly returns potentially untrusted value — ensure proper escaping",
     "cwe": "CWE-79", "owasp": "A03:2021"},

    # open() with 'w' mode for user-supplied path, inside function
    {"id": "SEC_PI013", "language": "python", "severity": "MEDIUM",
     "pattern": "open($PATH, $MODE)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "metavar_regex": {"$MODE": r"['\"]w"},
     "message": "open() in write mode with potentially user-controlled path — validate path",
     "cwe": "CWE-22", "owasp": "A01:2021"},

    # subprocess.run/call with shell=True inside any function
    {"id": "SEC_PI014", "language": "python", "severity": "HIGH",
     "pattern": "subprocess.run($CMD, shell=True)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "message": "subprocess.run(shell=True) inside function — command injection if $CMD contains user input",
     "cwe": "CWE-78", "owasp": "A03:2021"},

    # hashlib.md5 / hashlib.sha1 inside password-hashing functions
    {"id": "SEC_PI015", "language": "python", "severity": "HIGH",
     "pattern": "hashlib.md5($DATA)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "metavar_regex": {"$F": r"(?i)(hash|password|passwd|digest|crypt|encode)"},
     "message": "MD5 used in a password-hashing function — use bcrypt/argon2 instead",
     "cwe": "CWE-327", "owasp": "A02:2021"},

    {"id": "SEC_PI016", "language": "python", "severity": "HIGH",
     "pattern": "hashlib.sha1($DATA)",
     "pattern-inside": "def $F($ARGS):\n    ...",
     "metavar_regex": {"$F": r"(?i)(hash|password|passwd|digest|crypt|encode)"},
     "message": "SHA1 used in a password-hashing function — use bcrypt/argon2 instead",
     "cwe": "CWE-327", "owasp": "A02:2021"},
]


def _compile_structural_rules(raw: list[dict]) -> dict[str, list[StructuralRule]]:
    """Compile raw structural rule dicts into StructuralRule objects grouped by language."""
    compiled: dict[str, list[StructuralRule]] = {}
    for r in raw:
        lang = r["language"]
        rule_id = r["id"]
        sev = r["severity"]
        msg = r["message"]
        cwe = r.get("cwe", "")
        owasp = r.get("owasp", "")

        # Skip JS rules at module load (esprima may not be available yet)
        if lang == "javascript":
            continue

        try:
            if lang == "python":
                expr_pat, stmt_pat = None, None
                if "pattern" in r:
                    expr_pat, stmt_pat = _parse_py_pattern_flex(r["pattern"])
                pattern_not = [_parse_py_pattern(p) for p in r.get("pattern_not", [])]
                pattern_either = [_parse_py_pattern(p) for p in r.get("pattern_either", [])]
                if "pattern-inside" in r:
                    _ei, _si = _parse_py_pattern_flex(r["pattern-inside"])
                    pattern_inside = _si if _si is not None else _ei
                else:
                    pattern_inside = None
                if "pattern-not-inside" in r:
                    _ei, _si = _parse_py_pattern_flex(r["pattern-not-inside"])
                    pattern_not_inside = _si if _si is not None else _ei
                else:
                    pattern_not_inside = None
            else:
                continue

            if expr_pat is None and stmt_pat is None and not r.get("pattern_either"):
                continue

            metavar_regex = {
                k.lstrip("$"): re.compile(v)
                for k, v in r.get("metavar_regex", {}).items()
            }
            sr = StructuralRule(
                id=rule_id, language=lang, severity=sev,
                message=msg, cwe=cwe, owasp=owasp,
                pattern=expr_pat,
                stmt_pattern=stmt_pat,
                pattern_not=pattern_not,
                pattern_either=pattern_either,
                pattern_inside=pattern_inside,
                pattern_not_inside=pattern_not_inside,
                metavar_regex=metavar_regex,
            )
            compiled.setdefault(lang, []).append(sr)
        except Exception:
            continue  # skip invalid patterns silently

    return compiled


STRUCTURAL_RULES: dict[str, list[StructuralRule]] = _compile_structural_rules(_RAW_STRUCTURAL_RULES)


_JS_STRUCTURAL_RULES_COMPILED = False


def _ensure_js_structural_rules() -> None:
    global _JS_STRUCTURAL_RULES_COMPILED
    if _JS_STRUCTURAL_RULES_COMPILED:
        return
    esp = _get_esprima()
    if esp is None:
        return
    js_raw = [r for r in _RAW_STRUCTURAL_RULES if r["language"] == "javascript"]
    for r in js_raw:
        try:
            pattern = _parse_js_pattern(r["pattern"]) if "pattern" in r else None
            if pattern is None:
                continue
            pattern_not = [p for p in [_parse_js_pattern(s) for s in r.get("pattern_not", [])] if p]
            sr = StructuralRule(
                id=r["id"], language="javascript", severity=r["severity"],
                message=r["message"], cwe=r.get("cwe", ""), owasp=r.get("owasp", ""),
                pattern=pattern, pattern_not=pattern_not,
            )
            STRUCTURAL_RULES.setdefault("javascript", []).append(sr)
        except Exception:
            continue
    _JS_STRUCTURAL_RULES_COMPILED = True


# ── False-positive suppression helpers ───────────────────────────────────────

def _python_nocode_spans(source: str) -> tuple[list[tuple[int, int]], list[int]]:
    """
    Return (spans, line_offsets) for the Python source string.

    spans       : absolute byte-offset ranges (start, end) of every STRING and
                  COMMENT token.  Regex matches whose start falls inside one of
                  these ranges are skipped (documentation / comments are not code).
    line_offsets: line_offsets[i] is the byte offset of the (i+1)-th line in
                  source (0-indexed), i.e. line_offsets[0]=0, line_offsets[1]=
                  len(line-1), etc.  Used to convert (line_no, col) → abs offset.
    """
    raw_lines = source.splitlines(keepends=True)
    offsets: list[int] = [0]
    for ln in raw_lines:
        offsets.append(offsets[-1] + len(ln))

    spans: list[tuple[int, int]] = []
    try:
        for tok_type, _, tok_start, tok_end, _ in tokenize.generate_tokens(
            io.StringIO(source).readline
        ):
            if tok_type in (tokenize.STRING, tokenize.COMMENT):
                s = offsets[tok_start[0] - 1] + tok_start[1]
                e = offsets[tok_end[0]   - 1] + tok_end[1]
                spans.append((s, e))
    except tokenize.TokenError:
        pass

    return spans, offsets  # offsets[i] = start of (i+1)-th line


# ── High-entropy string detection (SEC001E) ───────────────────────────────────

# Known prefixes for popular secret formats — low-entropy bar when matched.
_SECRET_PREFIXES: tuple[str, ...] = (
    "AKIA", "ASIA", "AIPA",                    # AWS access/session keys
    "ghp_", "ghs_", "gho_", "ghr_", "ghb_",   # GitHub tokens
    "sk-",                                      # OpenAI / Anthropic
    "xoxb-", "xoxa-", "xoxe-", "xoxp-",       # Slack tokens
    "AIza",                                    # Google API key
    "ya29.",                                   # Google OAuth token
    "SG.",                                     # SendGrid
    "EAA",                                     # Facebook access token
    "Bearer ",                                 # OAuth bearer (literal in source)
)

_B64_ALPHA = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)
_HEX_ALPHA = frozenset("0123456789abcdefABCDEF")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_like_secret(value: str) -> bool:
    """
    Return True if the string value is likely a hardcoded secret based on
    character set and Shannon entropy — not a URL, path, or readable phrase.
    """
    if len(value) < 12:
        return False
    if any(value.startswith(p) for p in ("http://", "https://", "//", "/*", "*/")):
        return False
    if value.count("/") > 4:
        return False
    # Real secrets never contain spaces or parentheses.
    # Strings like User-Agent headers, CSS values, or natural-language phrases
    # all have spaces/parens and are caught here before the entropy check.
    if " " in value or "(" in value or ")" in value:
        return False
    # High-signal known prefixes — lower entropy bar because the prefix is itself evidence.
    if any(value.startswith(p) for p in _SECRET_PREFIXES):
        return _shannon_entropy(value) >= 3.0
    chars = frozenset(value)
    ent   = _shannon_entropy(value)
    # Pure hex strings (e.g. 40-char SHA1, 32-char MD5, API tokens).
    if chars <= _HEX_ALPHA and len(value) >= 20:
        return ent >= 3.5
    # Base64-alphabet strings (JWT segments, base64-encoded secrets).
    if chars <= _B64_ALPHA and len(value) >= 20:
        return ent >= 4.0
    # Generic fallback — require higher entropy to avoid natural-language FPs.
    return ent >= 5.0 and len(value) >= 20


# Matches string literals in most languages (minimum 12 chars inside).
_STRING_LITERAL_RE = re.compile(
    r'"([^"\\]{12,}(?:\\.[^"\\]*)*)"|'
    r"'([^'\\]{12,}(?:\\.[^'\\]*)*)'"
)


def scan_entropy(path: Path, language: str) -> list[Finding]:
    """
    Detect high-entropy string literals that may be hardcoded secrets (SEC001E).
    Complements SEC001 regex rules by catching API keys and tokens that lack
    a recognisable variable-name prefix.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    nosec = _NOSEC.get(language, "")
    pfxs  = _COMMENT_PREFIX.get(language, ())
    cwe, owasp = RULE_META.get("SEC001E", ("CWE-798", "A07:2021"))
    findings: list[Finding] = []

    for i, raw_line in enumerate(source.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if any(stripped.startswith(p) for p in pfxs):
            continue
        if nosec and nosec in raw_line.lower():
            continue
        for m in _STRING_LITERAL_RE.finditer(raw_line):
            value = m.group(1) or m.group(2) or ""
            if not _looks_like_secret(value):
                continue
            ent = _shannon_entropy(value)
            findings.append(Finding(
                file=str(path), line=i,
                severity="HIGH", rule_id="SEC001E",
                language=language,
                message=(
                    f"High-entropy string literal (entropy={ent:.2f} bits/char) — "
                    "possible hardcoded API key, token, or credential"
                ),
                code_snippet=stripped[:120],
                confidence="MEDIUM",
                cwe=cwe, owasp=owasp,
            ))
    return findings


# Per-language inline suppression marker (# nosec / // nosec).
# A line containing this string (case-insensitive) is skipped entirely.
_NOSEC: dict[str, str] = {
    "python":     "# nosec",
    "bash":       "# nosec",
    "php":        "# nosec",
    "build":      "# nosec",
    "javascript": "// nosec",
    "java":       "// nosec",
    "go":         "// nosec",
    "c":          "// nosec",
    "dockerfile": "# nosec",
    "gha":        "# nosec",
}

# Single-line comment prefixes — full lines starting with these are skipped.
_COMMENT_PREFIX: dict[str, tuple[str, ...]] = {
    "python":     ("#",),
    "bash":       ("#",),
    "build":      ("#",),
    "javascript": ("//",),
    "java":       ("//",),
    "go":         ("//",),
    "c":          ("//",),
    "php":        ("//", "#"),
    "dockerfile": ("#",),
    "gha":        ("#",),
}

# Languages that support /* … */ block comments.
_BLOCK_COMMENT_LANGS = frozenset({"javascript", "java", "go", "c", "php"})


RULES = {
    "python": [
        ("SEC001", "HIGH",   r'\b(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret in variable"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC002", "HIGH",   r'\bexec\s*\(',                  "Use of exec()"),
        ("SEC002", "HIGH",   r'\bos\.system\s*\(',            "Use of os.system() — shell injection risk"),
        ("SEC002", "HIGH",   r'\bpickle\.loads\s*\(',         "Unsafe pickle deserialization"),
        ("SEC002", "MEDIUM", r'\bsubprocess\.call\s*\(',      "Subprocess usage — sanitise inputs"),
        ("SEC002", "MEDIUM", r'\bcompile\s*\(',               "Dynamic code compilation"),
        ("SEC003", "LOW",    r'\bassert\b',                   "Assert stripped with python -O"),
        ("SEC004", "HIGH",   r'(f["\']|%\s*["\']|\.format\s*\().*-(SELECT|INSERT|UPDATE|DELETE)',
                             "Possible SQL injection via string formatting"),
        ("SEC004", "HIGH",   r'\.(execute|executemany)\s*\(\s*["\'].*["\'\s]\s*\+',
                             "SQL injection: string concatenation passed directly to execute()"),
        ("SEC057", "MEDIUM", r'\b(graphql|graphql_sync|execute|schema\.execute)\s*\(.*\b(request\.(args|form|values|json|GET|POST)|params\[|input\s*\()',
                             "GraphQL execution with user input as query string - injection risk"),
        ("SEC005", "MEDIUM", r'\bhashlib\.md5\b|\bhashlib\.sha1\b',
                             "Weak hashing algorithm (MD5/SHA1)"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|http-equiv\s*=\s*["\"]Content-Security-Policy["\"][^>]*',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC026", "HIGH",   r'\b(jinja2\.Template|render_template_string)\s*\(',
                             "Direct template compilation — ensure template source is not user-controlled"),
        ("SEC026B", "HIGH",  r'\b(render_template_string|jinja2\.Template|Environment\.from_string|Template\()\s*\(.*\b(request\.(args|form|values|files|json|GET|POST)|params\[|input\s*\()',
                             "SSTI risk: template source built directly from user input"),
        ("SEC026C", "MEDIUM", r'\b\.\s*from_string\s*\(.*\b(request\.(args|form|values|files|json|GET|POST)|params\[|input\s*\()',
                             "SSTI risk: template source from user input via from_string"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\b(open|Path)\s*\(.*\b(request\.(args|form|values|files|json|GET|POST)|params\[|input\s*\()',
                             "File operation with user-controlled input — path traversal / LFI risk"),
        ("SEC035", "HIGH",   r'\bos\.path\.join\s*\(.*\b(request\.(args|form|values|files|json|GET|POST)|params\[|input\s*\()',
                             "os.path.join with user input — path traversal risk"),
        ("SEC035B", "HIGH",  r'\b(send_file|send_from_directory|send_static_file)\s*\(.*\b(request\.|params|input)',
                             "Flask file-serving with user input — path traversal risk"),
        ("SEC027", "HIGH",   r'\bos\.path\.join\s*\([^,]+,\s*["\']/',
                             "os.path.join() with absolute path — preceding components silently dropped"),
        ("SEC027B", "HIGH",  r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC039", "HIGH",   r'%00.*\b(open|read|file|path|import)',
                             "Null byte in file path context — path truncation risk"),
        ("SEC037", "MEDIUM", r'["\']/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline|maps|fd/)|\.ssh/(id_rsa|authorized_keys)',
                             "Reference to sensitive system file — possible LFI target"),
        ("SEC042", "MEDIUM", r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd|root)',
                             "Access to /proc filesystem — information disclosure risk"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC043", "HIGH",   r'(?i)\balgorithms?\s*=\s*[\[\(]?\s*["\']none["\']',
                             "JWT 'none' algorithm — allows unsigned token forgery"),
        ("SEC044", "HIGH",   r'jwt\.decode\s*\(.*\bverify\s*=\s*False',
                             "JWT decode with verify=False — signature not checked"),
        ("SEC044B", "HIGH",  r'verify_signature["\']?\s*:\s*False',
                             "JWT signature verification explicitly disabled"),
        ("SEC044C", "HIGH",  r'verify_exp["\']?\s*:\s*False',
                             "JWT expiration check disabled — expired tokens accepted"),
        ("SEC046", "HIGH",   r'jwt\.(encode|decode)\s*\([^,]+,\s*["\'][^"\']{1,20}["\']',
                             "JWT with short hardcoded secret — crackable via hashcat"),
        ("SEC049", "MEDIUM", r'\bheader\s*\[\s*["\']kid["\']\s*\]|\bheader\s*\.\s*get\s*\(\s*["\'](kid|jku|x5u)["\']',
                             "JWT kid/jku/x5u header accessed — validate against path traversal and injection"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'\.(search_s|search|search_ext_s|search_st)\s*\(.*\b(request\.(args|form|json|values|GET|POST)|params\[|input\s*\()',
                             "LDAP search with user-controlled input — LDAP injection risk"),
        ("SEC052", "HIGH",   r'\.(simple_bind_s|bind_s|bind)\s*\(.*\b(request\.|params\[|input\s*\()',
                             "LDAP bind with user input — authentication bypass risk"),
        ("SEC053", "HIGH",   r'f["\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|userPassword|sAMAccountName)\s*=.*\{',
                             "LDAP filter built with f-string — injection risk"),
        ("SEC053", "HIGH",   r'["\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|userPassword|sAMAccountName)\s*=.*["\'].*(?:\.format\s*\(|%\s*\(|%s|\+\s*\w)',
                             "LDAP filter built via string formatting/concatenation — injection risk"),
        
        ("SEC056", "MEDIUM", r'\b(redirect|HttpResponseRedirect|HttpResponsePermanentRedirect)\s*\(.*\b(request\.(args|GET|POST|values|form)|params\[|input\s*\()',
                             "Redirect with user-controlled input - open redirect risk"),
        
        ("SEC054", "HIGH",   r'["\']\$where["\']',
                             "MongoDB $where executes JavaScript - NoSQL injection risk if user-controlled"),
        ("SEC024", "MEDIUM", r'\bunicodedata\.normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\b(idna\.(encode|decode)|encodings\.idna)\b',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # SSRF
        ("SEC066", "HIGH",   r'\brequests\.(get|post|put|patch|delete|head|request)\s*\(.*\b(request\.(args|form|values|json|GET|POST|data)|input\s*\(|os\.environ)',
                             "SSRF risk: requests call with user-controlled URL — validate and whitelist destinations"),
        ("SEC006", "HIGH",   r'\bflask\.(Response|make_response)\s*\(.*\b(request\.(args|form|values|json|GET|POST)|params\[|input\s*\()',
                             "XSS: Flask response built with unescaped user input"),
        ("SEC133", "HIGH",   r'\burllib(?:\.request)?\.urlopen\s*\(.*\b(request\.(args|form|values|json|GET|POST)|input\s*\()',
                             "SSRF risk: urllib.urlopen with user-controlled URL — validate and whitelist destinations"),
        ("SEC133", "MEDIUM", r'\burllib(?:\.request)?\.urlopen\s*\(\s*[A-Za-z_]\w*',
                             "SSRF risk: urllib.urlopen with variable URL — ensure destination is validated"),
        # XXE - Enhanced patterns to catch actual parsing calls
        ("SEC067", "MEDIUM", r'\bimport\s+xml(?:\s|$)|\bfrom\s+xml\b',
                             "XML import detected — use defusedxml instead to prevent XXE attacks"),
        ("SEC083", "HIGH",   r'\blxml\.etree\b|\bxml\.sax\b|\bxml\.dom\b|\bxml\.etree\b|\bXMLParser\s*\(',
                             "XML parser usage — ensure external entities are disabled or use defusedxml"),
        ("SEC083", "HIGH",   r'\bxml\.etree\.ElementTree\.(parse|fromstring|iterparse|XMLParser)\s*\(',
                             "xml.etree parsing without defusedxml — XXE vulnerability, use defusedxml.ElementTree instead"),
        ("SEC083", "HIGH",   r'\blxml\.etree\.(parse|fromstring|XMLParser|iterparse|HTML|XML)\s*\([^)]*(?!resolve_entities\s*=\s*False)',
                             "lxml parsing without resolve_entities=False — XXE vulnerability"),
        ("SEC083", "HIGH",   r'\bxml\.sax\.(parse|parseString|make_parser)\s*\(',
                             "xml.sax parsing — XXE vulnerability, use defusedxml.sax instead"),
        ("SEC083", "HIGH",   r'\bminidom\.(parse|parseString)\s*\(',
                             "minidom parsing — XXE vulnerability, use defusedxml.minidom instead"),
        ("SEC115", "MEDIUM", r'\bimport\s+xmlrpc\b|\bimport\s+xmlrpclib\b|\bimport\s+SimpleXMLRPCServer\b',
                             "xmlrpc usage — use defusedxml.xmlrpc to prevent XML entity attacks"),
        # YAML injection
        ("SEC068", "HIGH",   r'\byaml\.load\s*\([^)]*(?!\bLoader\s*=\s*yaml\.(?:Safe|Full|Base|Unsafe)Loader)',
                             "yaml.load() without safe Loader — use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)"),
        # Pickle/marshal
        ("SEC069", "HIGH",   r'\bpickle\.(load|loads|Unpickler)\s*\(',
                             "Unsafe pickle deserialization — can lead to arbitrary code execution"),
        ("SEC130", "HIGH",   r'\bmarshal\.(load|loads)\s*\(',
                             "Unsafe marshal deserialization — can lead to arbitrary code execution"),
        # Django-specific
        ("SEC070", "HIGH",   r'@csrf_exempt\b',
                             "CSRF protection disabled via @csrf_exempt — verify this endpoint does not change state"),
        ("SEC071", "HIGH",   r'\b(raw\s*\(|RawSQL\s*\(|\.extra\s*\(.*where|cursor\.execute\s*\(.*%|cursor\.execute\s*\(.*\.format)',
                             "Django raw SQL query — parameterize all inputs to prevent SQL injection"),
        ("SEC072", "MEDIUM", r'\bDEBUG\s*=\s*True\b',
                             "Django/Flask DEBUG=True — disable in production to prevent information leakage"),
        ("SEC121", "HIGH",   r'\bSECRET_KEY\s*=\s*["\'][^"\']{1,50}["\']',
                             "Hardcoded SECRET_KEY detected — use environment variables for secrets"),
        # Flask-specific
        ("SEC073", "MEDIUM", r'\bapp\.run\s*\(.*\bdebug\s*=\s*True',
                             "Flask debug=True — disables security controls and exposes debugger in production"),
        # Cryptography weak algorithms
        ("SEC074", "HIGH",   r'\bAES\.(?:new|MODE_ECB)\b|(?:Cipher\.getInstance|mode\s*=\s*).*ECB',
                             "ECB mode cipher — does not provide semantic security, use CBC or GCM"),
        ("SEC076", "HIGH",   r'\b(DES|TripleDES|ARC4|Blowfish|DES3|ARC2)\b.*(?:new\s*\(|\.encrypt|\.decrypt)',
                             "Weak cipher algorithm (DES/3DES/RC4/Blowfish/ARC4) — use AES-256-GCM"),
        ("SEC116", "MEDIUM", r'\b(algorithms\.MD4|algorithms\.MD5|algorithms\.SHA1|algorithms\.Blowfish|algorithms\.ARC4|algorithms\.DES|algorithms\.TripleDES|algorithms\.RC4)\b',
                             "Weak cryptographic algorithm in cryptography library — use SHA256+ or AES-GCM"),
        ("SEC131", "MEDIUM", r'\bpadding\.PKCS1v15\s*\(\s*\)|\bpadding\.OAEP\s*\(.*\bMGF1\s*\(.*\bSHA1\b',
                             "Weak RSA padding (PKCS1v15 or OAEP with SHA1) — use OAEP with SHA256"),
        ("SEC085", "MEDIUM", r'\bhashlib\.new\s*\(\s*["\'](?:md5|sha1|md4|sha|ripemd160)["\']',
                             "hashlib.new() with weak algorithm — use SHA256 or better"),
        # Timing attacks
        ("SEC077", "MEDIUM", r'\b(password|token|secret|key|hash|signature)\s*==\s*\w|\w\s*==\s*(password|token|secret|key|hash|signature)\b',
                             "Non-constant-time string comparison for secret — use hmac.compare_digest() to prevent timing attacks"),
        # ReDoS
        ("SEC078", "MEDIUM", r'\bre\.compile\s*\(.*\b(request\.(args|form|values|json)|input\s*\()',
                             "User-controlled regex pattern — catastrophic backtracking (ReDoS) risk"),
        # Insecure temp file
        ("SEC079", "MEDIUM", r'\btempfile\.mktemp\s*\(',
                             "tempfile.mktemp() is insecure (race condition) — use tempfile.mkstemp() instead"),
        # subprocess shell=True
        ("SEC080", "HIGH",   r'\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\([^)]*\bshell\s*=\s*True',
                             "subprocess with shell=True — command injection risk, avoid or sanitize inputs"),
        # SSL weak protocols
        ("SEC081", "HIGH",   r'\bssl\.PROTOCOL_(?:TLSv1|SSLv2|SSLv3|SSLv23)\b',
                             "Weak SSL/TLS protocol version — use ssl.PROTOCOL_TLS_CLIENT with minimum TLS 1.2"),
        ("SEC082", "HIGH",   r'\bverify\s*=\s*False\b|\bcheck_hostname\s*=\s*False\b',
                             "SSL certificate verification disabled — vulnerable to MITM attacks"),
        # Python log injection
        ("SEC122", "MEDIUM", r'\b(logging\.(info|debug|warning|error|critical|exception)|logger\.(info|debug|warning|error|critical|exception))\s*\(.*\+.*\b(request\.(args|form|values|json|GET|POST)|input\s*\()',
                             "Log injection: user-controlled data in log message — sanitize newlines and control characters"),
        # os.exec family
        ("SEC124", "HIGH",   r'\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\(',
                             "os.exec* replaces the current process — injection risk if arguments are user-controlled"),
        # XML bomb
        ("SEC084", "HIGH",   r'<!ENTITY\s+\w+\s+["\'].*&\w+;.*["\']',
                             "Potential XML entity expansion attack (XML bomb / billion laughs)"),
        # Python ssl protocol check
        ("SEC123", "HIGH",   r'\bssl\.wrap_socket\s*\(',
                             "ssl.wrap_socket() is deprecated — use ssl.SSLContext with TLSv1.2+ minimum"),
    ],

    "javascript": [
        ("SEC001", "HIGH",   r'(?<!\.)(?<!["\'])\b(password|api_?key|secret|token|access_?token|auth_?token)\s*[=:]\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC006", "HIGH",   r'innerHTML\s*=',                "XSS risk via innerHTML assignment"),
        ("SEC026", "HIGH",   r'\b(Handlebars|Mustache)\.compile\s*\(|\b_\.template\s*\(|\bng-bind-html\b|\$sce\.trustAsHtml\s*\(|\bv-html\s*=|\{\{\{[^}]+\}\}\}',
                             "Client-side template injection risk"),
        ("SEC026B", "HIGH",  r'\b(Handlebars|Mustache|nunjucks|ejs|pug)\.(compile|render|renderString)\s*\(.*\b(req\.(params|query|body)|request\.(params|query|body))',
                             "SSTI risk: server-side template source built from user input"),
        ("SEC026C", "MEDIUM", r'\b_\.template\s*\(.*\b(req\.(params|query|body)|request\.(params|query|body))',
                             "SSTI risk: lodash template compiled from user input"),
        ("SEC006", "HIGH",   r'document\.write\s*\(',         "XSS risk via document.write()"),
        ("SEC007", "HIGH",   r'dangerouslySetInnerHTML',      "React XSS risk — dangerouslySetInnerHTML"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|res\.setHeader\s*\(\s*["\"]Content-Security-Policy["\"]|http-equiv\s*=\s*["\"]Content-Security-Policy["\"]',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC033", "HIGH",   r'\b(upload\.single|upload\.array|multer\.single|multer\.array|formidable\.IncomingForm|busboy)\b',
                             "High-risk NodeJS file upload handling detected - verify allowlist and storage path safety"),
        ("SEC033B", "LOW",   r'\b(req\.files|req\.file)\b',
                             "File upload request data is referenced - ensure file validation and sanitizer usage"),
        ("SEC034", "MEDIUM", r'\b(path\.extname|mime\.lookup|file\.type)\b',
                             "File type/extension inspection found; confirm strict allowlist behavior"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\bfs\.(readFile|readFileSync|createReadStream|writeFile|writeFileSync|existsSync|access|open|stat)\s*\(.*\b(req\.(params|query|body|path)|request\.(params|query|body))',
                             "File system operation with user-controlled input — path traversal risk"),
        ("SEC035B", "HIGH",  r'\bpath\.(join|resolve)\s*\(.*\b(req\.(params|query|body)|request\.(params|query|body))',
                             "Path construction with user input — validate against traversal"),
        ("SEC035C", "HIGH",  r'\b(res\.sendFile|res\.download)\s*\(.*\b(req\.(params|query|body))',
                             "Serving file based on user input — path traversal risk"),
        ("SEC027", "HIGH",   r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC039", "HIGH",   r'%00.*\b(fs\.|path\.|read|file|require)',
                             "Null byte in file path context — path truncation risk"),
        ("SEC037", "MEDIUM", r'["\']/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline|maps|fd/)|\.ssh/(id_rsa|authorized_keys)',
                             "Reference to sensitive system file — possible LFI target"),
        ("SEC042", "MEDIUM", r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd|root)',
                             "Access to /proc filesystem — information disclosure risk"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC043", "HIGH",   r'(?i)algorithms?\s*:\s*[\[\(]?\s*["\']none["\']',
                             "JWT 'none' algorithm — allows unsigned token forgery"),
        ("SEC044", "MEDIUM", r'\bjwt\.decode\s*\(',
                             "jwt.decode() does not verify signatures — use jwt.verify() for auth decisions"),
        ("SEC050", "HIGH",   r'ignoreExpiration\s*:\s*true',
                             "JWT expiration validation disabled — expired tokens accepted"),
        ("SEC046", "HIGH",   r'jwt\.(sign|verify)\s*\([^,]+,\s*["\'][^"\']{1,20}["\']',
                             "JWT with short hardcoded secret — crackable via hashcat"),
        ("SEC049", "MEDIUM", r'\bheader\s*\.\s*(kid|jku|x5u)\b|\[\s*["\'](kid|jku|x5u)["\']\s*\]',
                             "JWT kid/jku/x5u header accessed — validate against injection"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'\.(search|bind)\s*\(.*\b(req\.(params|query|body)|request\.(params|query|body))',
                             "LDAP operation with user-controlled input — injection risk"),
        ("SEC053", "HIGH",   r'filter\s*[:=]\s*[`"\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|sAMAccountName)\s*=.*\$\{',
                             "LDAP filter built with template literal — injection risk"),
        ("SEC053", "HIGH",   r'["\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|sAMAccountName)\s*=.*["\'].*\+\s*\w',
                             "LDAP filter built via string concatenation — injection risk"),
        # -- Open Redirect (SEC056) --
        ("SEC056", "MEDIUM", r'\b(res|response)\.redirect\s*\(.*\b(req\.(query|params|body)|request\.(query|params|body))',
                             "Redirect with user-controlled input - open redirect risk"),
        # ── NoSQL Injection (SEC054-SEC055) ──
        ("SEC054", "HIGH",   r'["\']\$where["\']',
                             "MongoDB $where executes JavaScript — NoSQL injection risk if user-controlled"),
        ("SEC004", "HIGH",   r'(query|sql)\s*[=+]\s*[`"\'].*\$\{', "Possible SQL injection via template literal"),
        ("SEC004", "HIGH",   r'''(query|sql)\s*=\s*['"`][^'"`]*(SELECT|INSERT|UPDATE|DELETE)[^'"`]*['"`]\s*\+''',
                             "SQL injection: query string built with + concatenation"),
        ("SEC006", "HIGH",   r'\bres\.(send|write)\s*\(.*\+.*\b(req\.(query|body|params)|request\.(query|body|params))',
                             "XSS: server response built by concatenating user input"),
        ("SEC006", "HIGH",   r'\bres\.(send|write)\s*\(`[^`]*\$\{.*\b(req\.(query|body|params))',
                             "XSS: server response built with user input in template literal"),
        ("SEC057", "MEDIUM", r'\b(graphql|execute|executeOperation)\s*\(.*\b(req\.(body|query|params)|request\.(body|query|params))',
                             "GraphQL execution with user input as query string - injection risk"),
        ("SEC057B","MEDIUM", r'\bgql\s*`[^`]*\$\{[^}]*\b(req\.(body|query|params)|request\.(body|query|params))',
                             "GraphQL query template literal includes user input - injection risk"),
        ("SEC008", "MEDIUM", r'Math\.random\s*\(',            "Math.random() is not cryptographically secure"),
        ("SEC009", "MEDIUM", r'(http|ws)://',                 "Insecure protocol (use https/wss)"),
        ("SEC010", "LOW",    r'console\.(log|debug|info)\s*\(', "Debug logging left in code"),
        ("SEC024", "MEDIUM", r'\.normalize\s*\(\s*["\']-(NFC|NFD|NFKC|NFKD)-',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bpunycode\.(toASCII|toUnicode)\s*\(|\b(domainToASCII|domainToUnicode)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # Prototype pollution
        ("SEC086", "HIGH",   r'(?:__proto__|constructor\s*\[|prototype\s*\[)',
                             "Prototype pollution vector: __proto__ or constructor[prototype] assignment"),
        ("SEC086", "HIGH",   r'Object\.assign\s*\(\s*(?:\{\}|[a-zA-Z_$][\w$]*)\s*,\s*(?:JSON\.parse|req\.|request\.)',
                             "Prototype pollution via Object.assign with parsed/user-controlled data"),
        # ReDoS
        ("SEC087", "MEDIUM", r'new\s+RegExp\s*\(.*\b(req\.(query|params|body)|request\.(query|params|body))',
                             "User-controlled regex (ReDoS risk) — never pass user input directly to new RegExp()"),
        ("SEC087", "MEDIUM", r'\bnew\s+RegExp\s*\(\s*[A-Za-z_$][\w$]*',
                             "Regex from variable (potential ReDoS) — ensure pattern is not user-controlled"),
        # XXE
        ("SEC088", "MEDIUM", r'\bnew\s+DOMParser\s*\(|\bxml2js\.parseString\s*\(|\bfast-xml-parser\b|require\s*\(\s*["\']xml2js["\']\s*\)',
                             "XML parser usage — ensure external entity expansion is disabled to prevent XXE"),
        # Insecure deserialization
        ("SEC089", "HIGH",   r'\bserialize\s*\(|\bnode-serialize\b|require\s*\(\s*["\']node-serialize["\']\s*\)',
                             "node-serialize: deserializing untrusted data can lead to RCE"),
        # CORS
        ("SEC090", "HIGH",   r'Access-Control-Allow-Origin.*\*|res\.header\s*\(\s*["\']Access-Control-Allow-Origin["\']\s*,\s*["\'][*]["\']\s*\)',
                             "CORS wildcard (Access-Control-Allow-Origin: *) — restrict to specific trusted origins"),
        ("SEC114", "HIGH",   r'Access-Control-Allow-Credentials.*true.*Access-Control-Allow-Origin.*\*|Access-Control-Allow-Origin.*\*.*Access-Control-Allow-Credentials.*true',
                             "CORS wildcard with credentials=true — browsers block this but audit configuration"),
        # Crypto
        ("SEC091", "MEDIUM", r'\bcrypto\.createCipher\s*\(',
                             "crypto.createCipher() is deprecated — use crypto.createCipheriv() with explicit IV"),
        ("SEC074", "MEDIUM", r'["\']aes-\d+-ecb["\']|createCipheriv\s*\(\s*["\'][^"\']*ecb["\']',
                             "ECB cipher mode — does not provide semantic security, use CBC or GCM mode"),
        # YAML injection
        ("SEC111", "HIGH",   r'\byaml\.load\s*\(|\brequire\s*\(\s*["\']js-yaml["\']\s*\).*\.load\s*\(',
                             "js-yaml yaml.load() unsafe — use yaml.safeLoad() or load with SAFE_SCHEMA"),
        # Path traversal Express
        ("SEC112", "HIGH",   r'\bres\.sendFile\s*\(.*\b(req\.(query|params|body)|request\.(query|params|body))',
                             "Express res.sendFile with user input — path traversal risk, use path.basename() and whitelist"),
        # Timing attack
        ("SEC113", "MEDIUM", r'(?:token|secret|password|hash|signature|key)\s*===?\s*\w|\w\s*===?\s*(?:token|secret|password|hash|signature)',
                             "Non-constant-time comparison for secret — use crypto.timingSafeEqual() to prevent timing attacks"),
        # X-Frame-Options
        ("SEC129", "LOW",    r'X-Frame-Options.*ALLOWALL|res\.(?:set|setHeader)\s*\(\s*["\']X-Frame-Options["\']\s*,\s*["\']ALLOWALL["\']\s*\)',
                             "X-Frame-Options set to ALLOWALL — allows clickjacking from any origin"),
        # child_process injection
        ("SEC080", "HIGH",   r'\bchild_process\b.*\b(exec|execSync|spawn|spawnSync)\s*\(.*\b(req\.(query|params|body)|request\.(query|params|body))',
                             "child_process execution with user input — command injection risk"),
        # dangerouslySetInnerHTML already in SEC007 but add explicit with user input
        ("SEC007", "HIGH",   r'dangerouslySetInnerHTML\s*=\s*\{\s*\{.*\b(props\.|state\.|this\.state|req\.|request\.)',
                             "React dangerouslySetInnerHTML with dynamic/user data — XSS risk"),
        # ── expr-eval CVE-2025-12735: RCE via evaluate() function injection ──
        ("SEC136", "CRITICAL", r'require\s*\(\s*["\']expr-eval["\']\s*\)|from\s+["\']expr-eval["\']',
                             "expr-eval imported — CVE-2025-12735: Parser.evaluate() allows RCE via function injection in the context object; maintainer unresponsive, main branch unpatched"),
        ("SEC136", "CRITICAL", r'\.evaluate\s*\(\s*(?:[^,)]+,\s*)?\b(req\.(query|params|body|headers)|request\.(query|params|body|headers)|userInput|userData|ctx|context|input|data)\b',
                             "expr-eval .evaluate() called with user-controlled context — CVE-2025-12735: attacker can inject arbitrary functions to achieve RCE"),
    ],

    "php": [
        ("SEC001", "HIGH",   r'\$?(password|api_key|secret)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC011", "MEDIUM", r'(?<!htmlspecialchars\()(?<!htmlentities\()(?<!intval\()(?<!filter_var\()(?<!strip_tags\()\$_(GET|POST|REQUEST|COOKIE)\[',
                             "User input used without immediate sanitization — verify downstream handling"),
        ("SEC012", "HIGH",   r'\bshell_exec\s*\((?!.*escapeshellarg)(?!.*escapeshellcmd)|\bsystem\s*\((?!.*escapeshellarg)(?!.*escapeshellcmd)|\bpassthru\s*\((?!.*escapeshellarg)',
                             "Shell execution function — injection risk (use escapeshellarg to sanitise)"),
        ("SEC004", "HIGH",   r'mysql_query\s*\(.*\$',        "Possible SQL injection"),
        # Enhanced PHP SQL injection patterns - catch string concatenation
        ("SEC004", "HIGH",   r'\b(mysqli_query|mysql_query|pg_query|mssql_query)\s*\([^)]*\$[a-zA-Z_][\w\[\]]*\s*[)\.]',
                             "SQL query function with variable — possible SQL injection"),
        ("SEC004", "HIGH",   r'\$\w+\s*=\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*["\'].*\.\s*\$_(GET|POST|REQUEST|COOKIE)',
                             "SQL query string concatenated with user input — SQL injection risk"),
        ("SEC004", "HIGH",   r'\$\w+\s*=\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*["\'].*\.\s*\$[a-zA-Z_]',
                             "SQL query built via string concatenation — verify input sanitization"),
        ("SEC057", "MEDIUM", r'GraphQL\\GraphQL::executeQuery\s*\(.*\b\$_(GET|POST|REQUEST|COOKIE)',
                             "GraphQL execution with user input as query string - injection risk"),
        ("SEC013", "HIGH",   r'\bmd5\s*\(|\bsha1\s*\(',      "Weak hashing (MD5/SHA1)"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|header\s*\(\s*["\"]Content-Security-Policy["\"]|http-equiv\s*=\s*["\"]Content-Security-Policy["\"]',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC026", "HIGH",   r'\b(template\(|Twig::create|\{\{[^}]+\}\})\b',
                             "Template injection risk"),
        ("SEC026B", "HIGH",  r'\b(Twig\\Environment|Twig_Environment)\b.*\b(createTemplate|render)\s*\(.*\b\$_(GET|POST|REQUEST|COOKIE)',
                             "SSTI risk: Twig template source from user input"),
        ("SEC026C", "MEDIUM", r'\btemplate\s*\(.*\b\$_(GET|POST|REQUEST|COOKIE)',
                             "SSTI risk: template source built from user input"),
        ("SEC029", "HIGH",   r'\bunserialize\s*\((?![^)]*allowed_classes)',
                             "Unserialize() call without allowed_classes - potential object injection"),
        ("SEC030", "HIGH",   r'function\s+__(sleep|wakeup|unserialize|destruct|toString)\s*\(',
                             "Magic methods used (sleep/wakeup/unserialize/destruct/toString) - verify deserialization-safe patterns"),
        ("SEC031", "HIGH",   r'(?i)(phar:\/\/|Phar::).*(unserialize|fopen|file_get_contents|file_exists|include|require|readfile|glob)',
                             "Risky phar usage in deserialization/file access context — needs review"),
        ("SEC031B", "LOW",   r'(?i)(phar:\/\/|Phar::)',
                             "Phar usage detected — verify it is safe and not under attacker control"),
        ("SEC032", "HIGH",   r'\b(spl_autoload_register|__autoload)\s*\(',
                             "Autoload hooks used - check for dangerous dynamic class loading in deserialization chains"),
        ("SEC033", "HIGH",   r'\b(move_uploaded_file|is_uploaded_file|\$_FILES|UPLOAD_ERR_\w+)\b',
                             "File upload handling found - verify secure filename checks, extension/mime allowlist, and path traversal protections"),
        ("SEC034", "MEDIUM", r'\b(pathinfo\s*\(.*PATHINFO_EXTENSION|mime_content_type\(|finfo_file\()\b',
                             "File type/extension detection is in place; ensure allowlist is used and not bypassed"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\b(include|require|include_once|require_once)\s*[\(]?\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)',
                             "File inclusion with direct user input — critical LFI vulnerability"),
        ("SEC035B", "HIGH",  r'\b(include|require|include_once|require_once)\s*[\(]?\s*\$[a-zA-Z_]\w*\s*[;\.\)]',
                             "File inclusion via variable — verify input is not user-controlled"),
        ("SEC036", "HIGH",   r'(php://(filter|input|fd)|expect://|data://text|zip://[^i]|phar://)',
                             "PHP stream wrapper — exploitable for LFI/RCE if user-controlled"),
        ("SEC035C", "HIGH",  r'\b(file_get_contents|fopen|readfile|file\b|fread|parse_ini_file|highlight_file|show_source)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                             "File function with direct user input — path traversal risk"),
        ("SEC040", "MEDIUM", r'\bstr_replace\s*\(\s*["\']\.\.(/|\\\\)["\']',
                             "Naive path traversal filter — bypassable with ....// or encoding"),
        ("SEC041", "MEDIUM", r'\b(include|require|file_get_contents|fopen)\s*\(.*(/var/log/|access\.log|error\.log)',
                             "Log file in inclusion/read context — log poisoning vector"),
        ("SEC041B", "MEDIUM",r'\b(include|require)\s*\(.*(/var/lib/php|/tmp/sess_|sess_.*PHPSESSID)',
                             "PHP session file inclusion — session poisoning risk"),
        ("SEC027", "HIGH",   r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC039", "HIGH",   r'%00.*\b(include|require|fopen|file_get_contents|readfile)',
                             "Null byte in file inclusion context — path truncation risk"),
        ("SEC037", "MEDIUM", r'["\']/etc/(passwd|shadow|hosts)|/proc/self/(environ|cmdline)|\.ssh/id_rsa|C:\\\\(boot\.ini|windows\\\\win\.ini)',
                             "Reference to sensitive system file — possible LFI target"),
        ("SEC042", "MEDIUM", r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd)',
                             "Access to /proc filesystem — information disclosure risk"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC043", "HIGH",   r'(?i)["\']alg["\']\s*=>\s*["\']none["\']|["\']none["\'].*\balgorithm',
                             "JWT 'none' algorithm — allows unsigned token forgery"),
        ("SEC044", "HIGH",   r'json_decode\s*\(\s*base64_decode\s*\(.*\b(jwt|token)\b',
                             "Manual JWT base64 decode without signature verification"),
        ("SEC046", "HIGH",   r'(?i)(JWT_SECRET|jwt_key|jwt_secret)\s*=\s*["\'][^"\']{1,20}["\']',
                             "Weak or hardcoded JWT secret — crackable via hashcat"),
        ("SEC048", "HIGH",   r'\$\w*(kid|header)\w*\s*.*\b(include|require|fopen|file_get_contents|mysql|query|exec|system|pdo)',
                             "JWT kid/header value flows into dangerous sink — injection risk"),
        ("SEC049", "MEDIUM", r'->(?:kid|jku|x5u)\b|\$\w*(?:kid|jku|x5u)',
                             "JWT kid/jku/x5u header extracted — validate against path traversal and injection"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'\bldap_search\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
                             "ldap_search with user input — LDAP injection risk"),
        ("SEC051B", "HIGH",  r'\bldap_(list|read)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
                             "LDAP query function with user input — injection risk"),
        ("SEC052", "HIGH",   r'\bldap_bind\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
                             "ldap_bind with user input — authentication bypass risk"),
        ("SEC053", "HIGH",   r'\bldap_(search|list|read)\s*\(.*\.\s*\$\w',
                             "LDAP query with string concatenation — injection risk"),
        ("SEC053B", "HIGH",  r'["\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|userPassword|sAMAccountName)\s*=.*["\'].*\.\s*\$',
                             "LDAP filter built via PHP string concatenation — injection risk"),
        # -- Open Redirect (SEC056) --
        ("SEC056", "MEDIUM", r'header\s*\(\s*["\']Location:\s*["\']\s*\.\s*\$_(GET|POST|REQUEST|COOKIE)|header\s*\(\s*["\']Location:.*\$_(GET|POST|REQUEST|COOKIE)',
                             "Redirect with user-controlled input - open redirect risk"),
        # ── NoSQL Injection (SEC054-SEC055) ──
        ("SEC054", "HIGH",   r'["\']\$where["\']',
                             "MongoDB $where executes JavaScript — NoSQL injection risk if user-controlled"),
        ("SEC014", "MEDIUM", r'error_reporting\s*\(\s*E_ALL', "Verbose error reporting enabled"),
        ("SEC024", "MEDIUM", r'\bNormalizer::normalize\s*\(|\bnormalizer_normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bidn_to_(ascii|utf8)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # SSRF
        ("SEC092", "HIGH",   r'\bcurl_init\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|\bfile_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                             "SSRF risk: PHP URL fetch with user-controlled URL — validate and whitelist destinations"),
        # SSL verification disabled
        ("SEC097", "HIGH",   r'\bcurl_setopt\s*\(.*CURLOPT_SSL_VERIFYPEER\s*,\s*(0|false|null)\b',
                             "PHP cURL SSL verification disabled (CURLOPT_SSL_VERIFYPEER=false) — vulnerable to MITM"),
        # Type juggling - NARROWED to reduce false positives (only security-critical contexts)
        ("SEC093", "HIGH",   r'\b(password|passwd|pwd|hash|token|secret|auth|admin|login|session|role|permission|privilege)\s*==\s*(0|false|null|true|["\'][^"\']*["\'])|if\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*==\s*(0|false|null|true)|==\s*(0|false|null)\s*&&.*\b(auth|login|admin|session)',
                             "PHP loose comparison (==) in security-sensitive context — type juggling can bypass authentication, use ==="),
        # extract/parse_str injection
        ("SEC094", "HIGH",   r'\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|\bparse_str\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)',
                             "extract() or parse_str() with user input — variable injection risk"),
        # preg_replace /e modifier
        ("SEC095", "HIGH",   r'\bpreg_replace\s*\(\s*["\'][^"\']*\/e["\']',
                             "preg_replace() with /e modifier executes PHP code — use preg_replace_callback() instead"),
        # mcrypt / weak crypto
        ("SEC096", "HIGH",   r'\b(mcrypt_encrypt|mcrypt_decrypt|mcrypt_module_open)\s*\(',
                             "mcrypt is deprecated — use OpenSSL or Sodium for encryption"),
        ("SEC135", "MEDIUM", r'\b(crypt\s*\(|str_rot13\s*\(|hash\s*\(\s*["\'](?:md5|sha1|crc32)["\'])',
                             "Weak PHP cryptographic function — use password_hash() for passwords, SHA256+ for hashing"),
        # XXE
        ("SEC126", "HIGH",   r'\bsimplexml_load_(?:string|file)\s*\(.*LIBXML_NOENT|\bnew\s+DOMDocument\s*\(.*LIBXML_NOENT',
                             "PHP XML parser with LIBXML_NOENT enables external entity processing — XXE risk"),
        ("SEC126", "HIGH",   r'\blibxml_disable_entity_loader\s*\(\s*false\s*\)',
                             "libxml_disable_entity_loader(false) explicitly enables external entity loading — XXE risk"),
        # phpinfo exposure
        ("SEC125", "MEDIUM", r'\bphpinfo\s*\(',
                             "phpinfo() exposes server configuration and installed modules — remove from production code"),
        # mb_ereg_replace /e
        ("SEC127", "HIGH",   r'\bmb_ereg_replace\s*\([^,]+,[^,]+,[^,]+,\s*["\'][^"\']*e["\']',
                             "mb_ereg_replace() with 'e' modifier executes PHP code — use mb_ereg_replace_callback()"),
        # Backtick operator
        ("SEC134", "HIGH",   r'`[^`]*\$[a-zA-Z_]',
                             "Backtick operator with variable — shell command injection risk"),
    ],

    "java": [
        ("SEC001", "HIGH",   r'\b(password|apiKey|secret)\s*=\s*"[^"]{4,}"',
                             "Hardcoded secret"),
        ("SEC004", "HIGH",   r'(createQuery|executeQuery|prepareStatement)\s*\(.*\+',
                             "Possible SQL injection via string concatenation"),
        ("SEC004", "HIGH",   r'\bStatement\b.*\bcreateStatement\b|\bstmt\.executeQuery\s*\(\s*query\s*\)|\bstmt\.execute\s*\(\s*query\s*\)',
                             "SQL injection: Statement.executeQuery with assembled query string"),
        ("SEC015", "HIGH",   r'Runtime\.getRuntime\(\)\.exec\s*\(',
                             "OS command execution — injection risk"),
        ("SEC016", "HIGH",   r'ObjectInputStream',           "Java deserialization — potential RCE"),
        ("SEC005", "MEDIUM", r'MessageDigest\.getInstance\("(MD5|SHA-1)"',
                             "Weak hashing algorithm"),
        ("SEC017", "MEDIUM", r'\.printStackTrace\s*\(',      "Stack trace exposed — info leakage"),
        ("SEC009", "MEDIUM", r'"http://',                    "Insecure HTTP protocol"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|response\.setHeader\s*\(\s*["\"]Content-Security-Policy["\"]|http-equiv\s*=\s*["\"]Content-Security-Policy["\"]',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC033", "HIGH",   r'\b(ServletFileUpload\.getItemIterator|request\.getPart|@MultipartConfig)\b',
                             "High-risk Java file upload handler pattern found - verify path traversal and content gate"),
        ("SEC033B", "LOW",   r'\b(org\.apache\.commons\.fileupload|Part)\b',
                             "Identified Java fileupload library usage - confirm sufficiency of security checks"),
        ("SEC034", "MEDIUM", r'\b(\bfilename\b|path\.toLowerCase\(|MimeType|isMimeTypeValid)\b',
                             "File upload metadata parsing detected - ensure strict constraints are applied"),
        ("SEC026", "HIGH",   r'\b(Template|VelocityEngine|FreemarkerConfiguration|handlebars)\b',
                             "Possible template injection risk"),
        ("SEC026B", "HIGH",  r'\b(Template|VelocityEngine)\b.*\b(StringReader|evaluate|compile|process)\b.*\b(request\.getParameter|getQueryString|getPathInfo)',
                             "SSTI risk: template source built from user input"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\b(new\s+File|FileInputStream|FileReader|Files\.(readAllBytes|readString|newInputStream)|Paths\.get)\s*\(.*\b(request\.getParameter|getServletPath|getPathInfo|getRequestURI)',
                             "File operation with request parameter — path traversal risk"),
        ("SEC035B", "HIGH",  r'\b(new\s+File|Paths\.get)\s*\(.*\+\s*.*(request|req|param|input)',
                             "File path built via concatenation with user input — path traversal risk"),
        ("SEC035C", "HIGH",  r'\b(RequestDispatcher|getRequestDispatcher|forward|include)\s*\(.*\b(request\.getParameter|getPathInfo)',
                             "Request dispatch with user input — server-side inclusion risk"),
        ("SEC027", "HIGH",   r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC037", "MEDIUM", r'["\']/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline|maps|fd/)|\.ssh/(id_rsa|authorized_keys)',
                             "Reference to sensitive system file — possible LFI target"),
        ("SEC042", "MEDIUM", r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd|root)',
                             "Access to /proc filesystem — information disclosure risk"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC043", "HIGH",   r'(?i)["\']none["\'].*\b(algorithm|alg|SigningAlgorithm)|SigningAlgorithm.*NONE',
                             "JWT 'none' algorithm — allows unsigned token forgery"),
        ("SEC044", "HIGH",   r'\.parseClaimsJwt\s*\(',
                             "parseClaimsJwt() does not verify signatures — use parseClaimsJws()"),
        ("SEC046", "HIGH",   r'\.setSigningKey\s*\(\s*["\'][^"\']{1,20}["\']',
                             "JWT with short hardcoded signing key — crackable via hashcat"),
        ("SEC046B", "HIGH",  r'\.setSigningKey\s*\(\s*["\'][^"\']+["\']\.getBytes',
                             "JWT signing key from hardcoded string literal"),
        ("SEC049", "MEDIUM", r'\.getHeaderClaim\s*\(\s*["\']kid["\']|header\.get\s*\(\s*["\'](kid|jku|x5u)["\']',
                             "JWT kid/jku/x5u header accessed — validate against injection"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'\.(search|list)\s*\(.*\b(request\.getParameter|getQueryString|getPathInfo)',
                             "LDAP search with request parameter — injection risk"),
        ("SEC052", "HIGH",   r'(InitialDirContext|InitialLdapContext|DirContext)\s*\(.*\+.*\b(request\.getParameter|getQueryString)',
                             "LDAP context with user input — authentication bypass risk"),
        ("SEC053", "HIGH",   r'["\'].*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|sAMAccountName)\s*=.*["\'].*\+\s*.*(request|param|input)',
                             "LDAP filter built via concatenation with user input — injection risk"),
        # -- Open Redirect (SEC056) --
        ("SEC056", "MEDIUM", r'\.sendRedirect\s*\(.*\b(request\.getParameter|getParameter\s*\()',
                             "Redirect with user-controlled input - open redirect risk"),
        # ── NoSQL Injection (SEC054-SEC055) ──
        ("SEC054", "HIGH",   r'["\']\$where["\']',
                             "MongoDB $where executes JavaScript — NoSQL injection risk if user-controlled"),
        ("SEC024", "MEDIUM", r'\bNormalizer\.normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bIDN\.(toASCII|toUnicode)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # XXE - DocumentBuilderFactory
        ("SEC098", "HIGH",   r'\bDocumentBuilderFactory\.newInstance\s*\(|\bnew\s+DocumentBuilder\b|\bSAXParserFactory\.newInstance\s*\(',
                             "XML parser factory without disabling external entities — XXE risk, set FEATURE_SECURE_PROCESSING"),
        ("SEC083", "HIGH",   r'\bXMLInputFactory\.newInstance\s*\(|\bXMLInputFactory\.newFactory\s*\(',
                             "XMLInputFactory without disabling external entities — XXE risk"),
        # SSRF
        ("SEC099", "HIGH",   r'\bnew\s+URL\s*\([^)]*(?:request\.getParameter|getQueryString|getPathInfo)\s*\(|new\s+URL\s*\(.*\+\s*(?:request|param|input)\b',
                             "Java SSRF: new URL() with user input — validate and whitelist URL destinations"),
        # Deserialization
        ("SEC100", "HIGH",   r'\bXMLDecoder\s*\(|\bXStream\b|\bObjectInputStream\b.*\breadObject\s*\(',
                             "Insecure Java deserialization (XMLDecoder/XStream/ObjectInputStream) — can lead to RCE"),
        ("SEC118", "HIGH",   r'\benableDefaultTyping\s*\(|\bactivateDefaultTyping\s*\(',
                             "Jackson enableDefaultTyping()/activateDefaultTyping() — polymorphic deserialization RCE risk"),
        ("SEC119", "HIGH",   r'\bnew\s+Yaml\s*\(\s*\)(?!\s*\.\s*(?:setTag|addImplicitResolver|setBeanAccess))|org\.yaml\.snakeyaml\.Yaml\s*\(\s*\)',
                             "SnakeYAML Yaml() without SafeConstructor — unsafe deserialization, use new Yaml(new SafeConstructor())"),
        # Log injection
        ("SEC101", "MEDIUM", r'\b(?:log(?:ger)?|LOG)\s*\.\s*(?:info|warn|error|debug|trace)\s*\(\s*["\'][^"\']*["\']\s*\+\s*(?:request\.getParameter|getQueryString|getPathInfo)',
                             "Log injection: user-controlled data concatenated in log message — sanitize newlines and control characters"),
        # Crypto
        ("SEC102", "HIGH",   r'Cipher\.getInstance\s*\(\s*["\'](?:AES/ECB|DES|DESede|RC2|RC4|Blowfish)["\']',
                             "Insecure cipher algorithm or mode (ECB/DES/3DES/RC4) — use AES/GCM/NoPadding"),
        # SpEL injection
        ("SEC120", "HIGH",   r'\bSpelExpressionParser\b|\bExpressionParser\b.*\bparseExpression\b|\b@Value\s*\(\s*["\']#\{.*\+',
                             "Spring Expression Language (SpEL) with dynamic/user-controlled expression — SpEL injection risk"),
        # YAML
        ("SEC119", "HIGH",   r'\byaml\.load\s*\(|\bYaml\s*\(\s*\)\s*\.\s*load\s*\(',
                             "Unsafe YAML load — use SafeConstructor to prevent object deserialization"),
    ],

    "go": [
        ("SEC001", "HIGH",   r'\b(password|apiKey|secret)\s*(?::=|=)\s*"[^"]{4,}"',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\bexec\.Command\s*\(',        "OS command execution"),
        ("SEC004", "HIGH",   r'(Query|Exec)\s*\(.*\+',       "Possible SQL injection via concatenation"),
        ("SEC009", "MEDIUM", r'"http://',                    "Insecure HTTP protocol"),
        ("SEC018", "MEDIUM", r'math/rand',                   "math/rand is not cryptographically secure — use crypto/rand"),
        ("SEC019", "LOW",    r'fmt\.Println\s*\(',           "Debug print statement"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|w.Header\(\)\.Set\s*\(\s*["\"]Content-Security-Policy["\"]|http-equiv\s*=\s*["\"]Content-Security-Policy["\"]',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC033", "HIGH",   r'\b(FormFile\(|ParseMultipartForm\(|http\.MaxBytesReader\()\b',
                             "High-risk Go file upload flow query found - validate filename and destination path"),
        ("SEC033B", "LOW",   r'\b(multipart\.FileHeader|Request\.MultipartForm)\b',
                             "Go multipart upload structs used - make sure file type/size checks are enforced"),
        ("SEC034", "LOW",    r'\bfilepath\.(Clean|Abs|Base)\s*\(',
                             "Path sanitization utility detected — confirm it is applied to all user-supplied file paths"),
        ("SEC026", "HIGH",   r'\b(template\.Execute|template\.Parse|text/template)\b',
                             "text/template usage — verify template source is not user-controlled (html/template is safe)"),
        ("SEC026B", "HIGH",  r'\btemplate\.(New|Parse|ParseFiles|ParseFS)\s*\(.*\b(r\.(FormValue|URL\.Query\(\)\.Get|PathValue)|req\.(FormValue|URL\.Query\(\)\.Get)|c\.(Param|Query))',
                             "SSTI risk: template source built from user input"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\b(os\.(Open|ReadFile|OpenFile)|ioutil\.ReadFile)\s*\(.*\b(r\.(URL|FormValue|PathValue)|req\.(URL|FormValue)|c\.(Param|Query))',
                             "File operation with user-controlled input — path traversal risk"),
        ("SEC035B", "HIGH",  r'\b(http\.ServeFile|http\.FileServer)\s*\(.*\b(r\.(URL|FormValue)|req\.URL)',
                             "Serving files based on user input — path traversal risk"),
        ("SEC040", "MEDIUM", r'strings\.Replace\s*\(.*["\']\.\.(/|\\\\)["\']',
                             "Naive path traversal filter — bypassable with encoding or ....//"),
        ("SEC027", "HIGH",   r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC037", "MEDIUM", r'["\']/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline|maps|fd/)|\.ssh/(id_rsa|authorized_keys)',
                             "Reference to sensitive system file — possible LFI target"),
        ("SEC042", "MEDIUM", r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd|root)',
                             "Access to /proc filesystem — information disclosure risk"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC043", "HIGH",   r'(?i)SigningMethodNone|jwt\.UnsafeAllowNoneSignatureType|["\']none["\'].*(?:alg|method)',
                             "JWT 'none' algorithm — allows unsigned token forgery"),
        ("SEC044", "HIGH",   r'jwt\.Parse\s*\(.*,\s*nil\b',
                             "JWT parsed with nil key function — no signature verification"),
        ("SEC046", "HIGH",   r'(?i)\[\]byte\s*\(\s*["\'][^"\']{1,20}["\']\s*\).*(?:sign|jwt|token)|(?:secret|key).*\[\]byte\s*\(\s*["\'][^"\']{1,20}["\']\s*\)',
                             "JWT with short hardcoded secret — crackable via hashcat"),
        ("SEC049", "MEDIUM", r'Header\s*\[\s*["\']kid["\']\s*\]|\.Header\.\s*(kid|jku|x5u)\b',
                             "JWT kid/jku/x5u header accessed — validate against injection"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'ldap\.NewSearchRequest\s*\(.*\b(r\.(FormValue|URL)|req\.|fmt\.Sprintf)',
                             "LDAP search with user-controlled input — injection risk"),
        ("SEC053", "HIGH",   r'fmt\.Sprintf\s*\(.*\((?:&|\|)?\(?\s*(?:uid|cn|sn|mail|ou|dc|objectClass|sAMAccountName)\s*=',
                             "LDAP filter built with fmt.Sprintf — injection risk"),
        # -- Open Redirect (SEC056) --
        ("SEC056", "MEDIUM", r'\bhttp\.Redirect\s*\(.*\b(r\.(URL\.Query\(\)\.Get|FormValue)|req\.(URL\.Query\(\)\.Get|FormValue))',
                             "Redirect with user-controlled input - open redirect risk"),
        # ── NoSQL Injection (SEC054-SEC055)
        ("SEC054", "HIGH",   r'["\']\$where["\']',
                             "MongoDB $where executes JavaScript — NoSQL injection risk if user-controlled"),
        ("SEC024", "MEDIUM", r'\bnorm\.(NFC|NFD|NFKC|NFKD)\.(String|Bytes)\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\b(idna\.(ToASCII|ToUnicode)|golang\.org/x/net/idna)\b',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # SSRF
        ("SEC103", "HIGH",   r'\bhttp\.Get\s*\(.*\b(?:r\.|req\.|c\.(?:Param|Query)|os\.Args|fmt\.Sprintf)',
                             "SSRF risk: http.Get with user-controlled URL — validate and whitelist destinations"),
        ("SEC103", "HIGH",   r'\bhttp\.(?:Post|Head|Do)\s*\(.*\b(?:r\.|req\.|c\.(?:Param|Query)|fmt\.Sprintf)',
                             "SSRF risk: http client call with potentially user-controlled URL"),
        # Weak crypto
        ("SEC104", "HIGH",   r'\bdes\.NewCipher\s*\(|\brc4\.NewCipher\s*\(|\bdes\.NewTripleDESCipher\s*\(|\bblowfish\.NewCipher\s*\(',
                             "Weak cipher (DES/3DES/RC4/Blowfish) — use AES-256-GCM from crypto/aes"),
        ("SEC104", "MEDIUM", r'\bmd5\.New\s*\(|\bmd5\.Sum\s*\(|\bsha1\.New\s*\(|\bsha1\.Sum\s*\(',
                             "Weak hash algorithm (MD5/SHA1) — use SHA256 or SHA3"),
        # TLS InsecureSkipVerify
        ("SEC105", "HIGH",   r'\bInsecureSkipVerify\s*:\s*true\b',
                             "TLS certificate verification disabled (InsecureSkipVerify:true) — vulnerable to MITM attacks"),
        # text/template injection
        ("SEC106", "HIGH",   r'\btemplate\.Must\s*\(\s*template\.New|text/template.*Execute\s*\(.*\b(?:r\.|req\.|c\.(?:Param|Query))',
                             "text/template with user-controlled data — use html/template for web content to prevent injection"),
        # Log injection
        ("SEC107", "MEDIUM", r'\b(?:log|logger)\s*\.\s*(?:Printf|Println|Sprintf)\s*\(.*\b(?:r\.|req\.|c\.(?:Param|Query)|os\.Args)',
                             "Log injection: user-controlled data in log message — sanitize newlines and control characters"),
        # Insecure tmp file
        ("SEC117", "MEDIUM", r'\bioutil\.WriteFile\s*\(\s*["\'][^"\']*(?:/tmp/|\\temp\\)',
                             "Insecure temp file creation in shared /tmp — use ioutil.TempFile/os.CreateTemp instead"),
        # Decompression bomb
        ("SEC128", "MEDIUM", r'\bflate\.NewReader\s*\(|\bgzip\.NewReader\s*\(|\bzlib\.NewReader\s*\(',
                             "Decompression without size limit — risk of decompression bomb (zip bomb) attack"),
    ],

    "bash": [
        ("SEC001", "HIGH",   r'\b(PASSWORD|API_KEY|SECRET|TOKEN)=["\'][^"\'$\s]{4,}',
                             "Hardcoded secret in env variable"),
        ("SEC020", "HIGH",   r'curl.*(-k|--insecure)',       "curl with SSL verification disabled"),
        ("SEC021", "HIGH",   r'eval\s+',                     "Use of eval in shell script"),
        ("SEC022", "MEDIUM", r'chmod\s+777',                 "Overly permissive file permissions"),
        ("SEC023", "MEDIUM", r'\b(rm|cp|mv|eval|bash|sh|chmod|chown|tar|find|cat|export|source|\.|exec)\s+[^|"\'\n]*?(?<![\'"])\$[A-Za-z_][A-Za-z0-9_]*(?!["\'])',
                             "Unquoted shell variable in command — word-splitting/globbing risk"),
        ("SEC026", "HIGH",   r'\b(curl\s+.*--data|wget\s+.*--post-data|envsubst|sed\s+.*\$\{)|\$\{[^}]+\}\}',
                             "Possible command/template injection risk"),
        # ── Path Traversal / File Inclusion (SEC027, SEC035-SEC042) ──
        ("SEC035", "HIGH",   r'\b(cat|less|more|head|tail|source|\.)\s+.*\$\{?[A-Za-z_]+\}?.*(/|\\)',
                             "File read command with unvalidated variable in path — traversal risk"),
        ("SEC027", "HIGH",   r'(\.\./|\.\.\\){3,}',
                             "Deep directory traversal sequence (3+ levels)"),
        ("SEC038", "HIGH",   r'(%2e(%2e|\.)|\.%2e)(%2f|%5c|/|\\)|%252e|%c0%ae|%c0%af',
                             "Encoded path traversal sequence — filter bypass attempt"),
        ("SEC037", "LOW",    r'/etc/(passwd|shadow|hosts|group)|/proc/self/(environ|cmdline)',
                             "Reference to sensitive system file"),
        ("SEC042", "LOW",    r'/proc/(self|[0-9]+)/(environ|cmdline|maps|status|fd/|cwd|root)',
                             "Access to /proc filesystem"),
        # ── JWT Security (SEC043-SEC050) ──
        ("SEC046", "HIGH",   r'(?i)(JWT_SECRET|JWT_KEY|JWT_SIGNING_KEY)\s*=\s*["\'][^"\']{1,20}["\']',
                             "Weak or hardcoded JWT secret in environment variable"),
        # ── LDAP Injection (SEC051-SEC053) ──
        ("SEC051", "HIGH",   r'\bldapsearch\b.*\$\{?[A-Za-z_]+\}?',
                             "ldapsearch with unvalidated variable - LDAP injection risk"),
        ("SEC052", "HIGH",   r'\bldap(whoami|passwd|modify|add|delete)\b.*\$\{?[A-Za-z_]+\}?',
                             "LDAP command with unvalidated variable - LDAP injection risk"),
        ("SEC064", "HIGH",   r'(?i)\b-Wl,-z,execstack\b|\b-z\s+execstack\b',
                             "Executable stack enabled (execstack) - disables NX/DEP, increases ROP risk"),
        ("SEC064B","HIGH",   r'(?i)\b-(fno-PIE|fno-pie|no-pie)\b',
                             "PIE disabled - weakens ASLR effectiveness"),
        ("SEC064C","HIGH",   r'(?i)\b-Wl,-z,norelro\b|\b-z\s+norelro\b',
                             "RELRO disabled - weakens GOT/PLT protections"),
        ("SEC064D","HIGH",   r'(?i)\b/NXCOMPAT\s*:\s*NO\b',
                             "NX/DEP disabled via /NXCOMPAT:NO - executable memory allowed"),
        ("SEC064E","HIGH",   r'(?i)\b/DYNAMICBASE\s*:\s*NO\b',
                             "ASLR disabled via /DYNAMICBASE:NO"),
        ("SEC009", "MEDIUM", r'http://',                     "Insecure HTTP protocol"),

        # ── Semgrep-derived new rules (SEC066+) ──────────────────────────────
        # curl/wget to arbitrary variable URLs
        ("SEC108", "HIGH",   r'\b(curl|wget)\s+[^|&;\n]*\$\{?[A-Za-z_][A-Za-z0-9_]*\}?',
                             "curl/wget with variable URL — user-controlled URL could lead to SSRF"),
        # IFS tampering
        ("SEC109", "MEDIUM", r'\bIFS\s*=',
                             "IFS variable modification — affects word splitting globally, can lead to unexpected command execution"),
        # Command substitution with user input
        ("SEC110", "HIGH",   r'\$\(.*\$\{?[1-9@*]\}?\s*\)|\`[^\`]*\$\{?[1-9@*]\}?[^\`]*\`',
                             "Command substitution with positional argument — shell injection risk if input is unsanitized"),
    ],
    "build": [
        ("SEC064", "HIGH",   r'(?i)\b-Wl,-z,execstack\b|\b-z\s+execstack\b',
                             "Executable stack enabled (execstack) - disables NX/DEP, increases ROP risk"),
        ("SEC064B","HIGH",   r'(?i)\b-(fno-PIE|fno-pie|no-pie)\b',
                             "PIE disabled - weakens ASLR effectiveness"),
        ("SEC064C","HIGH",   r'(?i)\b-Wl,-z,norelro\b|\b-z\s+norelro\b',
                             "RELRO disabled - weakens GOT/PLT protections"),
        ("SEC064D","HIGH",   r'(?i)\b/NXCOMPAT\s*:\s*NO\b',
                             "NX/DEP disabled via /NXCOMPAT:NO - executable memory allowed"),
        ("SEC064E","HIGH",   r'(?i)\b/DYNAMICBASE\s*:\s*NO\b',
                             "ASLR disabled via /DYNAMICBASE:NO"),
    ],
    "c": [
        ("SEC060", "MEDIUM", r'\bmmap\s*\([^;]*\bPROT_EXEC\b',
                             "Executable memory mapping (PROT_EXEC) - review for shellcode/JIT safety"),
        ("SEC060B","MEDIUM", r'\bmprotect\s*\([^;]*\bPROT_EXEC\b',
                             "Memory protection changed to executable (PROT_EXEC) - review for shellcode/JIT safety"),
        ("SEC060C","MEDIUM", r'\bVirtualAlloc\s*\([^;]*\bPAGE_EXECUTE(?:_READ|_READWRITE|_WRITECOPY)?\b',
                             "Executable memory allocation (PAGE_EXECUTE*) - review for shellcode/JIT safety"),
        ("SEC060D","MEDIUM", r'\bVirtualProtect\s*\([^;]*\bPAGE_EXECUTE(?:_READ|_READWRITE|_WRITECOPY)?\b',
                             "Memory protection changed to executable (PAGE_EXECUTE*) - review for shellcode/JIT safety"),
        ("SEC061", "HIGH",   r'\b(printf|vprintf|wprintf|vwprintf|printf_s)\s*\(\s*(argv\s*\[|getenv\s*\(|gets\s*\(|fgets\s*\(|scanf\s*\(|read\s*\(|recv\s*\(|getline\s*\(|getopt\s*\()',
                             "Possible format string vulnerability: printf-family format from user-controlled input"),
        ("SEC061", "HIGH",   r'\b(fprintf|sprintf|snprintf|vfprintf|vsprintf|vsnprintf|dprintf|syslog|err|errx|warn|warnx|asprintf|vasprintf)\s*\(\s*[^,]+,\s*(argv\s*\[|getenv\s*\(|gets\s*\(|fgets\s*\(|scanf\s*\(|read\s*\(|recv\s*\(|getline\s*\(|getopt\s*\()',
                             "Possible format string vulnerability: printf-family format from user-controlled input"),
        ("SEC062", "HIGH",   r'__attribute__\s*\(\s*\(\s*no_stack_protector\s*\)\s*\)',
                             "Stack protector explicitly disabled via no_stack_protector attribute"),
        ("SEC062B","HIGH",   r'__attribute__\s*\(\s*\(\s*optimize\s*\(\s*["\']no-stack-protector["\']\s*\)\s*\)\s*\)',
                             "Stack protector disabled via optimize(\"no-stack-protector\") attribute"),
        ("SEC062C","HIGH",   r'__declspec\s*\(\s*safebuffers\s*\)',
                             "MSVC safebuffers disables /GS stack checks"),
        ("SEC062D","HIGH",   r'#\s*pragma\s+GCC\s+optimize\s*\(\s*["\']?no-stack-protector["\']?\s*\)',
                             "GCC pragma disables stack protector"),
        ("SEC063", "HIGH",   r'\bpersonality\s*\(\s*[^;]*\bADDR_NO_RANDOMIZE\b',
                             "ASLR explicitly disabled via personality(ADDR_NO_RANDOMIZE)"),
        ("SEC063B","HIGH",   r'#\s*pragma\s+comment\s*\(\s*linker\s*,\s*["\']/DYNAMICBASE:NO["\']\s*\)',
                             "ASLR disabled via linker option /DYNAMICBASE:NO"),
        ("SEC065", "HIGH",   r'\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)\s*;\s*[^;]*\b(\1\s*->|\1\s*\[|\*\s*\1|\1\s*\.)',
                             "Potential use-after-free: pointer dereferenced after free on same line"),
    ],

    # ── Dockerfile security rules ─────────────────────────────────────────────
    "dockerfile": [
        ("SEC001",  "HIGH",
         r'(?i)(?:password|passwd|secret|api_key|token|credential|auth)\s*=\s*\S{4,}',
         "Hardcoded credential in Dockerfile — use Docker secrets (--secret) or runtime environment injection"),
        ("SEC201",  "HIGH",
         r'(?i)^\s*USER\s+(?:root|0)\s*$',
         "Container runs as root — add a non-root USER instruction to reduce blast radius"),
        ("SEC202",  "HIGH",
         r'(?i)(?:curl|wget)\s+[^\n|]*\|\s*(?:bash|sh|python\d*|perl|ruby)\b',
         "Remote code execution: piping curl/wget output to a shell interpreter"),
        ("SEC203",  "HIGH",
         r'--privileged\b',
         "Privileged container grants all host capabilities — avoid unless strictly required"),
        ("SEC204",  "LOW",
         r'(?i)(?:^|\s)FROM\s+\S+:latest(?:\s|$)',
         "Image pinned to :latest — use a specific digest (sha256:…) for reproducible builds"),
        ("SEC205",  "HIGH",
         r'(?i)^\s*ADD\s+https?://',
         "ADD with remote URL skips integrity checks — use RUN curl + sha256sum instead"),
        ("SEC206",  "MEDIUM",
         r'\bchmod\s+(?:777|a\+rwx|ugo\+rwx)\b',
         "chmod 777 / a+rwx — overly permissive file mode baked into image layer"),
        ("SEC207",  "HIGH",
         r'(?i)^\s*ENV\s+(?:PASSWORD|PASSWD|SECRET|API_KEY|TOKEN|PRIVATE_KEY|ACCESS_KEY)\s*=\s*\S+',
         "Secret in ENV instruction is baked into the image — use Docker secrets or runtime injection"),
        ("SEC208",  "MEDIUM",
         r'(?i)(?:curl|wget)\s+(?:[^\n]*\s)?(?:-k|--insecure)\b',
         "TLS verification disabled in Dockerfile RUN step — remove -k / --insecure"),
        ("SEC001E", "MEDIUM",
         r'(?i)(?:ARG|ENV)\s+\S+=\S{16,}',
         "Long value in ARG/ENV — verify this is not a hardcoded secret"),
    ],

    # ── GitHub Actions security rules ─────────────────────────────────────────
    "gha": [
        ("SEC301",  "HIGH",
         r'\$\{\{\s*github\.event\.(?:pull_request|issue|comment|review|review_comment)'
         r'\.(?:body|title|name|head\.sha|head\.ref)\s*\}\}',
         "Untrusted user input in workflow expression — script injection if interpolated in run: or env:"),
        ("SEC302",  "HIGH",
         r'on:\s*\[?pull_request_target',
         "pull_request_target executes workflow code from fork context — pwn-request attack vector"),
        ("SEC303",  "MEDIUM",
         r'uses:\s+[^@\s]+@(?:main|master|HEAD|v?\d+(?!\.\d+))\b',
         "Action pinned to mutable ref (branch/major tag) — pin to a full commit SHA for supply chain safety"),
        ("SEC304",  "HIGH",
         r'run:.*\$\{\{\s*github\.event\.',
         "Shell run step interpolates GitHub event data — expression/command injection risk"),
        ("SEC305",  "MEDIUM",
         r'runs-on:\s*(?:\[?\s*)?self-hosted',
         "Self-hosted runner — ensure runner is isolated and ephemeral to prevent supply chain attacks"),
        ("SEC306",  "HIGH",
         r'(?:echo|printf|::set-output)\s+.*\$\{\{\s*secrets\.',
         "Secret value may be echoed to workflow log — use ::add-mask:: to redact"),
        ("SEC307",  "MEDIUM",
         r'permissions:\s*write-all',
         "Overly broad permissions: write-all — grant only the minimum required permissions"),
        ("SEC308",  "HIGH",
         r'\$\{\{\s*(?:inputs|env)\.[A-Za-z_]\w*\s*\}\}',
         "Workflow input/env variable interpolated directly — validate before use to prevent injection"),
        ("SEC001",  "HIGH",
         r'(?i)(?:password|secret|api_key|token|credential)\s*:\s*["\']?[A-Za-z0-9+/]{16,}["\']?',
         "Possible hardcoded secret in workflow file — use repository secrets instead"),
    ],
}



# ── Context-aware rule skipping ──────────────────────────────────────────────
#
# Lines whose entire content matches one of these patterns are exempt from the
# associated rule.  This eliminates false positives that arise when a vulnerable
# pattern appears in a context that is structurally safe (e.g. deep relative
# paths inside static ES import/require statements are resolved at build-time,
# not at runtime, and carry no user input).
#
# Shape: { language: { rule_id: [skip_regex, ...] } }

_RULE_SKIP: dict[str, dict[str, list[str]]] = {
    "javascript": {
        # ../../../ in a static import / export-from / require with a literal
        # path only (no template-literal interpolation, no concatenation).
        "SEC027": [
            # ES6: import X from '../../..'  |  import '../../..'
            r"""^\s*(?:import\b|export\b[^"']*\bfrom\b)\s.*?["'](\.\.\/){2,}[^"'$`{}+]*["']""",
            # ES6 dynamic import with literal only: import('../../..')
            r"""^\s*(?:const|let|var)\s+[\w{}\s,*]+\s*=\s*(?:await\s+)?import\s*\(\s*["'](\.\.\/){2,}[^"'$`{}+]*["']\s*\)""",
            # CommonJS: require('../../..')  — full or destructured (multiline tail: } = require(...))
            r"""^\s*(?:(?:const|let|var)\s+[\w{}\s,*]+\s*=\s*)?require\s*\(\s*["'](\.\.\/){2,}[^"'$`{}+]*["']\s*\)""",
            r"""^\s*\}\s*=\s*require\s*\(\s*["'](\.\.\/){2,}[^"'$`{}+]*["']\s*\)""",
        ],
    },
}


# ── Taint analysis: sources and sinks ────────────────────────────────────────
#
# Sources: expressions that introduce user-controlled data.
# Sinks  : call sites where tainted data reaching them is dangerous.
#
# The cross-line taint engine (scan_taint) uses these for all languages.
# The Python AST engine (scan_python_ast_taint) has its own typed source/sink
# tables below (_PY_SOURCE_ATTRS, _PY_SINK_TABLE) for higher precision.

_TAINT_SOURCES: dict[str, list[str]] = {
    "python": [
        r'\brequest\.(args|form|values|json|data|cookies|headers|files)\b',
        r'\brequest\.get(?:_json|_data)\s*\(',
        r'\binput\s*\(',
        r'\bsys\.argv\b',
        r'\bos\.environ\b',
        # Django-specific sources
        r'\brequest\.(GET|POST|FILES|META)\b',
        r'\brequest\.resolver_match\.kwargs\b',
        # Flask-specific sources
        r'\bflask\.request\.(args|form|values|json|data|cookies|headers)\b',
    ],
    "javascript": [
        r'\breq(?:uest)?\.(query|body|params|headers|cookies)\b',
        r'\bprocess\.argv\b',
        r'\blocation\.(search|hash|href|pathname)\b',
        r'\bdocument\.URL\b',
        r'\bevent\.(target|data|detail)\b',
        # Express-specific
        r'\breq\.(?:originalUrl|url|path)\b',
        # Browser
        r'\bdocument\.(?:cookie|referrer)\b',
        r'\bwindow\.(?:location|name)\b',
        r'\bURLSearchParams\b',
    ],
    "php": [
        r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b',
        r'\bgetenv\s*\(',
        r'\bphp://input\b',
        r'\$_ENV\b',
        r'\bapache_request_headers\s*\(',
    ],
    "java": [
        r'\brequest\.getParameter\s*\(',
        r'\brequest\.getHeader\s*\(',
        r'\brequest\.(getInputStream|getReader)\s*\(',
        r'\bgetQueryString\s*\(',
        # Spring-specific sources
        r'@PathVariable\b',
        r'@RequestParam\b',
        r'@RequestBody\b',
        r'\bbindingResult\b',
    ],
    "go": [
        r'\b(?:r|req)\.(FormValue|PostFormValue)\s*\(',
        r'\b(?:r|req)\.URL\.Query\(\)\.Get\s*\(',
        r'\bc\.(Param|Query|GetHeader)\s*\(',
        r'\bos\.Args\b',
        # Gin/Echo/Fiber-specific
        r'\bc\.(?:QueryParam|FormValue|Param)\s*\(',
        r'\bctx\.(?:QueryParam|FormValue|Param)\s*\(',
    ],
    "bash": [
        r'(?<!\$)\$\{?(?:[1-9]|@|\*)\}?',   # positional args $1..$9, $@, $*
        r'\bread\s+\w+',
        r'\$\{?[A-Z_]+\}?\s*=.*\$\{?(?:QUERY_STRING|REQUEST_URI|HTTP_)\w+',  # CGI env vars
    ],
}

_TAINT_SINKS: dict[str, list[tuple[str, str, str, str]]] = {
    "python": [
        ("SEC004T", "HIGH",
         r'\b(?:cursor|conn|db|engine|session)\s*\.\s*(?:execute|executemany|scalar|query|raw)\s*\(',
         "SQL sink — user-controlled variable flows into database query"),
        ("SEC002T", "HIGH",
         r'\b(?:os\.system|subprocess\.(?:run|call|check_output|check_call|Popen)|exec)\s*\(',
         "Command sink — user-controlled variable flows into shell execution"),
        ("SEC035T", "HIGH",
         r'\b(?:open|send_file|send_from_directory)\s*\(',
         "File-operation sink — user-controlled variable used as path"),
        ("SEC026T", "HIGH",
         r'\b(?:render_template_string|jinja2\.Template|from_string)\s*\(',
         "Template sink — user-controlled variable used as template source"),
        ("SEC056T", "MEDIUM",
         r'\b(?:redirect|HttpResponseRedirect)\s*\(',
         "Redirect sink — user-controlled variable used as redirect URL"),
        # New sinks from Semgrep rules
        ("SEC066", "HIGH",
         r'\brequests\.(get|post|put|patch|delete|head|request)\s*\(',
         "SSRF sink — user-controlled variable used as URL in HTTP request"),
        ("SEC133", "HIGH",
         r'\burllib(?:\.request)?\.urlopen\s*\(',
         "SSRF sink — user-controlled variable used as URL in urllib.urlopen"),
        ("SEC068", "HIGH",
         r'\byaml\.load\s*\(',
         "YAML injection sink — user-controlled variable passed to yaml.load()"),
        ("SEC069", "HIGH",
         r'\bpickle\.(?:load|loads|Unpickler)\s*\(',
         "Deserialization sink — user-controlled data passed to pickle"),
    ],
    "javascript": [
        ("SEC004T", "HIGH",
         r'\b(?:execute|executeQuery|executeUpdate|db\.exec|connection\.exec)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC002T", "HIGH",
         r'\b(?:eval|exec|execSync|execFileSync|spawn|spawnSync)\s*\(',
         "Command sink — user-controlled variable flows into execution"),
        ("SEC035T", "HIGH",
         r'\bfs\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(',
         "File-operation sink — user-controlled variable used as path"),
        ("SEC006T", "HIGH",
         r'\binnerHTML\s*=',
         "DOM sink — user-controlled variable written to innerHTML"),
        ("SEC056T", "MEDIUM",
         r'\bres(?:ponse)?\.redirect\s*\(',
         "Redirect sink — user-controlled variable used as redirect URL"),
        # New sinks from Semgrep rules
        ("SEC080", "HIGH",
         r'\bchild_process\b.*\b(?:exec|execSync|spawn|spawnSync)\s*\(',
         "Command sink — user-controlled variable passed to child_process"),
        ("SEC087", "MEDIUM",
         r'\bnew\s+RegExp\s*\(',
         "ReDoS sink — user-controlled variable used as regex pattern"),
        ("SEC112", "HIGH",
         r'\bres\.sendFile\s*\(',
         "Path traversal sink — user-controlled variable used in sendFile"),
    ],
    "php": [
        ("SEC004T", "HIGH",
         r'\b(?:mysql_query|mysqli_query|mysqli_real_query|mysqli_multi_query|pg_query|mssql_query|odbc_exec|sqlsrv_query|->query|->exec|->execute|->prepare|PDO::query|PDO::exec)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC006T", "HIGH",
         r'\becho\b|\bprint\b',
         "XSS sink — user-controlled variable echoed to output without escaping"),
        ("SEC002T", "HIGH",
         r'\b(?:system|exec|shell_exec|passthru|popen)\s*\(',
         "Command sink — user-controlled variable flows into shell execution"),
        ("SEC035T", "HIGH",
         r'\b(?:include|require|include_once|require_once|file_get_contents|fopen)\b',
         "File-inclusion sink — user-controlled variable used as path"),
        # New sinks from Semgrep rules
        ("SEC092", "HIGH",
         r'\b(?:curl_init|curl_setopt)\s*\(',
         "SSRF sink — user-controlled variable used as URL in cURL"),
        ("SEC095", "HIGH",
         r'\bpreg_replace\s*\(',
         "Code injection sink — user-controlled variable in preg_replace with /e modifier"),
    ],
    "java": [
        ("SEC004T", "HIGH",
         r'\b(?:createQuery|executeQuery|prepareStatement|execute|executeUpdate)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC002T", "HIGH",
         r'\bRuntime\.getRuntime\(\)\.exec\s*\(',
         "Command sink — user-controlled variable flows into exec()"),
        # New sinks from Semgrep rules
        ("SEC099", "HIGH",
         r'\bnew\s+URL\s*\(',
         "SSRF sink — user-controlled variable used in URL constructor"),
        ("SEC101", "MEDIUM",
         r'\b(?:log(?:ger)?|LOG)\s*\.\s*(?:info|warn|error|debug|trace)\s*\(',
         "Log injection sink — user-controlled variable in log statement"),
        ("SEC120", "HIGH",
         r'\b(?:parseExpression|getValue|setValue)\s*\(',
         "SpEL injection sink — user-controlled variable in SpEL expression"),
    ],
    "go": [
        ("SEC004T", "HIGH",
         r'\b(?:db|tx)\.(?:Query|Exec|QueryRow|QueryContext|ExecContext)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC002T", "HIGH",
         r'\bexec\.Command\s*\(',
         "Command sink — user-controlled variable flows into exec"),
        ("SEC035T", "HIGH",
         r'\bos\.(?:Open|ReadFile|OpenFile)\s*\(',
         "File-operation sink — user-controlled variable used as path"),
        # New sinks from Semgrep rules
        ("SEC103", "HIGH",
         r'\bhttp\.(?:Get|Post|Head|Do)\s*\(',
         "SSRF sink — user-controlled variable used as HTTP URL"),
        ("SEC107", "MEDIUM",
         r'\b(?:log|logger)\s*\.\s*(?:Printf|Println|Sprintf)\s*\(',
         "Log injection sink — user-controlled variable in log statement"),
    ],
}


# ── Pre-compiled patterns for O(1) repeated matching (A1) ────────────────────
_COMPILED_RULES: dict[str, list[tuple[str, str, re.Pattern, str]]] = {
    lang: [(rid, sev, re.compile(pat, re.IGNORECASE), msg) for rid, sev, pat, msg in rules]
    for lang, rules in RULES.items()
}

_COMPILED_TAINT_SOURCES: dict[str, list[re.Pattern]] = {
    lang: [re.compile(p, re.IGNORECASE) for p in pats]
    for lang, pats in _TAINT_SOURCES.items()
}

_COMPILED_TAINT_SINKS: dict[str, list[tuple[str, str, re.Pattern, str]]] = {
    lang: [(rid, sev, re.compile(pat, re.IGNORECASE), msg) for rid, sev, pat, msg in sinks]
    for lang, sinks in _TAINT_SINKS.items()
}


def _lhs_name(line: str, language: str) -> str | None:
    """
    Return the simple variable name being assigned on this line, or None.

    Handles:
      Python / JS / Go  :  name = expr  |  name := expr  |  (const|let|var) name = expr
      PHP               :  $name = expr
      Java              :  Type name = expr  |  name = expr
    """
    s = line.strip()
    if language == "php":
        m = re.match(r'^\$([A-Za-z_]\w*)\s*=(?!=)', s)
        if m:
            return "$" + m.group(1)
    if language == "java":
        m = re.match(r'^(?:\w+(?:\s*<[^>]*>)?\s+)+([A-Za-z_]\w*)\s*=(?!=)', s)
        if m:
            return m.group(1)
    # Walrus / Go short-assign
    m = re.match(r'^([A-Za-z_]\w*)\s*:=', s)
    if m:
        return m.group(1)
    # JS / Go: const / let / var / final
    m = re.match(r'^(?:const|let|var|final)\s+([A-Za-z_]\w*)\s*=(?!=)', s)
    if m:
        return m.group(1)
    # Generic  name = expr  (exclude == and !=)
    m = re.match(r'^([A-Za-z_]\w*)\s*=(?![=>])', s)
    if m:
        return m.group(1)
    return None


def scan_taint(path: Path, language: str, taint_window: int = 25) -> list[Finding]:
    """
    Cross-line source-to-sink taint analysis for all supported languages.

    Algorithm
    ---------
    Pass 1 — collect every assignment of the form  ``name = <source>``  and
             record {var_name: [line_numbers]}.
    Pass 2 — for each sink call, check whether any tainted variable appears as
             an argument within taint_window lines of the most recent source assignment.

    This catches patterns like::

        filename = request.args.get("f")   # source (line N)
        open(filename)                      # sink   (line N+3)  ← flagged

    which single-line regex rules cannot detect.
    """
    compiled_sources = _COMPILED_TAINT_SOURCES.get(language, [])
    compiled_sinks   = _COMPILED_TAINT_SINKS.get(language, [])
    if not compiled_sources or not compiled_sinks:
        return []

    try:
        src = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    lines = src.splitlines()

    # Pass 1: build taint map  {var_name: [line_numbers where tainted]}
    tainted: dict[str, list[int]] = {}
    for i, line in enumerate(lines, 1):
        if not line.strip():
            continue
        for cpat in compiled_sources:
            if cpat.search(line):
                var = _lhs_name(line, language)
                if var:
                    tainted.setdefault(var, []).append(i)

    if not tainted:
        return []

    # Pass 1.5: Taint propagation — track when tainted vars are assigned to other vars
    # This catches patterns like: $html .= $tainted_var; or output = output + tainted_var
    max_propagation_iterations = 3
    for _ in range(max_propagation_iterations):
        new_tainted: dict[str, list[int]] = {}
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            # Check if this line assigns using a tainted variable
            lhs = _lhs_name(line, language)
            if lhs and lhs not in tainted:
                # Check if any tainted variable appears on the right-hand side
                for tainted_var in list(tainted.keys()):
                    # Match variable usage: $var, var, var[...], etc.
                    if re.search(r'\b' + re.escape(tainted_var) + r'\b', line):
                        # Also check for concatenation/append operations
                        if any(op in line for op in ['.=', '+=', '+', '.', 'concat', '||', '&']):
                            new_tainted.setdefault(lhs, []).append(i)
                            break
        # Merge new tainted variables
        if not new_tainted:
            break  # No new propagation, exit early
        for var, lines_list in new_tainted.items():
            tainted.setdefault(var, []).extend(lines_list)

    # Pass 2: match sinks and check for tainted-variable usage
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule_id, severity, compiled_sink, message in compiled_sinks:
            if not compiled_sink.search(line):
                continue
            for var, src_lines in tainted.items():
                if not re.search(r'\b' + re.escape(var) + r'\b', line):
                    continue
                nearby = [s for s in src_lines if 0 < i - s <= taint_window]
                if not nearby:
                    continue
                key = (i, rule_id)
                if key in reported:
                    continue
                reported.add(key)
                cwe, owasp = RULE_META.get(rule_id, ("", ""))
                findings.append(Finding(
                    file=str(path),
                    line=i,
                    severity=severity,
                    rule_id=rule_id,
                    language=language,
                    message=f"{message} — tainted by user input on line {max(nearby)}",
                    code_snippet=stripped[:120],
                    confidence="MEDIUM",
                    cwe=cwe,
                    owasp=owasp,
                ))

    return findings


# ── Rules where the string CONTENT is the vulnerability ──────────────────────
#
# For most rules, a match inside a Python string literal is a false positive
# (documentation).  For these rules the *value* of the string IS the finding
# (e.g. "../../../" as an actual path argument to open()).  The tokenizer-based
# span filter is therefore bypassed for them; instead, lines whose stripped
# content begins with a quote character (dictionary doc values) are skipped.

_BYPASS_STRING_FILTER = frozenset({
    "SEC027",  "SEC027B",   # deep directory traversal sequences
    "SEC038",               # URL-encoded traversal (%2e%2e%2f …)
    "SEC039",               # null byte in file-path context
    "SEC037",               # sensitive system file references (/etc/passwd …)
    "SEC042",               # /proc filesystem access
})


# ── Control Flow Graph (CFG) for path-sensitive taint ─────────────────────────────

# Known sanitizer calls: assigning the result of these to a variable removes taint from that var.
_PY_SANITIZERS: frozenset[str] = frozenset({
    "escape", "html.escape", "markupsafe.escape", "bleach.clean",
    "quote", "mogrify",
    "basename", "os.path.basename",
    "int", "float", "bool",
    "re.escape",
    "mark_safe", "conditional_escape", "strip_tags",
    "validate", "sanitize", "clean",
})


@dataclass
class BasicBlock:
    id: int
    stmts: list = field(default_factory=list)
    succs: list = field(default_factory=list)
    preds: list = field(default_factory=list)


@dataclass
class ControlFlowGraph:
    entry_id: int
    blocks: dict
    exit_ids: list


class _CFGBuilder:
    def __init__(self):
        self._next_id = 0
        self.blocks: dict[int, BasicBlock] = {}

    def _new_block(self) -> "BasicBlock":
        b = BasicBlock(id=self._next_id)
        self.blocks[self._next_id] = b
        self._next_id += 1
        return b

    def _link(self, from_id: int, to_id: int) -> None:
        if to_id not in self.blocks[from_id].succs:
            self.blocks[from_id].succs.append(to_id)
        if from_id not in self.blocks[to_id].preds:
            self.blocks[to_id].preds.append(from_id)

    def build(self, func: "ast.FunctionDef | ast.AsyncFunctionDef") -> "ControlFlowGraph":
        entry = self._new_block()
        exits = self._process_body(func.body, entry.id)
        return ControlFlowGraph(entry_id=entry.id, blocks=self.blocks, exit_ids=exits)

    def _process_body(self, stmts: list, current_id: int) -> list[int]:
        for stmt in stmts:
            ntype = type(stmt).__name__
            if ntype in ("Return", "Raise", "Break", "Continue"):
                self.blocks[current_id].stmts.append(stmt)
                return [current_id]
            elif ntype == "If":
                self.blocks[current_id].stmts.append(stmt)
                t_blk = self._new_block()
                self._link(current_id, t_blk.id)
                t_exits = self._process_body(stmt.body, t_blk.id)
                if stmt.orelse:
                    f_blk = self._new_block()
                    self._link(current_id, f_blk.id)
                    f_exits = self._process_body(stmt.orelse, f_blk.id)
                else:
                    f_exits = [current_id]
                merge = self._new_block()
                for eid in t_exits + f_exits:
                    self._link(eid, merge.id)
                current_id = merge.id
            elif ntype in ("For", "While"):
                hdr = self._new_block()
                hdr.stmts.append(stmt)
                self._link(current_id, hdr.id)
                body = self._new_block()
                self._link(hdr.id, body.id)
                b_exits = self._process_body(
                    stmt.body if hasattr(stmt, "body") else [], body.id
                )
                for eid in b_exits:
                    self._link(eid, hdr.id)
                after = self._new_block()
                self._link(hdr.id, after.id)
                current_id = after.id
            elif ntype == "Try":
                t_blk = self._new_block()
                self._link(current_id, t_blk.id)
                t_exits = self._process_body(stmt.body, t_blk.id)
                after = self._new_block()
                for eid in t_exits:
                    self._link(eid, after.id)
                for handler in getattr(stmt, "handlers", []):
                    h_blk = self._new_block()
                    self._link(t_blk.id, h_blk.id)
                    h_exits = self._process_body(handler.body, h_blk.id)
                    for eid in h_exits:
                        self._link(eid, after.id)
                finalbody = getattr(stmt, "finalbody", None)
                if finalbody:
                    f_blk = self._new_block()
                    self._link(after.id, f_blk.id)
                    f_exits = self._process_body(finalbody, f_blk.id)
                    current_id = f_exits[0] if f_exits else after.id
                else:
                    current_id = after.id
            else:
                self.blocks[current_id].stmts.append(stmt)
        return [current_id]


def build_python_cfg(func: "ast.FunctionDef | ast.AsyncFunctionDef") -> ControlFlowGraph:
    return _CFGBuilder().build(func)


def _cfg_block_transfer(block: BasicBlock, in_tainted: set[str]) -> set[str]:
    """Compute OUT = transfer(IN) for a single basic block."""
    tainted = set(in_tainted)
    for stmt in block.stmts:
        for node in ast.walk(stmt):
            rhs: ast.expr | None = None
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                rhs, targets = node.value, node.targets
            elif isinstance(node, ast.AnnAssign) and node.value:
                rhs, targets = node.value, [node.target]
            elif isinstance(node, ast.NamedExpr):
                rhs, targets = node.value, [node.target]
            if rhs is None:
                continue
            is_sanitized = (
                isinstance(rhs, ast.Call) and (
                    _dotted_name(rhs.func) in _PY_SANITIZERS
                    or _dotted_name(rhs.func).rsplit(".", 1)[-1] in _PY_SANITIZERS
                )
            )
            is_tainted = (not is_sanitized) and (
                _is_py_source(rhs) or _uses_tainted(rhs, tainted)
            )
            for t in targets:
                if isinstance(t, ast.Name):
                    if is_sanitized:
                        tainted.discard(t.id)
                    elif is_tainted:
                        tainted.add(t.id)
                elif isinstance(t, (ast.Tuple, ast.List)):
                    for elt in t.elts:
                        if isinstance(elt, ast.Name):
                            if is_sanitized:
                                tainted.discard(elt.id)
                            elif is_tainted:
                                tainted.add(elt.id)
    return tainted


def cfg_path_sensitive_taint(cfg: ControlFlowGraph) -> dict[int, set[str]]:
    """
    Forward dataflow analysis (worklist) over the CFG.
    Returns block_id → tainted variable set at block ENTRY.
    Sanitizer calls kill taint from the assigned variable (reduces false positives).
    """
    in_sets: dict[int, set[str]] = {bid: set() for bid in cfg.blocks}
    out_sets: dict[int, set[str]] = {bid: set() for bid in cfg.blocks}
    worklist: list[int] = [cfg.entry_id]
    on_list: set[int] = {cfg.entry_id}

    while worklist:
        bid = worklist.pop(0)
        on_list.discard(bid)
        block = cfg.blocks[bid]

        new_in: set[str] = set()
        for pred in block.preds:
            new_in |= out_sets.get(pred, set())
        in_sets[bid] = new_in

        new_out = _cfg_block_transfer(block, new_in)
        if new_out != out_sets.get(bid):
            out_sets[bid] = new_out
            for succ in block.succs:
                if succ not in on_list:
                    worklist.append(succ)
                    on_list.add(succ)

    return in_sets


# ── Python AST intra-function taint analysis ─────────────────────────────────

# Bare function names that return user-controlled data.
_PY_SOURCE_CALLS = frozenset({
    "input", "sys.argv",
})

# (rule_id, severity, sink-name-suffixes, human message)
_PY_SINK_TABLE: list[tuple[str, str, frozenset[str], str]] = [
    ("SEC004T", "HIGH",
     frozenset({"execute", "executemany", "scalar", "query", "raw", "filter_by"}),
     "SQL sink — user-controlled variable flows into database query"),
    ("SEC002T", "HIGH",
     frozenset({"system", "popen", "run", "call", "check_output", "check_call", "Popen", "exec"}),
     "Command sink — user-controlled variable flows into shell execution"),
    ("SEC035T", "HIGH",
     frozenset({"open", "send_file", "send_from_directory", "read_text", "read_bytes"}),
     "File-operation sink — user-controlled variable used as path"),
    ("SEC026T", "HIGH",
     frozenset({"render_template_string", "Template", "from_string"}),
     "Template sink — user-controlled variable used as template source"),
    ("SEC006T", "HIGH",
     frozenset({"Response", "make_response"}),
     "XSS sink — user-controlled variable in HTTP response body"),
    ("SEC056T", "MEDIUM",
     frozenset({"redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect"}),
     "Redirect sink — user-controlled variable used as redirect URL"),
]


def _dotted_name(node: ast.expr) -> str:
    """Return the dotted representation of a Name or Attribute chain."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _dotted_name(node.value) + "." + node.attr
    return ""


def _py_call_name(node: ast.Call) -> str:
    """Return a dotted name for an AST Call node, e.g. ``cursor.execute``."""
    return _dotted_name(node.func)


def _is_py_source(node: ast.expr) -> bool:
    """
    Return True if the expression introduces user-controlled data.

    Recognises:
    * Any call on the ``request`` object: request.args.get(), request.form['x'], …
    * Bare sources: input(), sys.argv
    * Subscript/attribute chains rooted at request: request.args['id']
    * Tuple/List whose elements are sources (for tuple-unpacking assignments)
    """
    if isinstance(node, ast.Call):
        name = _py_call_name(node)
        # Everything on flask/Django request objects is tainted
        first = name.split(".")[0] if "." in name else ""
        if (name.startswith("request.") or name.startswith("flask.request.")
                or first in _REQUEST_PARAM_NAMES):
            return True
        if name in _PY_SOURCE_CALLS or any(name.endswith("." + s) for s in _PY_SOURCE_CALLS):
            return True
    if isinstance(node, ast.Attribute):
        name = _dotted_name(node)
        first = name.split(".")[0] if "." in name else ""
        if (name.startswith("request.") or name.startswith("flask.request.")
                or first in _REQUEST_PARAM_NAMES):
            return True
    if isinstance(node, ast.Subscript):
        return _is_py_source(node.value)
    # Tuple/List: tainted if *any* element is tainted, e.g. ``a, b = src(), src()``
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_is_py_source(e) for e in node.elts)
    return False


# ── Type-based false-positive suppression ────────────────────────────────────

# Functions that return a numeric/bool/safe type regardless of their arguments.
_NUMERIC_SAFE_BUILTINS: frozenset[str] = frozenset({
    "int", "float", "bool", "len", "id", "abs", "round", "ord", "hash",
})

# Sanitisation functions that scrub dangerous content from strings.
_SANITIZER_CALLS: frozenset[str] = frozenset({
    "html.escape",
    "markupsafe.escape",
    "bleach.clean",
    "bleach.linkify",
    "cgi.escape",
})


def _is_safe_transform(node: ast.expr) -> bool:
    """
    Return True when a node provably produces a safe (non-injectable) value.

    Safe transforms include:
    - Numeric coercions:  int(x), float(x), bool(x), len(x), …
    - Comparisons:        x == y, x is None  →  bool, not a string
    - Sanitisers:         html.escape(x), markupsafe.escape(x), bleach.clean(x)
    - Safe regex results: re.match(…), re.search(…), re.fullmatch(…)

    These suppress taint propagation because the result cannot directly cause
    SQL-injection or XSS even when the input is tainted.
    """
    if isinstance(node, ast.Call):
        name = _py_call_name(node)
        last = name.rsplit(".", 1)[-1]
        # Numeric builtins are always safe
        if last in _NUMERIC_SAFE_BUILTINS or name in _NUMERIC_SAFE_BUILTINS:
            return True
        # Sanitiser functions produce safe output
        if name in _SANITIZER_CALLS:
            return True
        # re.match / re.search / re.fullmatch return a Match object, not the string
        if name in ("re.match", "re.search", "re.fullmatch", "re.compile"):
            return True
    if isinstance(node, ast.Compare):
        # Comparison expressions always produce a bool — safe from string injection
        return True
    return False


def _uses_tainted(node: ast.expr, tainted: set[str]) -> bool:
    """
    Return True if the expression tree contains any tainted variable name.

    A5: Covers all common propagation forms:
    - ast.Name: direct variable reference
    - ast.BinOp: handles both `+` concat and `%` formatting
      ("SELECT %s" % tainted → BinOp(Str, Mod, tainted); right side checked)
    - ast.JoinedStr + ast.FormattedValue: f-strings (both node types handled)
    - ast.Call: "str".format(tainted) — args are checked
    - ast.Attribute: also checks attr: keys from alias tracking

    Calls that provably produce safe types (int(), len(), html.escape(), …)
    are suppressed via _is_safe_transform even when arguments are tainted.
    """
    # Short-circuit: if the whole expression produces a safe type, it's not tainted
    if _is_safe_transform(node):
        return False
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.BinOp):
        # Covers + concat AND % formatting: both left and right are checked recursively
        return _uses_tainted(node.left, tainted) or _uses_tainted(node.right, tainted)
    if isinstance(node, ast.JoinedStr):           # f-string outer node
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                return True
        return False
    if isinstance(node, ast.FormattedValue):      # inner {expr} part of f-string
        return _uses_tainted(node.value, tainted)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_uses_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_uses_tainted(v, tainted) for v in node.values if v)
    if isinstance(node, ast.Call):
        # Safe-transform calls (int, len, html.escape, …) are already filtered above.
        # Check arguments and keywords for tainted values.
        if any(_uses_tainted(a, tainted) for a in node.args):
            return True
        if any(_uses_tainted(kw.value, tainted) for kw in node.keywords):
            return True
        # Also check the callee itself: for method calls like raw.strip() or
        # tainted_obj.format(...) the tainted value is node.func.value, not an arg.
        if isinstance(node.func, ast.Attribute):
            return _uses_tainted(node.func.value, tainted)
        return False
    if isinstance(node, ast.Subscript):
        # tainted_dict['key'] or tainted_lst[i] → tainted
        return _uses_tainted(node.value, tainted)
    if isinstance(node, ast.IfExp):
        return _uses_tainted(node.body, tainted) or _uses_tainted(node.orelse, tainted)
    if isinstance(node, ast.Attribute):
        # Check both the object chain and the attr: alias key
        attr_key = "attr:" + _dotted_name(node)
        if attr_key in tainted:
            return True
        return _uses_tainted(node.value, tainted)
    if isinstance(node, ast.Starred):
        return _uses_tainted(node.value, tainted)
    return False


def _propagate_taint(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_funcs: frozenset[str] = frozenset(),
    initial_taint: "set[str] | None" = None,
) -> set[str]:
    """
    Fixed-point taint propagation within a function body.

    Repeatedly walks all assignments until the tainted-variable set stabilises.
    This handles chains like::

        x = request.args.get("q")
        y = x.strip()
        z = f"SELECT … {y}"
        cursor.execute(z)        # ← z is tainted

    If tainted_funcs is non-empty, calls to those functions are also treated
    as taint sources (inter-procedural taint propagation).

    A2: Pre-extract all assignment-like nodes once — O(N) instead of O(N×K).

    Also handles:
    - Attribute aliases:  self.data = tainted  → tracks attr:self.data
    - Subscript aliases:  result = d['key']    → result tainted if d tainted
    - Augmented assign:   buf += tainted        → buf tainted
    - Conditional assign: x = t if c else s    → x tainted (conservative)
    - Container taint:    lst = [t, s]         → lst tainted; extraction propagated
    - Mutation:           lst.append(tainted)  → lst tainted
    """
    # Pre-extract all assignment-like nodes once
    assign_nodes: list[tuple[ast.expr, list[ast.expr]]] = []
    # mutation_calls: list of (container_name, arg_node) for .append/.extend/.update
    mutation_calls: list[tuple[str, ast.expr]] = []

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            assign_nodes.append((node.value, node.targets))
        elif isinstance(node, ast.AnnAssign) and node.value:
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.NamedExpr):   # walrus :=
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.AugAssign):   # buf += tainted
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            # Detect lst.append(x), lst.extend(x), d.update(x)
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in ("append", "extend", "update", "add")
                and isinstance(call.func.value, ast.Name)
                and call.args
            ):
                mutation_calls.append((call.func.value.id, call.args[0]))

    # Seed from caller-supplied initial taint (e.g. class-level field taint)
    tainted: set[str] = set(initial_taint) if initial_taint else set()
    while True:
        prev = len(tainted)
        for rhs, targets in assign_nodes:
            is_tainted = _is_py_source(rhs) or _uses_tainted(rhs, tainted)
            # Inter-procedural: calls to known tainted functions are also sources
            if not is_tainted and tainted_funcs and isinstance(rhs, ast.Call):
                call_name = _py_call_name(rhs)
                last = call_name.rsplit(".", 1)[-1]
                if call_name in tainted_funcs or last in tainted_funcs:
                    is_tainted = True
            if is_tainted:
                for t in targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name):
                                tainted.add(elt.id)
                    elif isinstance(t, ast.Attribute):
                        # self.data = tainted → track attr:self.data
                        attr_key = "attr:" + _dotted_name(t)
                        tainted.add(attr_key)
                    elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                        # data['key'] = tainted → mark container as tainted
                        tainted.add(t.value.id)

        # Container mutation: lst.append(tainted_val) → lst tainted
        for container_name, arg_node in mutation_calls:
            if _uses_tainted(arg_node, tainted) or _is_py_source(arg_node):
                tainted.add(container_name)

        if len(tainted) == prev:
            break   # fixed point reached

    # Remove variables that are shielded by a realpath + startswith guard exit
    _remove_guard_sanitized(func, tainted)

    return tainted


def _remove_guard_sanitized(
    func: "ast.FunctionDef | ast.AsyncFunctionDef",
    tainted: set[str],
) -> None:
    """
    Remove variables from `tainted` that are protected by a realpath/resolve
    + startswith guard exit pattern, e.g.:

        filepath = os.realpath(os.path.join(BASE_DIR, filename))
        if not filepath.startswith(BASE_DIR):
            return abort(403)      # early exit

    After the guard, `filepath` is safe to use in open() etc.
    Modifies `tainted` in-place.
    """
    # Collect variables assigned via os.realpath() or os.path.realpath()
    realpath_vars: set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        rhs = node.value
        if not isinstance(rhs, ast.Call):
            continue
        call_name = _py_call_name(rhs)
        if call_name in ("os.realpath", "os.path.realpath", "realpath"):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    realpath_vars.add(t.id)

    if not realpath_vars:
        return

    # Check if any realpath var is the subject of a .startswith() guard with early exit
    for node in ast.walk(func):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        # Accept `not var.startswith(...)` or `UnaryOp(Not, var.startswith(...))`
        inner = test
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            inner = test.operand
        if not isinstance(inner, ast.Call):
            continue
        if not isinstance(inner.func, ast.Attribute):
            continue
        if inner.func.attr != "startswith":
            continue
        subj = inner.func.value
        if not isinstance(subj, ast.Name):
            continue
        var_name = subj.id
        if var_name not in realpath_vars:
            continue
        # The if-body must be an early exit (return/raise/continue)
        body = node.body
        has_exit = any(
            isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break))
            or (isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call)
                and _py_call_name(stmt.value) in ("abort", "flask.abort", "sys.exit", "exit"))
            for stmt in body
        )
        if has_exit:
            tainted.discard(var_name)


_REQUEST_PARAM_NAMES: frozenset[str] = frozenset({
    "request", "req", "ctx", "context", "event", "e",
    "app_request", "http_request", "flask_request",
})

_REQUEST_ATTR_PREFIXES: frozenset[str] = frozenset({
    "args", "form", "json", "data", "body", "params",
    "files", "cookies", "headers", "values", "get_json",
})


def _method_param_seed(func: "ast.FunctionDef | ast.AsyncFunctionDef") -> set[str]:
    """
    Return the set of parameter names that should be treated as taint sources.

    Any parameter that:
    - Is named like a request object (req, ctx, request, …), OR
    - Is not `self`/`cls` and the method has a request-like param anywhere
    will seed taint so that `req.args.get(...)` etc. propagate correctly.
    """
    seed: set[str] = set()
    param_names = [
        a.arg for a in func.args.args
        if a.arg not in ("self", "cls")
    ]
    for p in param_names:
        if p in _REQUEST_PARAM_NAMES:
            seed.add(p)
    # Also seed if any parameter is accessed with request-like attributes in
    # the body — catches custom names like `incoming`, `payload`, etc.
    for node in ast.walk(func):
        if isinstance(node, ast.Attribute):
            if (isinstance(node.value, ast.Name)
                    and node.value.id in param_names
                    and node.attr in _REQUEST_ATTR_PREFIXES):
                seed.add(node.value.id)
    return seed


def _get_class_tainted_fields(
    class_node: ast.ClassDef,
    tainted_funcs: frozenset[str] = frozenset(),
) -> set[str]:
    """
    Fixed-point collection of `attr:self.*` taint across all methods of a class.

    Runs multiple passes until the set of tainted fields stabilises, so that
    a field set in one method and read in another is tracked correctly:

        class Handler:
            def load(self, req):
                self.query = req.args.get('q')   # → attr:self.query
            def execute(self, db):
                db.cursor().execute(self.query)  # ← seeded by attr:self.query
    """
    methods = [
        n for n in ast.walk(class_node)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    class_attrs: set[str] = set()
    while True:
        prev = len(class_attrs)
        for method in methods:
            # Seed with request-like params so req.args.get() is treated as tainted
            param_seed = _method_param_seed(method)
            seed = class_attrs | param_seed
            method_taint = _propagate_taint(method, tainted_funcs,
                                            initial_taint=seed if seed else None)
            for key in method_taint:
                if key.startswith("attr:self.") or key.startswith("attr:cls."):
                    class_attrs.add(key)
        if len(class_attrs) == prev:
            break   # fixed point
    return class_attrs


def _build_parent_map(tree: ast.AST) -> dict[int, ast.AST]:
    """Return {id(child): parent_node} for every node in the AST."""
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _enclosing_class_name(
    func_node: ast.AST,
    parent_map: dict[int, ast.AST],
) -> str | None:
    """Walk up the parent chain and return the name of the immediately enclosing ClassDef."""
    node = parent_map.get(id(func_node))
    while node is not None:
        if isinstance(node, ast.ClassDef):
            return node.name
        node = parent_map.get(id(node))
    return None


_SQL_KEYWORDS = re.compile(
    r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|DROP|CREATE|ALTER|UNION)\b',
    re.IGNORECASE,
)

def _scan_sql_param_concat(
    path: Path,
    source: str,
    lines: list[str],
    tree: ast.AST,
) -> list[Finding]:
    """
    Detect: function parameter directly concatenated into a SQL-looking string
    → passed to .execute() with a single argument (not parameterized).

    Catches multi-line patterns like:
        def find_user(username):
            query = "SELECT ... '" + username + "'"
            cursor.execute(query)        # ← flagged

    Does NOT flag parameterized calls like cursor.execute(query, (username,))
    because there `query` itself is a plain string literal (not tainted).
    """
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    def _binop_names(node: ast.expr) -> set[str]:
        """Collect all Name.id values inside a BinOp tree."""
        names: set[str] = set()
        for n in ast.walk(node):
            if isinstance(n, ast.Name):
                names.add(n.id)
        return names

    def _binop_has_sql_literal(node: ast.expr) -> bool:
        """True if any Constant string in the BinOp contains a SQL keyword."""
        for n in ast.walk(node):
            if isinstance(n, ast.Constant) and isinstance(n.value, str):
                if _SQL_KEYWORDS.search(n.value):
                    return True
        return False

    all_funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for func in all_funcs:
        params = {a.arg for a in func.args.args if a.arg not in ("self", "cls")}
        if not params:
            continue

        # Map assigned variable → set of Names in its RHS BinOp
        sql_concat_vars: dict[str, set[str]] = {}
        for node in ast.walk(func):
            if not isinstance(node, ast.Assign):
                continue
            rhs = node.value
            if not isinstance(rhs, ast.BinOp):
                continue
            if not _binop_has_sql_literal(rhs):
                continue
            names = _binop_names(rhs)
            if not (names & params):
                continue
            for t in node.targets:
                if isinstance(t, ast.Name):
                    sql_concat_vars[t.id] = names & params

        if not sql_concat_vars:
            continue

        # Find .execute() calls with a single arg that is one of those vars
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in ("execute", "executemany"):
                continue
            # Only single-argument (non-parameterized) calls
            if len(node.args) != 1 or node.keywords:
                continue
            arg = node.args[0]
            if not isinstance(arg, ast.Name):
                continue
            if arg.id not in sql_concat_vars:
                continue
            key = (node.lineno, "SEC004T")
            if key in reported:
                continue
            reported.add(key)
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
            cwe, owasp = RULE_META.get("SEC004T", ("CWE-89", "A03:2021"))
            findings.append(Finding(
                file=str(path),
                line=node.lineno,
                severity="HIGH",
                rule_id="SEC004T",
                language="python",
                message=(
                    f"SQL injection — parameter(s) {sql_concat_vars[arg.id]} "
                    "concatenated into SQL string passed to execute()"
                ),
                code_snippet=snippet[:120],
                confidence="HIGH",
                cwe=cwe,
                owasp=owasp,
            ))

    return findings


def scan_python_ast_taint(
    path: Path,
    cross_file_funcs: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Intra-function taint analysis for Python using the AST.

    Phase 1: For each function, propagate taint. If any return value is tainted,
             add the function name to tainted_funcs.
    Phase 2: Re-run with tainted_funcs (intra-file) + cross_file_funcs (cross-file)
             so calls to those functions are also treated as taint sources.

    This catches multi-assignment taint chains that single-line regex cannot.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines  = source.splitlines()
        tree   = ast.parse(source)
    except SyntaxError:
        return []

    # Phase 1: collect all functions in this file whose return values are tainted
    tainted_funcs: set[str] = set()
    all_funcs = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    for func in all_funcs:
        tainted = _propagate_taint(func, frozenset())
        for node in ast.walk(func):
            if isinstance(node, ast.Return) and node.value is not None:
                if _is_py_source(node.value) or (tainted and _uses_tainted(node.value, tainted)):
                    tainted_funcs.add(func.name)
                    break

    # Merge cross-file tainted functions into the local set
    frozen_tainted_funcs = frozenset(tainted_funcs) | cross_file_funcs

    # Phase 1b: build class-level field taint maps (cross-method tracking)
    parent_map = _build_parent_map(tree)
    class_field_taint: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            class_field_taint[node.name] = _get_class_tainted_fields(
                node, frozen_tainted_funcs
            )

    # Phase 2: CFG-based path-sensitive taint + inter-procedural taint
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    for func in all_funcs:
        # Seed with class-level field taint when inside a class method
        cls_name = _enclosing_class_name(func, parent_map)
        initial = class_field_taint.get(cls_name) if cls_name else None

        # Always run _propagate_taint (handles alias analysis, container taint,
        # AugAssign, etc.) as the primary analysis.
        tainted = _propagate_taint(func, frozen_tainted_funcs,
                                   initial_taint=initial)

        # A4: optionally supplement with CFG-based analysis for path sensitivity.
        # Union of CFG entry-sets can catch additional taint from multi-block
        # functions. We merge rather than replace so the alias extensions in
        # _propagate_taint are always preserved.
        try:
            cfg = build_python_cfg(func)
            in_sets = cfg_path_sensitive_taint(cfg)
            if in_sets:
                for s in in_sets.values():
                    tainted.update(s)
        except Exception:
            pass

        # Re-apply guard sanitization after CFG merge (CFG union may re-add
        # variables that realpath + startswith guards make safe)
        _remove_guard_sanitized(func, tainted)

        if not tainted:
            continue

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            if not any(_uses_tainted(a, tainted) for a in all_args):
                continue

            call_name = _py_call_name(node)
            for rule_id, severity, sink_names, message in _PY_SINK_TABLE:
                # Match by exact name or by the last component (method name)
                last = call_name.rsplit(".", 1)[-1]
                if call_name not in sink_names and last not in sink_names:
                    continue
                key = (node.lineno, rule_id)
                if key in reported:
                    continue
                reported.add(key)
                snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                cwe, owasp = RULE_META.get(rule_id, ("", ""))
                findings.append(Finding(
                    file=str(path),
                    line=node.lineno,
                    severity=severity,
                    rule_id=rule_id,
                    language="python",
                    message=message + " (AST taint analysis)",
                    code_snippet=snippet[:120],
                    confidence="HIGH",
                    cwe=cwe,
                    owasp=owasp,
                ))

    # Additional pass: parameter → SQL concat → execute() (no web source required)
    try:
        findings.extend(_scan_sql_param_concat(path, source, lines, tree))
    except Exception:
        pass

    return findings


# ── JavaScript AST taint analysis (esprima) ───────────────────────────────────────────

_esprima = None
_ESPRIMA_AVAILABLE: bool | None = None  # None = not yet checked


def _get_esprima():
    global _esprima, _ESPRIMA_AVAILABLE
    if _ESPRIMA_AVAILABLE is None:
        try:
            import esprima as _mod
            _esprima = _mod
            _ESPRIMA_AVAILABLE = True
        except ImportError:
            _ESPRIMA_AVAILABLE = False
    return _esprima if _ESPRIMA_AVAILABLE else None


# JS taint sources — prefixes/dotted names whose value is user-controlled
_JS_AST_SOURCES: frozenset[str] = frozenset({
    # Express / Node HTTP
    "req.query", "req.body", "req.params", "req.headers", "req.cookies",
    "req.files", "req.file", "req.rawBody", "req.text",
    "request.query", "request.body", "request.params", "request.headers",
    "request.cookies", "request.files",
    # Koa
    "ctx.query", "ctx.params", "ctx.body", "ctx.request", "ctx.headers",
    "ctx.cookies", "ctx.querystring",
    # Fastify
    "request.body", "request.params", "request.query", "request.headers",
    # Browser DOM
    "location.search", "location.hash", "location.href", "location.pathname",
    "document.URL", "document.documentURI", "document.referrer", "document.cookie",
    "window.location", "window.name",
    # DOM form inputs / events
    "event.target.value", "event.data", "e.target.value", "e.data",
    "target.value",
    # Web APIs
    "URLSearchParams", "searchParams",
    "localStorage", "sessionStorage",
    "indexedDB",
    # process
    "process.env", "process.argv",
    # WebSocket / postMessage
    "message.data", "msg.data",
    # GraphQL
    "args", "context.args",
})

# JS sinks — (rule_id, severity, set-of-function-name-suffixes, message)
_JS_AST_SINKS: list[tuple[str, str, frozenset[str], str]] = [
    ("SEC002T", "HIGH",
     frozenset({"eval", "execScript", "setImmediate", "setInterval", "setTimeout"}),
     "Code injection — user-controlled value flows into dynamic code execution"),
    ("SEC002T", "HIGH",
     frozenset({"Function"}),
     "Code injection — new Function() with user-controlled string"),
    ("SEC004T", "HIGH",
     frozenset({"query", "execute", "run", "all", "prepare",
                "raw", "knex", "sql", "select", "where", "from"}),
     "SQL/NoSQL injection — user-controlled value flows into database query"),
    ("SEC003T", "HIGH",
     frozenset({"exec", "execSync", "execFile", "execFileSync",
                "spawn", "spawnSync", "fork"}),
     "Command injection — user-controlled value flows into shell execution"),
    ("SEC035T", "HIGH",
     frozenset({"readFile", "readFileSync", "writeFile", "writeFileSync",
                "createReadStream", "createWriteStream", "sendFile",
                "open", "openSync", "appendFile", "appendFileSync",
                "unlink", "unlinkSync", "rename", "renameSync",
                "copyFile", "copyFileSync", "mkdir", "mkdirSync",
                "rmdir", "rmdirSync", "stat", "statSync", "lstat"}),
     "Path traversal — user-controlled value used as file path"),
    ("SEC006T", "HIGH",
     frozenset({"write", "writeln", "insertAdjacentHTML", "setHTML",
                "render", "send"}),
     "XSS — user-controlled value written to document/response"),
    ("SEC066", "HIGH",
     frozenset({"fetch", "request", "axios", "got", "needle",
                "superagent", "http.get", "https.get", "http.request", "https.request"}),
     "SSRF — user-controlled value used as URL in HTTP request"),
    ("SEC056T", "MEDIUM",
     frozenset({"redirect"}),
     "Open redirect — user-controlled value used as redirect URL"),
    ("SEC099T", "HIGH",
     frozenset({"deserialize", "fromJSON", "parse", "unserialize"}),
     "Unsafe deserialization — user-controlled value passed to deserializer"),
    ("SEC100T", "HIGH",
     frozenset({"template", "compile", "render"}),
     "Server-side template injection — user-controlled value in template engine"),
]

# JS safe transforms — calls that produce numeric/safe output even from tainted input
_JS_SAFE_TRANSFORMS: frozenset[str] = frozenset({
    "parseInt", "parseFloat", "Number", "BigInt", "Boolean",
    "isNaN", "isFinite", "isInteger",
    "encodeURIComponent", "encodeURI", "escape",
    "DOMPurify.sanitize", "sanitize", "purify",
    "validator.escape", "validator.toInt", "validator.toFloat",
    "sanitizeHtml", "xss",
    "Math.abs", "Math.floor", "Math.ceil", "Math.round", "Math.trunc",
    "JSON.stringify",  # safe for XSS when used correctly in data attributes
})


def _js_member_chain(node: dict) -> str:
    """Recursively resolve a MemberExpression into a dotted string."""
    if not isinstance(node, dict):
        return ""
    ntype = node.get("type", "")
    if ntype == "Identifier":
        return node.get("name", "")
    if ntype == "MemberExpression" and not node.get("computed"):
        obj = _js_member_chain(node["object"])
        prop_node = node.get("property", {})
        prop = prop_node.get("name", "") if prop_node.get("type") == "Identifier" else ""
        return f"{obj}.{prop}" if (obj and prop) else (obj or prop)
    if ntype == "ThisExpression":
        return "this"
    return ""


def _js_is_source(node: dict) -> bool:
    """Return True if this JS AST node is a user-controlled taint source."""
    if not isinstance(node, dict):
        return False
    ntype = node.get("type", "")
    if ntype in ("MemberExpression", "Identifier"):
        chain = _js_member_chain(node)
        if chain and any(chain == s or chain.startswith(s + ".") for s in _JS_AST_SOURCES):
            return True
    if ntype == "CallExpression":
        # fetch(...).then(r => r.json()) style — callee chain matches source prefix
        chain = _js_member_chain(node.get("callee", {}))
        if chain and any(chain == s or chain.startswith(s + ".") for s in _JS_AST_SOURCES):
            return True
    if ntype == "AwaitExpression":
        # await req.json(), await fetch(url).json()
        return _js_is_source(node.get("argument", {}))
    return False


def _js_is_safe_transform(node: dict) -> bool:
    """Return True when a JS call/expression produces a safe (numeric/sanitized) value."""
    if not isinstance(node, dict):
        return False
    ntype = node.get("type", "")
    if ntype == "CallExpression":
        chain = _js_member_chain(node.get("callee", {}))
        last = chain.rsplit(".", 1)[-1]
        if chain in _JS_SAFE_TRANSFORMS or last in _JS_SAFE_TRANSFORMS:
            return True
    if ntype in ("UnaryExpression",) and node.get("operator") in ("+", "-", "~", "!"):
        return True  # unary +/- coerce to number; ! coerces to bool
    if ntype == "BinaryExpression" and node.get("operator") in (
        "===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"
    ):
        return True  # comparison always yields boolean
    return False


def _js_uses_tainted(node: dict, tainted: set[str]) -> bool:
    """Return True if this JS expression subtree references any tainted variable."""
    if not isinstance(node, dict):
        return False
    # Safe transforms break the taint chain
    if _js_is_safe_transform(node):
        return False
    ntype = node.get("type", "")
    if ntype == "Identifier":
        return node["name"] in tainted
    if ntype == "MemberExpression":
        # obj.prop — tainted if obj is tainted OR dotted key like "obj.prop" is tainted
        obj_chain = _js_member_chain(node)
        if obj_chain and obj_chain in tainted:
            return True
        return _js_uses_tainted(node.get("object", {}), tainted)
    if ntype in ("BinaryExpression", "LogicalExpression"):
        return (_js_uses_tainted(node.get("left", {}), tainted) or
                _js_uses_tainted(node.get("right", {}), tainted))
    if ntype == "AssignmentExpression":
        return _js_uses_tainted(node.get("right", {}), tainted)
    if ntype == "TemplateLiteral":
        return any(_js_uses_tainted(e, tainted) for e in node.get("expressions", []))
    if ntype == "CallExpression":
        args = node.get("arguments", [])
        callee = node.get("callee", {})
        # method calls: tainted.method(...) → result is tainted
        if callee.get("type") == "MemberExpression":
            if _js_uses_tainted(callee.get("object", {}), tainted):
                return True
        return any(_js_uses_tainted(a, tainted) for a in args)
    if ntype == "ArrayExpression":
        return any(_js_uses_tainted(e, tainted) for e in node.get("elements", []) if e)
    if ntype == "ObjectExpression":
        return any(_js_uses_tainted(p.get("value", {}), tainted)
                   for p in node.get("properties", []))
    if ntype == "ConditionalExpression":
        return (_js_uses_tainted(node.get("consequent", {}), tainted) or
                _js_uses_tainted(node.get("alternate", {}), tainted))
    if ntype == "SpreadElement":
        return _js_uses_tainted(node.get("argument", {}), tainted)
    if ntype == "AwaitExpression":
        return _js_uses_tainted(node.get("argument", {}), tainted)
    if ntype == "YieldExpression":
        return _js_uses_tainted(node.get("argument", {}), tainted)
    if ntype in ("TypeCastExpression", "TSAsExpression", "TSTypeAssertion"):
        return _js_uses_tainted(node.get("expression", {}), tainted)
    if ntype == "SequenceExpression":
        return any(_js_uses_tainted(e, tainted) for e in node.get("expressions", []))
    if ntype == "NewExpression":
        return any(_js_uses_tainted(a, tainted) for a in node.get("arguments", []))
    if ntype == "TaggedTemplateExpression":
        return _js_uses_tainted(node.get("quasi", {}), tainted)
    return False


def _js_walk(node: dict):
    """Yield all nodes in the JS AST via pre-order traversal."""
    if not isinstance(node, dict) or "type" not in node:
        return
    yield node
    for v in node.values():
        if isinstance(v, dict) and "type" in v:
            yield from _js_walk(v)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict) and "type" in item:
                    yield from _js_walk(item)


def _js_pattern_names(id_node: dict) -> list[str]:
    """
    Extract all variable names from a VariableDeclarator id node.
    Handles Identifier, ObjectPattern, ArrayPattern, RestElement.
    """
    if not isinstance(id_node, dict):
        return []
    ntype = id_node.get("type", "")
    if ntype == "Identifier":
        return [id_node["name"]]
    if ntype == "ObjectPattern":
        names = []
        for prop in id_node.get("properties", []):
            if prop.get("type") == "RestElement":
                names += _js_pattern_names(prop.get("argument", {}))
            else:
                names += _js_pattern_names(prop.get("value", {}))
        return names
    if ntype == "ArrayPattern":
        names = []
        for elt in id_node.get("elements", []):
            if elt:
                names += _js_pattern_names(elt)
        return names
    if ntype == "RestElement":
        return _js_pattern_names(id_node.get("argument", {}))
    if ntype == "AssignmentPattern":
        return _js_pattern_names(id_node.get("left", {}))
    return []


def _js_propagate_in_scope(body_nodes: list[dict], tainted: set[str]) -> set[str]:
    """
    Fixed-point taint propagation over a JS statement list.

    Handles:
    - var/let/const declarations (including destructuring)
    - Assignment expressions
    - Property assignments (obj.prop = tainted → "obj.prop" in tainted)
    - Augmented assignments (+=, etc.)
    - For-of/for-in loops seeding loop variable
    - Nested scopes (if/for/while/try — conservative union of all branches)
    - Await expressions
    - Spread / rest elements
    """
    tainted = set(tainted)

    def _process_stmts(stmts: list[dict]) -> None:
        """Single pass over a statement list, mutating tainted in place."""
        for node in stmts:
            ntype = node.get("type", "")

            # ── Variable declaration ──────────────────────────────────────────
            if ntype == "VariableDeclaration":
                for decl in node.get("declarations", []):
                    init = decl.get("init")
                    if init and (_js_is_source(init) or _js_uses_tainted(init, tainted)):
                        for name in _js_pattern_names(decl.get("id", {})):
                            tainted.add(name)

            # ── Expression statement ──────────────────────────────────────────
            elif ntype == "ExpressionStatement":
                expr = node.get("expression", {})
                etype = expr.get("type", "")
                if etype == "AssignmentExpression":
                    lhs = expr.get("left", {})
                    rhs = expr.get("right", {})
                    rhs_tainted = _js_is_source(rhs) or _js_uses_tainted(rhs, tainted)
                    if rhs_tainted:
                        # x = tainted
                        if lhs.get("type") == "Identifier":
                            tainted.add(lhs["name"])
                        # obj.prop = tainted → track "obj.prop"
                        elif lhs.get("type") == "MemberExpression":
                            chain = _js_member_chain(lhs)
                            if chain:
                                tainted.add(chain)
                    # += style augmented: if lhs already tainted, still tainted
                    if expr.get("operator", "=") != "=" and lhs.get("type") == "Identifier":
                        if lhs["name"] in tainted:
                            pass  # stays tainted

            # ── Return statement ──────────────────────────────────────────────
            elif ntype == "ReturnStatement":
                pass  # handled by caller

            # ── For-of / for-in: loop variable gets tainted if iterable is tainted
            elif ntype in ("ForOfStatement", "ForInStatement"):
                right = node.get("right", {})
                left = node.get("left", {})
                body = node.get("body", {})
                if _js_is_source(right) or _js_uses_tainted(right, tainted):
                    if left.get("type") == "VariableDeclaration":
                        for decl in left.get("declarations", []):
                            for name in _js_pattern_names(decl.get("id", {})):
                                tainted.add(name)
                if body:
                    inner = body.get("body", []) if body.get("type") == "BlockStatement" else [body]
                    _process_stmts(inner)

            # ── For statement ─────────────────────────────────────────────────
            elif ntype == "ForStatement":
                init = node.get("init")
                if init:
                    _process_stmts([init])
                body = node.get("body", {})
                if body:
                    inner = body.get("body", []) if body.get("type") == "BlockStatement" else [body]
                    _process_stmts(inner)

            # ── If/else: conservative union of both branches ──────────────────
            elif ntype == "IfStatement":
                cons = node.get("consequent", {})
                alt = node.get("alternate")
                if cons:
                    inner = cons.get("body", []) if cons.get("type") == "BlockStatement" else [cons]
                    _process_stmts(inner)
                if alt:
                    inner = alt.get("body", []) if alt.get("type") == "BlockStatement" else [alt]
                    _process_stmts(inner)

            # ── While / do-while ──────────────────────────────────────────────
            elif ntype in ("WhileStatement", "DoWhileStatement"):
                body = node.get("body", {})
                if body:
                    inner = body.get("body", []) if body.get("type") == "BlockStatement" else [body]
                    _process_stmts(inner)

            # ── Try / catch / finally ─────────────────────────────────────────
            elif ntype == "TryStatement":
                block = node.get("block", {})
                handler = node.get("handler")
                finalizer = node.get("finalizer")
                if block:
                    _process_stmts(block.get("body", []))
                if handler:
                    param = handler.get("param", {})
                    if param and param.get("type") == "Identifier":
                        # Exception object is controlled input in some contexts
                        pass
                    _process_stmts(handler.get("body", {}).get("body", []))
                if finalizer:
                    _process_stmts(finalizer.get("body", []))

            # ── Block statement ───────────────────────────────────────────────
            elif ntype == "BlockStatement":
                _process_stmts(node.get("body", []))

            # ── Switch statement ──────────────────────────────────────────────
            elif ntype == "SwitchStatement":
                for case in node.get("cases", []):
                    _process_stmts(case.get("consequent", []))

    # Fixed-point: repeat until tainted set stabilises
    while True:
        prev = len(tainted)
        _process_stmts(body_nodes)
        if len(tainted) == prev:
            break

    # Remove variables guarded by path.resolve() + .startsWith() + early exit
    _js_remove_guard_sanitized(body_nodes, tainted)

    return tainted


def _js_remove_guard_sanitized(stmts: list[dict], tainted: set[str]) -> None:
    """
    Remove variables from `tainted` that are protected by:
        const filepath = path.resolve(...);
        if (!filepath.startsWith(BASE_DIR)) { return ...; }

    Modifies tainted in-place.
    """
    # Collect vars assigned via path.resolve() or path.normalize()
    resolve_vars: set[str] = set()
    for stmt in stmts:
        if stmt.get("type") != "VariableDeclaration":
            continue
        for decl in stmt.get("declarations", []):
            init = decl.get("init")
            if not init or init.get("type") != "CallExpression":
                continue
            chain = _js_member_chain(init.get("callee", {}))
            last = chain.rsplit(".", 1)[-1] if "." in chain else chain
            if last in ("resolve", "normalize"):
                for name in _js_pattern_names(decl.get("id", {})):
                    resolve_vars.add(name)

    if not resolve_vars:
        return

    for stmt in stmts:
        if stmt.get("type") != "IfStatement":
            continue
        test = stmt.get("test", {})
        # Accept `!var.startsWith(...)` or `var.startsWith(...) === false`
        inner = test
        if test.get("type") == "UnaryExpression" and test.get("operator") == "!":
            inner = test.get("argument", {})
        if inner.get("type") != "CallExpression":
            continue
        callee = inner.get("callee", {})
        if (callee.get("type") != "MemberExpression"
                or callee.get("property", {}).get("name") != "startsWith"):
            continue
        obj = callee.get("object", {})
        if obj.get("type") != "Identifier" or obj.get("name") not in resolve_vars:
            continue
        # The if-body must be an early exit (return/throw)
        cons = stmt.get("consequent", {})
        body_stmts = cons.get("body", []) if cons.get("type") == "BlockStatement" else [cons]
        has_exit = any(s.get("type") in ("ReturnStatement", "ThrowStatement")
                       for s in body_stmts)
        if has_exit:
            tainted.discard(obj.get("name"))


# JS function summary for inter-procedural taint
class JsFuncSummary:
    __slots__ = ("name", "tainted_params", "returns_tainted")

    def __init__(self, name: str, tainted_params: set[int], returns_tainted: bool):
        self.name = name
        self.tainted_params: set[int] = tainted_params
        self.returns_tainted: bool = returns_tainted


def _js_collect_functions(root: dict) -> list[dict]:
    """Return all function nodes in the AST."""
    results = []
    for n in _js_walk(root):
        if n.get("type") in ("FunctionDeclaration", "FunctionExpression",
                              "ArrowFunctionExpression"):
            results.append(n)
    return results


def _js_func_name(func: dict) -> str:
    """Best-effort function name extraction."""
    if func.get("type") == "FunctionDeclaration":
        id_node = func.get("id")
        if id_node and id_node.get("type") == "Identifier":
            return id_node["name"]
    return ""


def _js_get_body_nodes(func: dict) -> list[dict]:
    """Return the flat body node list of a function."""
    body = func.get("body", {})
    if isinstance(body, dict) and body.get("type") == "BlockStatement":
        return body.get("body", [])
    return []


def _js_build_func_summaries(root: dict) -> dict[str, JsFuncSummary]:
    """
    Two-pass JS function summary builder.
    Pass 1: find functions whose return values are tainted (no cross-function knowledge).
    Pass 2: build full summaries knowing which functions return tainted values.
    """
    funcs = _js_collect_functions(root)

    # Pass 1 — tainted return names
    tainted_returns: set[str] = set()
    for func in funcs:
        params = [p.get("name", "") for p in func.get("params", [])
                  if p.get("type") == "Identifier"]
        body_nodes = _js_get_body_nodes(func)
        seed: set[str] = set()
        for i, p in enumerate(params):
            if p in ("req", "request", "ctx", "context", "e", "event"):
                seed.add(p)
        tainted = _js_propagate_in_scope(body_nodes, seed)
        for n in _js_walk({"type": "Program", "body": body_nodes}):
            if n.get("type") == "ReturnStatement":
                arg = n.get("argument")
                if arg and (_js_is_source(arg) or _js_uses_tainted(arg, tainted)):
                    name = _js_func_name(func)
                    if name:
                        tainted_returns.add(name)

    # Pass 2 — full summaries with cross-function taint
    summaries: dict[str, JsFuncSummary] = {}
    for func in funcs:
        name = _js_func_name(func)
        params = [p.get("name", "") for p in func.get("params", [])
                  if p.get("type") == "Identifier"]
        body_nodes = _js_get_body_nodes(func)

        # For each param, check if it reaches a sink when tainted
        tainted_params: set[int] = set()
        for i, p in enumerate(params):
            if not p:
                continue
            seed_tainted = _js_propagate_in_scope(body_nodes, {p} | {
                pn for pn in params if pn in ("req", "request", "ctx", "context", "e", "event")
            })
            for n in _js_walk({"type": "Program", "body": body_nodes}):
                if n.get("type") != "CallExpression":
                    continue
                callee = n.get("callee", {})
                call_name = _js_member_chain(callee)
                last = call_name.rsplit(".", 1)[-1] if call_name else ""
                args = n.get("arguments", [])
                if any(_js_uses_tainted(a, seed_tainted) for a in args):
                    for _, _, sink_names, _ in _JS_AST_SINKS:
                        if call_name in sink_names or last in sink_names:
                            tainted_params.add(i)
                            break

        # Check if function returns tainted value (with cross-function knowledge)
        seed_req: set[str] = set()
        for p in params:
            if p in ("req", "request", "ctx", "context", "e", "event"):
                seed_req.add(p)
        extra_sources = tainted_returns  # functions that return tainted
        all_tainted = _js_propagate_in_scope(body_nodes, seed_req)
        returns_tainted = False
        for n in _js_walk({"type": "Program", "body": body_nodes}):
            if n.get("type") == "ReturnStatement":
                arg = n.get("argument")
                if arg and (_js_is_source(arg) or _js_uses_tainted(arg, all_tainted)):
                    returns_tainted = True
                    break

        if name:
            summaries[name] = JsFuncSummary(name, tainted_params, returns_tainted)

    return summaries


def _js_check_sinks(
    body_nodes: list[dict],
    tainted: set[str],
    func_summaries: dict[str, "JsFuncSummary"],
    lines: list[str],
    findings: list,
    reported: set,
    path: "Path",
) -> None:
    """
    Walk body_nodes checking calls against sinks.
    Also checks inter-procedural: calls to functions with tainted_params summaries.
    Also checks dangerous property assignments (innerHTML etc.).
    """
    for node in body_nodes:
        for n in _js_walk(node):
            ntype = n.get("type", "")

            # ── Call expression → sink matching ──────────────────────────────
            if ntype == "CallExpression":
                callee = n.get("callee", {})
                if callee.get("type") == "Identifier":
                    call_name = callee["name"]
                elif callee.get("type") == "MemberExpression":
                    call_name = _js_member_chain(callee)
                else:
                    call_name = ""

                if not call_name:
                    continue

                last = call_name.rsplit(".", 1)[-1]
                args = n.get("arguments", [])

                # Direct sink
                if any(_js_uses_tainted(a, tainted) for a in args):
                    for rule_id, severity, sink_names, message in _JS_AST_SINKS:
                        if call_name not in sink_names and last not in sink_names:
                            continue
                        # SQL sinks: parameterized queries pass tainted values as
                        # the second arg (e.g. db.query(sql, [params], cb)).
                        # Only flag when the SQL string itself (first arg) is tainted.
                        if rule_id == "SEC004T":
                            if not (args and _js_uses_tainted(args[0], tainted)):
                                continue
                        # execFile/execFileSync are safe when the binary name is static
                        # and only the arguments array contains tainted values.
                        if rule_id == "SEC003T" and last in ("execFile", "execFileSync"):
                            if not (args and _js_uses_tainted(args[0], tainted)):
                                continue
                        loc = n.get("loc", {})
                        lineno = loc.get("start", {}).get("line", 0)
                        key = (lineno, rule_id)
                        if key in reported:
                            continue
                        reported.add(key)
                        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                        cwe, owasp = RULE_META.get(rule_id, ("", ""))
                        findings.append(Finding(
                            file=str(path), line=lineno,
                            severity=severity, rule_id=rule_id,
                            language="javascript",
                            message=message + " (JS taint)",
                            code_snippet=snippet[:120],
                            confidence="HIGH",
                            cwe=cwe, owasp=owasp,
                        ))

                # Inter-procedural: tainted arg → known sink-reaching param
                summary = func_summaries.get(last) or func_summaries.get(call_name)
                if summary and summary.tainted_params:
                    for param_idx in summary.tainted_params:
                        if param_idx < len(args) and _js_uses_tainted(args[param_idx], tainted):
                            loc = n.get("loc", {})
                            lineno = loc.get("start", {}).get("line", 0)
                            key = (lineno, "SEC004T_INTERPROC")
                            if key not in reported:
                                reported.add(key)
                                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                                findings.append(Finding(
                                    file=str(path), line=lineno,
                                    severity="HIGH", rule_id="SEC004T",
                                    language="javascript",
                                    message=f"Tainted argument flows into sink via {summary.name}() (inter-procedural)",
                                    code_snippet=snippet[:120],
                                    confidence="HIGH",
                                    cwe="CWE-89", owasp="A03:2021",
                                ))
                            break

            # ── Assignment to dangerous properties ────────────────────────────
            elif ntype == "AssignmentExpression":
                lhs = n.get("left", {})
                rhs = n.get("right", {})
                if lhs.get("type") != "MemberExpression":
                    continue
                prop = lhs.get("property", {}).get("name", "")
                if prop not in ("innerHTML", "outerHTML", "src", "href", "action",
                                "data", "srcdoc", "textContent"):
                    continue
                if not _js_uses_tainted(rhs, tainted):
                    continue
                rule_id = "SEC006T" if prop in ("innerHTML", "outerHTML", "srcdoc") else "SEC056T"
                severity = "HIGH"
                msg = f"XSS — tainted value assigned to .{prop}" if rule_id == "SEC006T" else \
                      f"Open redirect or injection — tainted value assigned to .{prop}"
                loc = n.get("loc", {})
                lineno = loc.get("start", {}).get("line", 0)
                key = (lineno, rule_id)
                if key not in reported:
                    reported.add(key)
                    snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                    cwe, owasp = RULE_META.get(rule_id, ("CWE-79", "A03:2021"))
                    findings.append(Finding(
                        file=str(path), line=lineno,
                        severity=severity, rule_id=rule_id,
                        language="javascript",
                        message=msg + " (JS taint)",
                        code_snippet=snippet[:120],
                        confidence="HIGH",
                        cwe=cwe, owasp=owasp,
                    ))


def scan_js_ast(path: Path) -> list[Finding]:
    """
    AST-based inter-procedural taint analysis for JavaScript files using esprima.

    Improvements over baseline:
    - Destructuring patterns (const { body } = req)
    - Nested scopes (if/for/while/try)
    - Spread / await / rest elements
    - Type-safe transforms suppress taint (parseInt, encodeURIComponent, DOMPurify)
    - Object property tracking (this.field = tainted)
    - Inter-procedural: function summaries map which params reach sinks
    - 30+ taint sources covering Express, Koa, Fastify, DOM, WebSocket, process.env
    - 40+ sink functions covering SQLi, CMDi, path traversal, XSS, SSRF, SSTI
    """
    esp = _get_esprima()
    if esp is None:
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    try:
        root_dict = esp.parseScript(source, tolerant=True, loc=True).toDict()
    except Exception:
        try:
            root_dict = esp.parseModule(source, tolerant=True, loc=True).toDict()
        except Exception:
            return []

    lines = source.splitlines()
    findings: list[Finding] = []
    reported: set[tuple] = set()

    # Build inter-procedural function summaries for this file
    func_summaries = _js_build_func_summaries(root_dict)

    # Seed names that indicate the parameter IS the request object
    _REQ_PARAM_NAMES = frozenset({
        "req", "request", "ctx", "context", "e", "event",
        "msg", "message",
    })

    def _scan_scope(params: list[str], body_nodes: list[dict],
                    extra_tainted: set[str] | None = None) -> None:
        seed: set[str] = set(extra_tainted or set())
        for p in params:
            if p in _REQ_PARAM_NAMES:
                seed.add(p)

        tainted = _js_propagate_in_scope(body_nodes, seed)

        # Inter-procedural: mark vars that come from tainted-return functions as tainted
        for n in _js_walk({"type": "Program", "body": body_nodes}):
            if n.get("type") == "VariableDeclarator":
                init = n.get("init", {})
                if init and init.get("type") == "CallExpression":
                    callee = init.get("callee", {})
                    fn_name = _js_member_chain(callee)
                    last = fn_name.rsplit(".", 1)[-1] if fn_name else ""
                    summary = func_summaries.get(fn_name) or func_summaries.get(last)
                    if summary and summary.returns_tainted:
                        for name in _js_pattern_names(n.get("id", {})):
                            tainted.add(name)

        if not tainted:
            return

        _js_check_sinks(body_nodes, tainted, func_summaries, lines,
                        findings, reported, path)

    def _visit(node: dict) -> None:
        ntype = node.get("type", "")
        if ntype in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            params = []
            for p in node.get("params", []):
                params += _js_pattern_names(p)
            body_nodes = _js_get_body_nodes(node)
            if body_nodes:
                _scan_scope(params, body_nodes)
        for v in node.values():
            if isinstance(v, dict) and "type" in v:
                _visit(v)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "type" in item:
                        _visit(item)

    # Top-level statements (script mode — no enclosing function)
    _scan_scope([], root_dict.get("body", []))

    # All nested functions
    _visit(root_dict)

    return findings


def scan_with_regex(path: Path, language: str) -> list[Finding]:
    findings: list[Finding] = []
    # Use pre-compiled rules for performance; fall back gracefully if language unknown
    if not _COMPILED_RULES.get(language):
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = source.splitlines()

    # Python: precompute string/comment byte-offset spans so that regex matches
    # falling inside a string literal or comment are silently dropped.
    nocode_spans: list[tuple[int, int]] = []
    line_offsets: list[int] = []
    if language == "python":
        nocode_spans, line_offsets = _python_nocode_spans(source)

    nosec_marker  = _NOSEC.get(language, "")
    comment_pfxs  = _COMMENT_PREFIX.get(language, ())
    in_block_cmt  = False

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue

        # ── Block comment state ( /* … */ ) ──────────────────────────────────
        if language in _BLOCK_COMMENT_LANGS:
            if in_block_cmt:
                if "*/" in stripped:
                    in_block_cmt = False
                continue                          # still inside block comment
            if "/*" in stripped:
                if "*/" not in stripped:
                    in_block_cmt = True          # multi-line block comment starts
                continue                          # skip the opening line too

        # ── Skip full single-line comment lines ───────────────────────────────
        if any(stripped.startswith(p) for p in comment_pfxs):
            continue

        # ── Inline nosec suppression ( # nosec / // nosec ) ──────────────────
        if nosec_marker and nosec_marker in line.lower():
            continue

        # ── Per-rule matching ─────────────────────────────────────────────────
        line_offset = line_offsets[i - 1] if line_offsets else 0

        skip_for_lang = _RULE_SKIP.get(language, {})

        for rule_id, severity, compiled_pat, message in _COMPILED_RULES.get(language, []):
            m = compiled_pat.search(line)
            if not m:
                continue

            # Python: false-positive suppression via tokenizer spans.
            if nocode_spans:
                if rule_id in _BYPASS_STRING_FILTER:
                    # The string VALUE is the vulnerability (path, sequence …).
                    # Only skip lines whose entire content is a documentation
                    # string (e.g. a dict-value line starting with a quote).
                    if stripped.startswith('"') or stripped.startswith("'"):
                        continue
                else:
                    abs_start = line_offset + m.start()
                    if any(s <= abs_start < e for s, e in nocode_spans):
                        continue

            # Context-aware skip (e.g. SEC027 in static ES import statements).
            skip_pats = skip_for_lang.get(rule_id, ())
            if any(re.search(sp, line) for sp in skip_pats):
                continue

            cwe, owasp = RULE_META.get(rule_id, ("", ""))
            findings.append(Finding(
                file=str(path), line=i,
                severity=severity, rule_id=rule_id,
                language=language, message=message,
                code_snippet=stripped[:120],
                confidence="LOW",
                cwe=cwe,
                owasp=owasp,
            ))

    return findings


def scan_python_ast(path: Path) -> list[Finding]:
    """Deeper Python-only AST scan layered on top of regex."""
    findings = []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines  = source.splitlines()
        tree   = ast.parse(source)
    except SyntaxError:
        return []

    class Visitor(ast.NodeVisitor):
        def visit_Assert(self, node):
            snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
            cwe, owasp = RULE_META.get("SEC003", ("", ""))
            findings.append(Finding(
                file=str(path), line=node.lineno,
                severity="LOW", rule_id="SEC003",
                language="python",
                message="Assert stripped with python -O — don't use for security checks",
                code_snippet=snippet,
                confidence="LOW",
                cwe=cwe,
                owasp=owasp,
            ))
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def scan_structural_python(path: Path) -> list[Finding]:
    """
    Scan a Python file using structural (AST) pattern matching.
    Produces HIGH-confidence findings — patterns match code structure, not text.
    """
    rules = STRUCTURAL_RULES.get("python", [])
    if not rules:
        return []
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines = source.splitlines()
        tree = ast.parse(source)
    except (SyntaxError, OSError):
        return []

    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    # Pre-compute realpath-guarded variables per function for FP suppression
    _guard_sanitized_by_func: dict[int, set[str]] = {}
    for func_node in ast.walk(tree):
        if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        gs: set[str] = set()
        _remove_guard_sanitized(func_node, gs)
        # gs will be empty since we seeded empty — instead collect realpath vars directly
        realpath_vars: set[str] = set()
        for n in ast.walk(func_node):
            if not isinstance(n, ast.Assign):
                continue
            rhs = n.value
            if not isinstance(rhs, ast.Call):
                continue
            cn = _py_call_name(rhs)
            if cn in ("os.realpath", "os.path.realpath", "realpath"):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        realpath_vars.add(t.id)
        if realpath_vars:
            dummy: set[str] = set(realpath_vars)
            _remove_guard_sanitized(func_node, dummy)
            guarded = realpath_vars - dummy
            _guard_sanitized_by_func[id(func_node)] = guarded

    # Build a mapping from AST node id to enclosing function id
    _node_to_func: dict[int, int] = {}
    for func_node in ast.walk(tree):
        if isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(func_node):
                if id(child) not in _node_to_func:
                    _node_to_func[id(child)] = id(func_node)

    _PATH_RULE_IDS = frozenset({"SEC_FI001", "SEC_FI002", "SEC_FI003", "SEC_FI004",
                                 "SEC035T", "SEC035S"})

    def _emit(node: ast.AST, rule: StructuralRule, bindings: dict) -> None:
        # pattern-not: skip if any negative pattern matches this node
        if any(match_py_pattern(neg, node) is not None for neg in rule.pattern_not):
            return
        # metavar-regex conditions
        for var, compiled_re in rule.metavar_regex.items():
            bound = bindings.get(var)
            if bound is None:
                continue
            val_src = ast.unparse(bound) if hasattr(ast, "unparse") else ""
            if not compiled_re.search(val_src):
                return
        # Suppress path-operation findings when the path arg is realpath-guarded
        if rule.id in _PATH_RULE_IDS:
            path_arg = bindings.get("PATH") or bindings.get("SRC") or bindings.get("DST")
            if path_arg is not None and isinstance(path_arg, ast.Name):
                enclosing_id = _node_to_func.get(id(node))
                guarded = _guard_sanitized_by_func.get(enclosing_id, set())
                if path_arg.id in guarded:
                    return
        lineno = getattr(node, "lineno", 0)
        key = (lineno, rule.id)
        if key in reported:
            return
        reported.add(key)
        snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
        findings.append(Finding(
            file=str(path), line=lineno,
            severity=rule.severity, rule_id=rule.id,
            language="python", message=rule.message,
            code_snippet=snippet[:120],
            confidence="HIGH",
            cwe=rule.cwe, owasp=rule.owasp,
        ))

    for rule in rules:
        # ── Pre-compute context nodes for pattern-inside / pattern-not-inside ──
        ctx_nodes: list | None = None
        excl_nodes: list | None = None
        if rule.pattern_inside is not None:
            ctx_nodes = _collect_inside_nodes(rule.pattern_inside, tree)
            if not ctx_nodes:
                continue  # required context absent — skip entire rule
        if rule.pattern_not_inside is not None:
            excl_nodes = _collect_inside_nodes(rule.pattern_not_inside, tree)

        # ── Expression patterns ───────────────────────────────────────────────
        patterns_to_try = rule.pattern_either if rule.pattern_either else (
            [rule.pattern] if rule.pattern else []
        )
        for pat in patterns_to_try:
            for node, bindings in find_py_pattern(pat, tree):
                if ctx_nodes is not None and not _is_descendant_of_any(node, ctx_nodes):
                    continue
                if excl_nodes and _is_descendant_of_any(node, excl_nodes):
                    continue
                _emit(node, rule, bindings)

        # ── Statement-sequence patterns ───────────────────────────────────────
        if rule.stmt_pattern:
            for first_stmt, bindings in find_py_stmt_pattern(rule.stmt_pattern, tree):
                if ctx_nodes is not None and not _is_descendant_of_any(first_stmt, ctx_nodes):
                    continue
                if excl_nodes and _is_descendant_of_any(first_stmt, excl_nodes):
                    continue
                _emit(first_stmt, rule, bindings)

    return findings


def scan_structural_js(path: Path) -> list[Finding]:
    """
    Scan a JavaScript/TypeScript file using structural pattern matching via esprima.
    Produces HIGH-confidence findings.
    """
    _ensure_js_structural_rules()
    rules = STRUCTURAL_RULES.get("javascript", [])
    if not rules:
        return []

    esp = _get_esprima()
    if esp is None:
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    try:
        root_dict = esp.parseScript(source, tolerant=True, loc=True).toDict()
    except Exception:
        try:
            root_dict = esp.parseModule(source, tolerant=True, loc=True).toDict()
        except Exception:
            return []

    lines = source.splitlines()
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    # Pre-collect path.resolve-guarded variables for FP suppression on path rules
    _JS_PATH_RULE_IDS = frozenset({"SEC_PT001", "SEC_PT002", "SEC_PT003",
                                    "SEC_PT004", "SEC_PT005", "SEC035T"})
    _js_guarded: set[str] = set()
    for func in _js_collect_functions(root_dict):
        body_nodes = _js_get_body_nodes(func)
        if not body_nodes:
            continue
        # Collect resolve vars in this function's body
        resolve_vars: set[str] = set()
        for stmt in body_nodes:
            if stmt.get("type") != "VariableDeclaration":
                continue
            for decl in stmt.get("declarations", []):
                init = decl.get("init")
                if not init or init.get("type") != "CallExpression":
                    continue
                chain = _js_member_chain(init.get("callee", {}))
                if chain.rsplit(".", 1)[-1] in ("resolve", "normalize"):
                    for name in _js_pattern_names(decl.get("id", {})):
                        resolve_vars.add(name)
        if resolve_vars:
            guarded = set(resolve_vars)
            _js_remove_guard_sanitized(body_nodes, guarded)
            _js_guarded.update(resolve_vars - guarded)

    for rule in rules:
        patterns_to_try = rule.pattern_either if rule.pattern_either else ([rule.pattern] if rule.pattern else [])
        for pat in patterns_to_try:
            if pat is None:
                continue
            for node, bindings in find_js_pattern(pat, root_dict):
                if any(match_js_pattern(neg, node) is not None for neg in rule.pattern_not):
                    continue
                # Suppress path rules when the path arg is resolve-guarded
                if rule.id in _JS_PATH_RULE_IDS and _js_guarded:
                    path_arg = bindings.get("PATH") or bindings.get("INPUT") or bindings.get("BASE")
                    if path_arg is not None:
                        arg_name = (path_arg.get("name") if path_arg.get("type") == "Identifier"
                                    else _js_member_chain(path_arg))
                        if arg_name in _js_guarded:
                            continue
                    # SEC_PT005: path.join() wrapped in path.resolve() at same line
                    if rule.id == "SEC_PT005":
                        loc = node.get("loc", {})
                        lineno = loc.get("start", {}).get("line", 0)
                        if 0 < lineno <= len(lines):
                            src_line = lines[lineno - 1]
                            if "path.resolve" in src_line or "path.normalize" in src_line:
                                continue
                loc = node.get("loc", {})
                lineno = loc.get("start", {}).get("line", 0)
                key = (lineno, rule.id)
                if key in reported:
                    continue
                reported.add(key)
                snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
                findings.append(Finding(
                    file=str(path), line=lineno,
                    severity=rule.severity, rule_id=rule.id,
                    language="javascript", message=rule.message,
                    code_snippet=snippet[:120],
                    confidence="HIGH",
                    cwe=rule.cwe, owasp=rule.owasp,
                ))

    return findings


def _detect_language(path: Path) -> str | None:
    """
    Resolve the scanner language for a file, including IaC formats.

    Resolution order:
      1. FILENAME_MAP  (Dockerfile, CMakeLists.txt, …)
      2. EXTENSION_MAP (.py, .js, .go, …)
      3. Content-based detection for .yml/.yaml → GHA or ignored
    """
    lang = FILENAME_MAP.get(path.name.lower())
    if lang:
        return lang
    lang = EXTENSION_MAP.get(path.suffix.lower())
    if lang and lang != "yaml_generic":
        return lang
    # .yml / .yaml: only scan if it looks like a GitHub Actions workflow
    if path.suffix.lower() in (".yml", ".yaml"):
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if re.search(r'^on\s*:', content, re.MULTILINE) and re.search(r'^jobs\s*:', content, re.MULTILINE):
                return "gha"
        except Exception:
            pass
        return None  # plain YAML — no rules defined, skip
    return None


# ═══════════════════════════════════════════════════════════════════════════════
# Tree-sitter taint engine — PHP, Java, Go
#
# Replaces line-by-line regex for these three languages with proper AST-based
# taint analysis, giving:
#   • No false positives from matches inside comments or string literals
#   • True data-flow: source → assign chain → sink (multi-step)
#   • HIGH-confidence findings (rule IDs end in "TS")
#
# Falls back silently if tree-sitter packages are not installed.
# ═══════════════════════════════════════════════════════════════════════════════

_TS_PARSERS_CACHE: dict = {}


def _get_ts_parser(lang: str):
    """Lazy-load and cache a (Parser, Language) pair for php/java/go. Returns None on failure."""
    if lang in _TS_PARSERS_CACHE:
        return _TS_PARSERS_CACHE[lang]
    try:
        from tree_sitter import Language as _TSL, Parser as _TSP
        if lang == "php":
            import tree_sitter_php as _m
            lo = _TSL(_m.language_php())
        elif lang == "java":
            import tree_sitter_java as _m
            lo = _TSL(_m.language())
        elif lang == "go":
            import tree_sitter_go as _m
            lo = _TSL(_m.language())
        else:
            _TS_PARSERS_CACHE[lang] = None
            return None
        p = _TSP(lo)
        _TS_PARSERS_CACHE[lang] = (p, lo)
        return _TS_PARSERS_CACHE[lang]
    except Exception:
        _TS_PARSERS_CACHE[lang] = None
        return None


def _ts_text(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _ts_walk(node):
    yield node
    for child in node.children:
        yield from _ts_walk(child)


def _ts_finding(
    path: Path, node, rule_id: str, severity: str,
    language: str, message: str, lines: list[str],
) -> "Finding":
    lineno = node.start_point[0] + 1
    snippet = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""
    cwe, owasp = RULE_META.get(rule_id, ("", ""))
    return Finding(
        file=str(path), line=lineno, severity=severity,
        rule_id=rule_id, language=language,
        message=message, code_snippet=snippet[:120],
        confidence="HIGH", cwe=cwe, owasp=owasp,
    )


# ── PHP taint engine ──────────────────────────────────────────────────────────

_PHP_TAINT_SOURCES: frozenset[str] = frozenset({
    "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES", "$_SERVER", "$_ENV",
})

_PHP_SANITIZERS: frozenset[str] = frozenset({
    "htmlspecialchars", "htmlentities", "strip_tags", "esc_html", "esc_attr",
    "intval", "floatval", "absint", "intdiv",
    "mysqli_real_escape_string", "mysql_real_escape_string", "addslashes",
    "escapeshellarg", "escapeshellcmd",
    "base64_encode", "urlencode", "rawurlencode", "json_encode",
    "preg_quote", "number_format", "filter_var", "filter_input",
})

_PHP_SQL_SINKS: frozenset[str] = frozenset({
    "mysql_query", "mysql_db_query",
    "mysqli_query", "mysqli_multi_query", "mysqli_real_query",
    "pg_query", "pg_execute", "pg_query_params",
    "sqlite_query", "sqlite_exec",
    "query", "exec", "execute", "prepare",
})

_PHP_CMD_SINKS: frozenset[str] = frozenset({
    "exec", "system", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec",
})

_PHP_FILE_SINKS: frozenset[str] = frozenset({
    "file_get_contents", "file_put_contents", "fopen",
    "readfile", "file", "unlink", "rename", "copy", "move_uploaded_file",
})

_PHP_EVAL_SINKS: frozenset[str] = frozenset({"eval", "assert"})
_PHP_HEADER_SINKS: frozenset[str] = frozenset({"header"})


def _php_is_tainted(node, src: bytes, tainted: set) -> bool:
    """Return True if this PHP expression subtree contains user-controlled data."""
    if node is None:
        return False
    ntype = node.type

    if ntype == "subscript_expression":
        children = node.named_children
        if children and _ts_text(children[0], src) in _PHP_TAINT_SOURCES:
            return True

    if ntype == "variable_name":
        t = _ts_text(node, src)
        return t in _PHP_TAINT_SOURCES or t in tainted

    if ntype == "encapsed_string":
        return any(_php_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype in ("binary_expression",):
        return any(_php_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "function_call_expression":
        nc = node.named_children
        if nc and _ts_text(nc[0], src).lower().lstrip("\\") in _PHP_SANITIZERS:
            return False
        return any(_php_is_tainted(c, src, tainted) for c in nc)

    if ntype == "member_call_expression":
        return any(_php_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "cast_expression":
        for c in node.children:
            if c.type == "cast_type" and _ts_text(c, src).lower() in (
                "int", "integer", "float", "double", "bool", "boolean"
            ):
                return False
        return any(_php_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype in ("arguments", "argument", "array_creation_expression"):
        return any(_php_is_tainted(c, src, tainted) for c in node.named_children)

    return False


def _php_propagate_scope(stmts: list, src: bytes, tainted: set) -> None:
    while True:
        prev = len(tainted)
        _php_propagate_once(stmts, src, tainted)
        if len(tainted) == prev:
            break


def _php_propagate_once(stmts: list, src: bytes, tainted: set) -> None:
    for node in stmts:
        ntype = node.type

        if ntype == "expression_statement":
            _php_propagate_once(list(node.named_children), src, tainted)

        elif ntype == "assignment_expression":
            nc = node.named_children
            if len(nc) >= 2 and _php_is_tainted(nc[-1], src, tainted):
                if nc[0].type == "variable_name":
                    tainted.add(_ts_text(nc[0], src))

        elif ntype == "augmented_assignment_expression":
            nc = node.named_children
            if nc:
                lhs_text = _ts_text(nc[0], src)
                if lhs_text in tainted or (len(nc) > 1 and _php_is_tainted(nc[-1], src, tainted)):
                    tainted.add(lhs_text)

        elif ntype == "foreach_statement":
            nc = node.named_children
            if nc and _php_is_tainted(nc[0], src, tainted):
                for c in nc[1:]:
                    if c.type == "variable_name":
                        tainted.add(_ts_text(c, src))
            for c in nc:
                if c.type == "compound_statement":
                    _php_propagate_once(list(c.named_children), src, tainted)

        elif ntype in ("if_statement", "while_statement", "for_statement",
                       "do_statement", "try_statement"):
            for child in node.named_children:
                if child.type in ("compound_statement", "else_clause",
                                  "elseif_clause", "finally_clause", "catch_clause"):
                    _php_propagate_once(list(child.named_children), src, tainted)

        elif ntype == "compound_statement":
            _php_propagate_once(list(node.named_children), src, tainted)


def _php_scan_sinks(
    stmts: list, src: bytes, tainted: set,
    path: "Path", lines: list, reported: set,
) -> "list[Finding]":
    findings: list = []

    def _report(rule_id, severity, message, node):
        lineno = node.start_point[0] + 1
        key = (lineno, rule_id)
        if key in reported:
            return
        reported.add(key)
        findings.append(_ts_finding(path, node, rule_id, severity, "php", message, lines))

    def _check_call(call_node):
        if call_node.type == "function_call_expression":
            nc = call_node.named_children
            fname = _ts_text(nc[0], src).lower().lstrip("\\") if nc else ""
            arg_nodes = [c for c in (nc[1].named_children if len(nc) > 1 and nc[1].type == "arguments" else [])
                         if c.is_named]
        elif call_node.type == "member_call_expression":
            nc = call_node.named_children
            fname = _ts_text(nc[1], src).lower() if len(nc) > 1 else ""
            arg_nodes = [c for c in (nc[2].named_children if len(nc) > 2 and nc[2].type == "arguments" else [])
                         if c.is_named]
        else:
            return

        if fname in _PHP_SQL_SINKS:
            if any(_php_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC004TS", "HIGH",
                        "SQL injection — user-controlled value flows into database query", call_node)

        if fname in _PHP_CMD_SINKS:
            if any(_php_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC002TS", "HIGH",
                        "Command injection — user-controlled value flows into shell execution", call_node)

        if fname in _PHP_FILE_SINKS:
            if arg_nodes and _php_is_tainted(arg_nodes[0], src, tainted):
                _report("SEC035TS", "HIGH",
                        "Path traversal / LFI — user-controlled value used as file path", call_node)

        if fname in _PHP_EVAL_SINKS:
            if any(_php_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC002TS", "HIGH",
                        "Code injection — user-controlled value passed to eval()", call_node)

        if fname in _PHP_HEADER_SINKS:
            if arg_nodes and _php_is_tainted(arg_nodes[0], src, tainted):
                _report("SEC056TS", "MEDIUM",
                        "Header injection / open redirect — user-controlled value in header()", call_node)

        if fname in ("printf", "vprintf", "fprintf", "sprintf"):
            if any(_php_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC006TS", "HIGH",
                        "XSS — user-controlled value in printf-family output", call_node)

    def _check_expr(node):
        if node.type in ("function_call_expression", "member_call_expression"):
            _check_call(node)
        for child in node.named_children:
            _check_expr(child)

    def _scan(inner_stmts):
        for node in inner_stmts:
            ntype = node.type

            if ntype == "expression_statement":
                for child in node.named_children:
                    _check_expr(child)

            elif ntype == "echo_statement":
                for child in node.named_children:
                    if _php_is_tainted(child, src, tainted):
                        _report("SEC006TS", "HIGH",
                                "XSS — user-controlled value echoed without sanitization", node)
                        break

            elif ntype in ("include_expression", "require_expression",
                           "include_once_expression", "require_once_expression"):
                for child in node.named_children:
                    if _php_is_tainted(child, src, tainted):
                        _report("SEC035TS", "HIGH",
                                "LFI — user-controlled value in include/require", node)
                        break

            elif ntype in ("if_statement", "while_statement", "for_statement",
                           "foreach_statement", "do_statement", "try_statement"):
                for child in node.named_children:
                    if child.type in ("compound_statement", "else_clause",
                                      "elseif_clause", "finally_clause", "catch_clause"):
                        _scan(list(child.named_children))
                    else:
                        _check_expr(child)

            elif ntype == "compound_statement":
                _scan(list(node.named_children))

    _scan(stmts)
    return findings


def scan_php_ts(path: "Path") -> "list[Finding]":
    """PHP taint analysis using tree-sitter AST — HIGH-confidence findings only."""
    result = _get_ts_parser("php")
    if result is None:
        return []
    parser, _ = result
    try:
        src_text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    src = src_text.encode("utf-8")
    lines = src_text.splitlines()
    tree = parser.parse(src)
    root = tree.root_node

    all_findings: list = []
    reported: set = set()

    def _process_scope(stmts):
        tainted: set = set()
        _php_propagate_scope(stmts, src, tainted)
        if tainted:
            all_findings.extend(_php_scan_sinks(stmts, src, tainted, path, lines, reported))

    # Top-level script statements
    top_stmts = [c for c in root.named_children
                 if c.type not in ("function_definition", "class_declaration",
                                   "namespace_definition")]
    if top_stmts:
        _process_scope(top_stmts)

    # Function and method bodies
    for node in _ts_walk(root):
        if node.type in ("function_definition", "method_declaration"):
            for child in node.named_children:
                if child.type == "compound_statement":
                    _process_scope(list(child.named_children))

    return all_findings


# ── Java taint engine ─────────────────────────────────────────────────────────

_JAVA_REQUEST_TYPES: frozenset[str] = frozenset({
    "httpservletrequest", "servletrequest", "httpexchange",
    "serverrequest", "requestinfo",
})

_JAVA_SOURCE_METHODS: frozenset[str] = frozenset({
    "getParameter", "getParameterValues", "getParameterMap",
    "getHeader", "getHeaders", "getHeaderNames",
    "getQueryString", "getInputStream", "getReader",
    "getCookies", "getRequestURI", "getRequestURL",
    "getPathInfo", "getServletPath",
})

_JAVA_SANITIZERS: frozenset[str] = frozenset({
    "parseInt", "parseLong", "parseDouble", "parseFloat", "parseBoolean",
    "valueOf", "escapeHtml", "encodeForHTML", "encodeForSQL",
    "sanitize", "escape", "encode", "stripTags",
})

_JAVA_SQL_SINKS: frozenset[str] = frozenset({
    "execute", "executeQuery", "executeUpdate", "executeBatch",
    "prepareStatement", "prepareCall", "nativeQuery",
    "createQuery", "createNativeQuery", "query",
})

_JAVA_CMD_SINKS: frozenset[str] = frozenset({"exec", "start"})
_JAVA_FILE_SINKS: frozenset[str] = frozenset({
    "readAllBytes", "readString", "readAllLines", "newInputStream",
    "newBufferedReader", "newFileReader",
})
_JAVA_OUTPUT_SINKS: frozenset[str] = frozenset({
    "println", "print", "printf", "format", "write", "append",
})


def _java_method_name(call_node, src: bytes) -> str:
    # method_invocation named_children: [object_id, method_id, argument_list]
    # The method name is the last identifier before argument_list
    name = ""
    for child in call_node.named_children:
        if child.type == "identifier":
            name = _ts_text(child, src)
        elif child.type == "argument_list":
            break
    return name


def _java_call_object(call_node, src: bytes) -> str:
    nc = call_node.named_children
    if nc and nc[0].type in ("identifier", "this"):
        return _ts_text(nc[0], src).lower()
    return ""


def _java_is_source(node, src: bytes) -> bool:
    if node.type == "method_invocation":
        return _java_method_name(node, src) in _JAVA_SOURCE_METHODS
    return False


def _java_is_tainted(node, src: bytes, tainted: set) -> bool:
    if node is None:
        return False
    ntype = node.type

    if _java_is_source(node, src):
        return True

    if ntype == "identifier":
        return _ts_text(node, src) in tainted

    if ntype in ("binary_expression", "string_concatenation"):
        return any(_java_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "method_invocation":
        if _java_method_name(node, src) in _JAVA_SANITIZERS:
            return False
        return any(_java_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype in ("argument_list", "array_initializer", "object_creation_expression"):
        return any(_java_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "field_access":
        nc = node.named_children
        return bool(nc) and _java_is_tainted(nc[0], src, tainted)

    if ntype in ("cast_expression",):
        return any(_java_is_tainted(c, src, tainted) for c in node.named_children)

    return False


def _java_propagate_scope(stmts: list, src: bytes, tainted: set) -> None:
    while True:
        prev = len(tainted)
        _java_propagate_once(stmts, src, tainted)
        if len(tainted) == prev:
            break


def _java_propagate_once(stmts: list, src: bytes, tainted: set) -> None:
    for node in stmts:
        ntype = node.type

        if ntype == "local_variable_declaration":
            for child in node.named_children:
                if child.type == "variable_declarator":
                    dc = child.named_children
                    if len(dc) >= 2 and _java_is_tainted(dc[-1], src, tainted):
                        if dc[0].type == "identifier":
                            tainted.add(_ts_text(dc[0], src))

        elif ntype == "assignment_expression":
            nc = node.named_children
            if len(nc) >= 2 and _java_is_tainted(nc[-1], src, tainted):
                if nc[0].type == "identifier":
                    tainted.add(_ts_text(nc[0], src))

        elif ntype == "expression_statement":
            for child in node.named_children:
                _java_propagate_once([child], src, tainted)

        elif ntype in ("if_statement", "while_statement", "for_statement",
                       "enhanced_for_statement", "do_statement",
                       "try_statement", "synchronized_statement"):
            for child in node.named_children:
                if child.type == "block":
                    _java_propagate_once(list(child.named_children), src, tainted)
                elif child.type in ("if_statement",):
                    _java_propagate_once([child], src, tainted)

        elif ntype == "block":
            _java_propagate_once(list(node.named_children), src, tainted)


def _java_scan_sinks(
    stmts: list, src: bytes, tainted: set,
    path: "Path", lines: list, reported: set,
) -> "list[Finding]":
    findings: list = []

    def _report(rule_id, severity, message, node):
        lineno = node.start_point[0] + 1
        key = (lineno, rule_id)
        if key in reported:
            return
        reported.add(key)
        findings.append(_ts_finding(path, node, rule_id, severity, "java", message, lines))

    def _check_call(node):
        if node.type != "method_invocation":
            return
        method = _java_method_name(node, src)
        obj = _java_call_object(node, src)
        arg_nodes = []
        for c in node.named_children:
            if c.type == "argument_list":
                arg_nodes = [x for x in c.named_children if x.is_named]
                break

        if method in _JAVA_SQL_SINKS:
            if any(_java_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC004TS", "HIGH",
                        "SQL injection — user-controlled value flows into database query", node)

        if method in _JAVA_CMD_SINKS and ("runtime" in obj or "process" in obj or not obj):
            if any(_java_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC002TS", "HIGH",
                        "Command injection — user-controlled value in Runtime.exec() / ProcessBuilder", node)

        if method in _JAVA_FILE_SINKS:
            if any(_java_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC035TS", "HIGH",
                        "Path traversal — user-controlled value used as file path", node)

        if method in _JAVA_OUTPUT_SINKS:
            # Exclude System.out, System.err, Logger, and similar non-HTTP writers
            if obj not in ("system", "err", "log", "logger", "out", "console", "stderr", "stdout"):
                if any(_java_is_tainted(a, src, tainted) for a in arg_nodes):
                    _report("SEC006TS", "HIGH",
                            "XSS — user-controlled value written to HTTP response", node)

        if method == "sendRedirect":
            if any(_java_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC056TS", "MEDIUM",
                        "Open redirect — user-controlled value in sendRedirect()", node)

    def _scan_expr(node):
        if node.type == "method_invocation":
            _check_call(node)
        for child in node.named_children:
            _scan_expr(child)

    def _scan(inner_stmts):
        for node in inner_stmts:
            ntype = node.type
            if ntype == "expression_statement":
                for child in node.named_children:
                    _scan_expr(child)
            elif ntype == "local_variable_declaration":
                # e.g. ResultSet rs = stmt.executeQuery(tainted)
                for child in node.named_children:
                    if child.type == "variable_declarator":
                        for c in child.named_children:
                            _scan_expr(c)
            elif ntype == "return_statement":
                for child in node.named_children:
                    _scan_expr(child)
            elif ntype in ("if_statement", "while_statement", "for_statement",
                           "enhanced_for_statement", "do_statement",
                           "try_statement", "synchronized_statement"):
                for child in node.named_children:
                    if child.type == "block":
                        _scan(list(child.named_children))
            elif ntype == "block":
                _scan(list(node.named_children))

    _scan(stmts)
    return findings


def scan_java_ts(path: "Path") -> "list[Finding]":
    """Java taint analysis using tree-sitter AST — HIGH-confidence findings only."""
    result = _get_ts_parser("java")
    if result is None:
        return []
    parser, _ = result
    try:
        src_text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    src = src_text.encode("utf-8")
    lines = src_text.splitlines()
    tree = parser.parse(src)
    root = tree.root_node

    all_findings: list = []
    reported: set = set()

    for node in _ts_walk(root):
        if node.type == "method_declaration":
            block = None
            for child in node.named_children:
                if child.type == "block":
                    block = child
                    break
            if block is None:
                continue

            stmts = list(block.named_children)
            tainted: set = set()

            # Seed taint from method parameters:
            #   - HttpServletRequest / similar types → definitely user input
            #   - String / CharSequence / Object → conservatively tainted
            #     (they may carry user data via the call graph)
            for param_container in node.named_children:
                if param_container.type == "formal_parameters":
                    for p in param_container.named_children:
                        if p.type == "formal_parameter":
                            pc = p.named_children
                            if len(pc) >= 2:
                                type_text = _ts_text(pc[0], src).lower()
                                param_name = _ts_text(pc[-1], src)
                                if any(t in type_text for t in _JAVA_REQUEST_TYPES):
                                    tainted.add(param_name)
                                elif type_text in (
                                    "string", "charsequence", "object",
                                    "stringbuilder", "stringbuffer",
                                ):
                                    tainted.add(param_name)

            _java_propagate_scope(stmts, src, tainted)
            if tainted:
                all_findings.extend(_java_scan_sinks(stmts, src, tainted, path, lines, reported))

    return all_findings


# ── Go taint engine ───────────────────────────────────────────────────────────

_GO_REQUEST_VARS: frozenset[str] = frozenset({"r", "req", "request", "ctx"})

_GO_SOURCE_METHODS: frozenset[str] = frozenset({
    "FormValue", "PostFormValue", "PostForm",
    "URLParam",   # chi
    "Param", "Query", "PostForm", "GetQuery", "GetPostForm",  # Gin / Echo
})

_GO_SANITIZERS: frozenset[str] = frozenset({
    "Atoi", "ParseInt", "ParseFloat", "ParseBool", "ParseUint",
    "PathEscape", "QueryEscape", "EscapeString", "EscapeHTML",
    "HTMLEscapeString", "HTMLEscaper",
})

_GO_SQL_SINKS: frozenset[str] = frozenset({
    "Query", "QueryRow", "QueryContext", "QueryRowContext",
    "Exec", "ExecContext", "Prepare", "PrepareContext",
    "Raw", "Where", "Select",
})

_GO_CMD_SINKS: frozenset[str] = frozenset({"Command"})

_GO_FILE_SINKS: frozenset[str] = frozenset({
    "Open", "ReadFile", "WriteFile", "Create", "OpenFile",
    "Stat", "Remove", "MkdirAll", "Mkdir",
    "ServeFile", "ServeContent",
})

_GO_HTTP_SINKS: frozenset[str] = frozenset({"Get", "Post", "Head", "Do", "NewRequest"})

_GO_WRITE_SINKS: frozenset[str] = frozenset({
    "Fprintf", "Fprintln", "Fprint",
    "Write", "WriteString",
})


def _go_call_parts(call_node, src: bytes) -> tuple:
    """Return (object_text, method_text, full_call_text) for a Go call_expression."""
    full = _ts_text(call_node, src)
    func_node = None
    for c in call_node.children:
        if c.type in ("selector_expression", "identifier", "call_expression"):
            func_node = c
            break
    if func_node is None:
        return "", "", full

    if func_node.type == "selector_expression":
        nc = func_node.named_children
        if len(nc) >= 2:
            return _ts_text(nc[0], src), _ts_text(nc[-1], src), full
    if func_node.type == "identifier":
        return "", _ts_text(func_node, src), full
    return "", "", full


def _go_is_source(call_node, src: bytes) -> bool:
    obj, method, full = _go_call_parts(call_node, src)

    # r.FormValue(...), r.PostFormValue(...)
    if method in _GO_SOURCE_METHODS and obj in _GO_REQUEST_VARS:
        return True

    # r.Header.Get(...), r.URL.Query().Get(...)  — chained .Get on anything starting with r.
    if method == "Get":
        for rv in _GO_REQUEST_VARS:
            if full.startswith(rv + "."):
                return True

    # mux.Vars(r), chi.URLParam(r, ...), any framework URLParam/Vars call
    if method in ("Vars", "URLParam"):
        return True

    # Gin/Echo: c.Param(), c.Query()
    if method in ("Param", "Query", "PostForm", "GetQuery", "GetPostForm"):
        if obj in ("c", "ctx", "context"):
            return True

    return False


def _go_is_tainted(node, src: bytes, tainted: set) -> bool:
    if node is None:
        return False
    ntype = node.type

    if ntype == "call_expression":
        if _go_is_source(node, src):
            return True
        _, method, _ = _go_call_parts(node, src)
        if method in _GO_SANITIZERS:
            return False
        return any(_go_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "identifier":
        return _ts_text(node, src) in tainted

    if ntype == "index_expression":
        nc = node.named_children
        return bool(nc) and _go_is_tainted(nc[0], src, tainted)

    if ntype == "selector_expression":
        nc = node.named_children
        return bool(nc) and _go_is_tainted(nc[0], src, tainted)

    if ntype == "binary_expression":
        return any(_go_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "expression_list":
        return any(_go_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype in ("argument_list", "composite_literal", "literal_value", "keyed_element"):
        return any(_go_is_tainted(c, src, tainted) for c in node.named_children)

    if ntype == "type_conversion_expression":
        nc = node.named_children
        if nc and _ts_text(nc[0], src) in (
            "int", "int8", "int16", "int32", "int64",
            "uint", "uint8", "uint16", "uint32", "uint64",
            "float32", "float64", "bool",
        ):
            return False
        return any(_go_is_tainted(c, src, tainted) for c in node.named_children)

    return False


def _go_propagate_scope(stmts: list, src: bytes, tainted: set) -> None:
    while True:
        prev = len(tainted)
        _go_propagate_once(stmts, src, tainted)
        if len(tainted) == prev:
            break


def _go_propagate_once(stmts: list, src: bytes, tainted: set) -> None:
    for node in stmts:
        ntype = node.type

        if ntype == "short_var_declaration":
            nc = node.named_children   # [expression_list_lhs, expression_list_rhs]
            if len(nc) >= 2:
                el_left, el_right = nc[0], nc[-1]
                if _go_is_tainted(el_right, src, tainted):
                    for c in (el_left.named_children if el_left.type == "expression_list"
                              else [el_left]):
                        if c.type == "identifier":
                            tainted.add(_ts_text(c, src))

        elif ntype == "assignment_statement":
            nc = node.named_children
            if len(nc) >= 2:
                el_left, el_right = nc[0], nc[-1]
                left_ids = (el_left.named_children if el_left.type == "expression_list"
                            else [el_left])
                right_exprs = (el_right.named_children if el_right.type == "expression_list"
                               else [el_right])
                for i, rhs in enumerate(right_exprs):
                    if _go_is_tainted(rhs, src, tainted) and i < len(left_ids):
                        if left_ids[i].type == "identifier":
                            tainted.add(_ts_text(left_ids[i], src))

        elif ntype in ("if_statement", "for_statement", "range_statement",
                       "switch_statement", "select_statement",
                       "type_switch_statement", "expression_switch_statement"):
            for child in node.named_children:
                if child.type in ("block", "statement_list"):
                    _go_propagate_once(list(child.named_children), src, tainted)
                elif child.type in ("communication_case", "default_case",
                                    "expression_case", "type_case"):
                    _go_propagate_once(list(child.named_children), src, tainted)

        elif ntype in ("block", "statement_list"):
            _go_propagate_once(list(node.named_children), src, tainted)


def _go_scan_sinks(
    stmts: list, src: bytes, tainted: set,
    path: "Path", lines: list, reported: set,
) -> "list[Finding]":
    findings: list = []

    def _report(rule_id, severity, message, node):
        lineno = node.start_point[0] + 1
        key = (lineno, rule_id)
        if key in reported:
            return
        reported.add(key)
        findings.append(_ts_finding(path, node, rule_id, severity, "go", message, lines))

    def _check_call(call_node):
        obj, method, _ = _go_call_parts(call_node, src)
        arg_nodes = []
        for c in call_node.named_children:
            if c.type == "argument_list":
                arg_nodes = [x for x in c.named_children if x.is_named]
                break

        if method in _GO_SQL_SINKS:
            if any(_go_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC004TS", "HIGH",
                        "SQL injection — user-controlled value flows into database query", call_node)

        if method in _GO_CMD_SINKS and obj == "exec":
            if any(_go_is_tainted(a, src, tainted) for a in arg_nodes):
                _report("SEC002TS", "HIGH",
                        "Command injection — user-controlled value in exec.Command()", call_node)

        if method in _GO_FILE_SINKS and obj in ("os", "ioutil", "http", ""):
            if arg_nodes and _go_is_tainted(arg_nodes[0], src, tainted):
                _report("SEC035TS", "HIGH",
                        "Path traversal — user-controlled value used as file path", call_node)

        if method in _GO_HTTP_SINKS and obj in ("http", "client", ""):
            if arg_nodes and _go_is_tainted(arg_nodes[0], src, tainted):
                _report("SEC066TS", "HIGH",
                        "SSRF — user-controlled value used as HTTP request URL", call_node)

        if method in _GO_WRITE_SINKS:
            if method in ("Fprintf", "Fprintln", "Fprint") and obj == "fmt":
                # skip first arg (writer), check the rest
                if any(_go_is_tainted(a, src, tainted) for a in arg_nodes[1:]):
                    _report("SEC006TS", "HIGH",
                            "XSS / format injection — user-controlled value in fmt.Fprintf response",
                            call_node)
            else:
                if any(_go_is_tainted(a, src, tainted) for a in arg_nodes):
                    _report("SEC006TS", "HIGH",
                            "XSS — user-controlled value written to HTTP response", call_node)

    def _scan_expr(node):
        if node.type == "call_expression":
            _check_call(node)
        for child in node.named_children:
            _scan_expr(child)

    def _scan(inner_stmts):
        for node in inner_stmts:
            ntype = node.type
            if ntype == "expression_statement":
                for child in node.named_children:
                    _scan_expr(child)
            elif ntype in ("if_statement", "for_statement", "range_statement",
                           "switch_statement", "select_statement",
                           "type_switch_statement", "expression_switch_statement"):
                for child in node.named_children:
                    if child.type in ("block", "statement_list"):
                        _scan(list(child.named_children))
                    elif child.type in ("communication_case", "default_case",
                                        "expression_case", "type_case"):
                        _scan(list(child.named_children))
            elif ntype in ("block", "statement_list"):
                _scan(list(node.named_children))

    _scan(stmts)
    return findings


def scan_go_ts(path: "Path") -> "list[Finding]":
    """Go taint analysis using tree-sitter AST — HIGH-confidence findings only."""
    result = _get_ts_parser("go")
    if result is None:
        return []
    parser, _ = result
    try:
        src_text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    src = src_text.encode("utf-8")
    lines = src_text.splitlines()
    tree = parser.parse(src)
    root = tree.root_node

    all_findings: list = []
    reported: set = set()

    for node in _ts_walk(root):
        if node.type == "function_declaration":
            block = None
            for child in node.named_children:
                if child.type == "block":
                    block = child
                    break
            if block is None:
                continue

            # Unwrap statement_list inside block
            stmt_list = None
            for child in block.named_children:
                if child.type == "statement_list":
                    stmt_list = list(child.named_children)
                    break
            if stmt_list is None:
                stmt_list = list(block.named_children)

            tainted: set = set()

            # Seed: parameters of type *http.Request or similar
            for plist in node.named_children:
                if plist.type == "parameter_list":
                    for p in plist.named_children:
                        if p.type == "parameter_declaration":
                            pc = p.named_children
                            if pc:
                                type_text = _ts_text(pc[-1], src).lower()
                                param_name = _ts_text(pc[0], src)
                                if "request" in type_text or "responsewriter" in type_text:
                                    tainted.add(param_name)

            _go_propagate_scope(stmt_list, src, tainted)
            if tainted:
                all_findings.extend(
                    _go_scan_sinks(stmt_list, src, tainted, path, lines, reported)
                )

    return all_findings


def scan_file(
    path: Path,
    taint_window: int = 25,
    cross_file_funcs: frozenset[str] = frozenset(),
    func_summaries: "dict[str, FuncSummary] | None" = None,
) -> list[Finding]:
    """
    Run all scan engines for the given file and return deduplicated findings.

    Engines (in order, each de-duplicated by (line, rule_id)):
      1.  scan_with_regex         — fast pattern matching with context filtering
      2.  scan_entropy            — Shannon-entropy secret detection (all languages)
      3.  scan_multiline          — multi-line/logical-line injection rules (non-Python)
      4.  scan_python_ast         — Python AST: assert-statement detection
      5.  scan_python_ast_taint   — Python AST: intra+inter-procedural + cross-file taint
      6.  scan_interprocedural    — inter-procedural taint via function summaries (Python)
      7.  scan_js_ast             — JavaScript AST taint analysis via esprima
      8.  scan_taint              — cross-line sliding-window taint (all languages)
      9.  scan_structural_python  — structural (AST) pattern matching for Python (HIGH confidence)
     10.  scan_structural_js      — structural (AST) pattern matching for JS (HIGH confidence)
     11.  scan_php_ts             — tree-sitter AST taint analysis for PHP (HIGH confidence)
     12.  scan_java_ts            — tree-sitter AST taint analysis for Java (HIGH confidence)
     13.  scan_go_ts              — tree-sitter AST taint analysis for Go (HIGH confidence)
    """
    language = _detect_language(path)
    if not language:
        return []

    seen: set[tuple[int, str]] = set()
    findings: list[Finding] = []

    def _merge(new: list[Finding]) -> None:
        for f in new:
            key = (f.line, f.rule_id)
            if key not in seen:
                seen.add(key)
                findings.append(f)

    _merge(scan_with_regex(path, language))
    _merge(scan_entropy(path, language))
    _merge(scan_multiline(path, language))

    if language == "python":
        _merge(scan_python_ast(path))
        _merge(scan_python_ast_taint(path, cross_file_funcs=cross_file_funcs))

    if language == "python" and func_summaries:
        _merge(scan_interprocedural(path, func_summaries, cross_file_funcs=cross_file_funcs))

    if language == "javascript":
        _merge(scan_js_ast(path))

    _merge(scan_taint(path, language, taint_window=taint_window))

    # Structural (AST) pattern matching — always HIGH confidence, "S"-suffixed IDs
    if language == "python":
        _merge(scan_structural_python(path))
    if language == "javascript":
        _merge(scan_structural_js(path))

    # Tree-sitter taint analysis — HIGH confidence, "TS"-suffixed rule IDs
    if language == "php":
        ts_php = scan_php_ts(path)
        _merge(ts_php)
        # SEC011 is a catch-all that fires on raw $_GET/$_POST usage regardless of
        # downstream sanitization. When tree-sitter finds no vulnerabilities (it
        # correctly tracks escapeshellarg, PDO prepare, etc.), suppress SEC011 to
        # avoid false positives on well-sanitized code.
        if not ts_php:
            findings[:] = [f for f in findings if f.rule_id != "SEC011"]
    if language == "java":
        _merge(scan_java_ts(path))
    if language == "go":
        _merge(scan_go_ts(path))

    return findings


# ── YAML custom rule loader ───────────────────────────────────────────────────

def _load_yaml_rules(rule_files: list[str]) -> None:
    """
    Load additional rules from YAML files and merge them into RULES / RULE_META.

    Schema (each file):
    ┌─────────────────────────────────────────────────────────────┐
    │ rules:                                                      │
    │   - id: CUSTOM001                                           │
    │     language: python   # python|javascript|php|java|go|bash │
    │                        # |dockerfile|gha|c|build            │
    │     severity: HIGH     # HIGH | MEDIUM | LOW                │
    │     pattern: 'regex'   # Python re pattern                  │
    │     message: "..."     # Human-readable description         │
    │     cwe: "CWE-89"      # optional                          │
    │     owasp: "A03:2021"  # optional                          │
    └─────────────────────────────────────────────────────────────┘
    """
    try:
        import yaml  # type: ignore[import]
    except ImportError:
        print("Warning: pyyaml not installed — cannot load custom rules. Run: pip install pyyaml")
        return

    for rule_file in rule_files:
        try:
            with open(rule_file, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except Exception as exc:
            print(f"Warning: could not load rule file {rule_file!r}: {exc}")
            continue

        loaded = 0
        for rule_def in (data or {}).get("rules", []):
            rid      = str(rule_def.get("id", "")).strip()
            lang     = str(rule_def.get("language", "")).strip().lower()
            severity = str(rule_def.get("severity", "MEDIUM")).strip().upper()
            message  = str(rule_def.get("message", "Custom rule")).strip()
            cwe      = str(rule_def.get("cwe", "")).strip()
            owasp    = str(rule_def.get("owasp", "")).strip()

            if not rid or not lang:
                print(f"Warning: skipping malformed rule in {rule_file!r}: {rule_def}")
                continue

            # Check if this is a structural rule (has 'pattern' as AST pattern, not regex)
            if "pattern" in rule_def or "pattern_either" in rule_def:
                is_structural = (
                    lang in ("python", "javascript") and
                    not str(rule_def.get("pattern", "")).startswith("^") and
                    # Heuristic: structural patterns don't have regex anchors/escapes
                    "\\b" not in str(rule_def.get("pattern", "")) and
                    "\\s" not in str(rule_def.get("pattern", "")) and
                    "$" in str(rule_def.get("pattern", ""))  # must have metavar
                )
                if is_structural:
                    raw_rule: dict = {
                        "id": rid,
                        "language": lang,
                        "severity": severity,
                        "message": message,
                        "cwe": cwe,
                        "owasp": owasp,
                    }
                    if "pattern" in rule_def:
                        raw_rule["pattern"] = rule_def["pattern"]
                    if "pattern_not" in rule_def:
                        pn = rule_def["pattern_not"]
                        raw_rule["pattern_not"] = pn if isinstance(pn, list) else [pn]
                    if "pattern_either" in rule_def:
                        raw_rule["pattern_either"] = rule_def["pattern_either"]
                    try:
                        new_compiled = _compile_structural_rules([raw_rule])
                        for l, srules in new_compiled.items():
                            STRUCTURAL_RULES.setdefault(l, []).extend(srules)
                        RULE_META.setdefault(rid, (cwe, owasp))
                        loaded += 1
                        continue
                    except Exception:
                        pass  # fall through to regex loading

            # Regular regex rule
            pattern = str(rule_def.get("pattern", "")).strip()
            if not pattern:
                print(f"Warning: skipping malformed rule in {rule_file!r}: {rule_def}")
                continue
            RULES.setdefault(lang, []).append((rid, severity, pattern, message))
            # Also add to compiled rules for the language
            try:
                compiled_pat = re.compile(pattern, re.IGNORECASE)
                _COMPILED_RULES.setdefault(lang, []).append((rid, severity, compiled_pat, message))
            except re.error:
                pass
            RULE_META.setdefault(rid, (cwe, owasp))
            loaded += 1
        print(f"  Loaded {loaded} custom rules from {rule_file}")


# ── Diff / incremental scanning ───────────────────────────────────────────────

def _get_diff_files(base_ref: str, root: Path) -> list[Path]:
    """
    Return paths of files changed relative to *base_ref* using git diff.
    Falls back to an empty list with a warning if git is unavailable.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", base_ref],
            capture_output=True, text=True, cwd=root,
        )
        if result.returncode != 0:
            # Try staged changes instead
            result = subprocess.run(
                ["git", "diff", "--name-only", "--cached"],
                capture_output=True, text=True, cwd=root,
            )
        files: list[Path] = []
        for name in result.stdout.splitlines():
            name = name.strip()
            if not name:
                continue
            p = (root / name).resolve()
            if p.is_file():
                files.append(p)
        return files
    except Exception as exc:
        print(f"Warning: git diff failed: {exc}")
        return []


# ── AI-assisted finding triage ────────────────────────────────────────────────

def _ai_explain_findings(
    findings: list[Finding],
    model: str = "claude-haiku-4-5-20251001",
) -> None:
    """
    Use the Anthropic API to generate a plain-English triage note for each
    HIGH finding, stored in finding.ai_explanation.

    Requires the ANTHROPIC_API_KEY environment variable.
    """
    try:
        import anthropic  # type: ignore[import]
    except ImportError:
        print("Warning: anthropic package not installed — run: pip install anthropic")
        return

    high = [f for f in findings if f.severity == "HIGH"]
    if not high:
        return

    client = anthropic.Anthropic()
    print(f"  AI triage: analysing {len(high)} HIGH finding(s) with {model} …")

    seen: set[tuple[str, int, str]] = set()
    for f in high:
        key = (f.file, f.line, f.rule_id)
        if key in seen:
            continue
        seen.add(key)

        prompt = (
            "You are a security expert reviewing a SAST tool finding. Be concise.\n\n"
            f"Rule    : {f.rule_id} | Severity: {f.severity}\n"
            f"CWE/OWASP: {f.cwe} / {f.owasp}\n"
            f"File    : {f.file} line {f.line}\n"
            f"Message : {f.message}\n"
            f"Snippet : {f.code_snippet}\n\n"
            "In 2-3 sentences answer: "
            "(1) Is this likely a true positive or false positive? "
            "(2) What is the real exploitability risk? "
            "(3) What is the recommended fix?"
        )
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=250,
                messages=[{"role": "user", "content": prompt}],
            )
            explanation = resp.content[0].text.strip()
        except Exception as exc:
            explanation = f"[AI triage unavailable: {exc}]"

        # Apply to all findings with the same key
        for f2 in findings:
            if (f2.file, f2.line, f2.rule_id) == key:
                f2.ai_explanation = explanation


# ── Multi-line / logical-line normalization ───────────────────────────────────

_OPEN_BRACKETS  = frozenset("([{")
_CLOSE_BRACKETS = frozenset(")]}")

def _logical_lines(source: str, language: str) -> list[tuple[int, str]]:
    """
    Join continuation lines into single logical lines for non-Python languages.

    Returns a list of (start_line_no, joined_text) tuples where line numbers
    are 1-based and refer to the first physical line of each logical line.

    Strategy:
    - Track open bracket depth; while depth > 0 join subsequent physical lines.
    - Also handle explicit line-continuations: backslash at end of line (C/Java/JS)
      and the pipe-at-start pattern used in some shell scripts.
    - Python is excluded — its AST engine is already multi-line-aware.
    """
    if language == "python":
        return [(i + 1, ln) for i, ln in enumerate(source.splitlines())]

    physical = source.splitlines()
    result: list[tuple[int, str]] = []
    depth   = 0
    buf     = ""
    start   = 1

    for i, raw in enumerate(physical):
        lineno = i + 1
        stripped = raw.rstrip()

        if not buf:
            start = lineno
            buf   = stripped
        else:
            buf += " " + stripped.lstrip()

        for ch in stripped:
            if ch in _OPEN_BRACKETS:
                depth += 1
            elif ch in _CLOSE_BRACKETS:
                depth = max(0, depth - 1)

        cont = depth > 0 or stripped.endswith("\\")
        if not cont:
            result.append((start, buf))
            buf   = ""
            depth = 0

    if buf:
        result.append((start, buf))

    return result


# Injection-class rules to re-run against logical lines (non-Python only)
_MULTILINE_RULES: dict[str, list[tuple[str, re.Pattern, str, str]]] = {
    "javascript": [
        ("SEC004", re.compile(
            r'(?:query|sql|SQL)\s*[+=]\s*.*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\$\{',
            re.IGNORECASE),
         "SQL injection via template literal across lines", "HIGH"),
        ("SEC004", re.compile(
            r'''(?:query|sql)\s*=\s*['"`][^'"`]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"`]*['"`]\s*\+''',
            re.IGNORECASE),
         "SQL injection via string concatenation across lines", "HIGH"),
        ("SEC006", re.compile(
            r'(?:innerHTML|outerHTML|document\.write)\s*[+=]\s*.*(?:req\.|request\.|params\.|query\.)',
            re.IGNORECASE),
         "XSS via multi-line DOM assignment", "HIGH"),
        ("SEC035", re.compile(
            r'req\.(query|params|body)(?:(?!startsWith).)*path\.(?:join|resolve)(?:(?!startsWith).)*fs\.(?:readFile|readFileSync|createReadStream)',
            re.IGNORECASE | re.DOTALL),
         "Path traversal: user input flows through path.join to fs.readFile without prefix validation", "HIGH"),
    ],
    "php": [
        ("SEC004", re.compile(
            r'(?:mysql_query|mysqli_query|PDO)\s*\(.*\$_(GET|POST|REQUEST|COOKIE)',
            re.IGNORECASE),
         "SQL injection: user input directly in query across lines", "HIGH"),
        ("SEC006", re.compile(
            r'echo\s+.*\$_(GET|POST|REQUEST|COOKIE)',
            re.IGNORECASE),
         "XSS: echoing unescaped user input across lines", "HIGH"),
    ],
    "java": [
        ("SEC004", re.compile(
            r'(?:createQuery|createNativeQuery|executeQuery|prepareStatement)\s*\(.*\+\s*(?:request\.getParameter|req\.getParam)',
            re.IGNORECASE),
         "SQL injection via concatenation across lines", "HIGH"),
    ],
    "go": [
        ("SEC004", re.compile(
            r'(?:db\.Query|db\.Exec|DB\.Raw)\s*\(.*\+\s*\w',
            re.IGNORECASE),
         "SQL injection via string concatenation across lines", "HIGH"),
    ],
}


def scan_multiline(path: Path, language: str) -> list[Finding]:
    """
    Apply injection rules to normalized logical lines to catch patterns that
    span multiple physical lines (e.g., a SQL query assembled via concatenation).
    Only runs for non-Python languages where we have explicit multi-line rules.
    """
    ml_rules = _MULTILINE_RULES.get(language)
    if not ml_rules:
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    logical = _logical_lines(source, language)
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()

    for lineno, text in logical:
        for rule_id, pattern, message, severity in ml_rules:
            if not pattern.search(text):
                continue
            key = (lineno, rule_id)
            if key in seen:
                continue
            seen.add(key)
            cwe, owasp = RULE_META.get(rule_id, ("", ""))
            findings.append(Finding(
                file=str(path),
                line=lineno,
                severity=severity,
                rule_id=rule_id + "M",
                language=language,
                message=message,
                code_snippet=text[:120],
                confidence="MEDIUM",
                cwe=cwe,
                owasp=owasp,
            ))

    return findings


# ── Cross-file taint tracking (Python) ───────────────────────────────────────

def _build_cross_file_taint_map(files: list[Path]) -> frozenset[str]:
    """
    Pre-pass over all Python files: collect names of functions/methods whose
    return values are tainted by user-controlled sources.

    Returns a frozenset of bare function names.  These are passed into
    scan_python_ast_taint() as additional taint sources so that, if file A
    defines get_username() which returns request.args["user"], and file B
    calls get_username() and feeds the result to cursor.execute(), file B
    will report a SQL-injection finding.
    """
    tainted_funcs: set[str] = set()

    for path in files:
        if not path.suffix == ".py":
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree   = ast.parse(source)
        except (SyntaxError, OSError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            tainted = _propagate_taint(node, frozenset())
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value is not None:
                    if _is_py_source(child.value) or (tainted and _uses_tainted(child.value, tainted)):
                        tainted_funcs.add(node.name)
                        break

    return frozenset(tainted_funcs)


# ── Inter-procedural call graph & function taint summaries ─────────────────────────

@dataclass
class FuncSummary:
    """
    Taint signature for a single function.
    sink_params maps parameter index to list of (rule_id, severity, message)
    for sinks that are reachable when that parameter is tainted.
    """
    name: str
    file: Path
    params: list
    # param_index → list of (rule_id, severity, message)
    sink_params: dict
    returns_tainted: bool
    lineno: int


def _propagate_taint_from_seed(
    func: "ast.FunctionDef | ast.AsyncFunctionDef",
    seed: set[str],
    known_tainted_funcs: frozenset[str] = frozenset(),
) -> set[str]:
    """
    Same as _propagate_taint but starts from an explicit seed set instead of
    looking for request.* sources. Used for computing per-parameter taint flows.

    A2: Pre-extract all assignment-like nodes once — O(N) instead of O(N×K).
    Also handles AugAssign, Attribute alias, and container mutation (same as
    _propagate_taint).
    """
    # Pre-extract all assignment-like nodes once
    assign_nodes: list[tuple[ast.expr, list[ast.expr]]] = []
    mutation_calls: list[tuple[str, ast.expr]] = []

    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            assign_nodes.append((node.value, node.targets))
        elif isinstance(node, ast.AnnAssign) and node.value:
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.NamedExpr):
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.AugAssign):
            assign_nodes.append((node.value, [node.target]))
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            call = node.value
            if (
                isinstance(call.func, ast.Attribute)
                and call.func.attr in ("append", "extend", "update", "add")
                and isinstance(call.func.value, ast.Name)
                and call.args
            ):
                mutation_calls.append((call.func.value.id, call.args[0]))

    tainted = set(seed)
    while True:
        prev = len(tainted)
        for rhs, targets in assign_nodes:
            is_tainted = _uses_tainted(rhs, tainted)
            if not is_tainted and known_tainted_funcs and isinstance(rhs, ast.Call):
                cn = _py_call_name(rhs)
                if cn in known_tainted_funcs or cn.rsplit(".", 1)[-1] in known_tainted_funcs:
                    is_tainted = True
            if is_tainted:
                for t in targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
                    elif isinstance(t, (ast.Tuple, ast.List)):
                        for elt in t.elts:
                            if isinstance(elt, ast.Name):
                                tainted.add(elt.id)
                    elif isinstance(t, ast.Attribute):
                        tainted.add("attr:" + _dotted_name(t))

        for container_name, arg_node in mutation_calls:
            if _uses_tainted(arg_node, tainted):
                tainted.add(container_name)

        if len(tainted) == prev:
            break
    return tainted


def _compute_func_summary(
    func: "ast.FunctionDef | ast.AsyncFunctionDef",
    file: Path,
    known_tainted_funcs: frozenset[str] = frozenset(),
) -> FuncSummary:
    """
    For each parameter of `func`, hypothetically treat it as a taint source
    and check if any sink in _PY_SINK_TABLE becomes reachable.
    This builds a per-function taint signature used for inter-procedural analysis.
    """
    params = [arg.arg for arg in func.args.args]
    # Skip 'self' and 'cls' as they are not data parameters
    data_params = [(i, p) for i, p in enumerate(params) if p not in ("self", "cls")]
    sink_params: dict[int, list[tuple[str, str, str]]] = {}

    for i, param_name in data_params:
        seed = {param_name}
        tainted = _propagate_taint_from_seed(func, seed, known_tainted_funcs)

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            all_args = list(node.args) + [kw.value for kw in node.keywords]
            if not any(_uses_tainted(a, tainted) for a in all_args):
                continue
            call_name = _py_call_name(node)
            last = call_name.rsplit(".", 1)[-1]
            for rule_id, severity, sink_names, message in _PY_SINK_TABLE:
                if call_name in sink_names or last in sink_names:
                    sink_params.setdefault(i, []).append((rule_id, severity, message))
                    break

    # Check if the function returns tainted data (for cross-file propagation)
    base_tainted = _propagate_taint(func, known_tainted_funcs)
    returns_tainted = False
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and node.value is not None:
            if _is_py_source(node.value) or (base_tainted and _uses_tainted(node.value, base_tainted)):
                returns_tainted = True
                break

    return FuncSummary(
        name=func.name,
        file=file,
        params=params,
        sink_params=sink_params,
        returns_tainted=returns_tainted,
        lineno=func.lineno,
    )


def _build_func_summaries(files: list[Path]) -> dict[str, "FuncSummary"]:
    """
    First pass: collect tainted-return function names.
    Second pass: build full summaries with inter-function knowledge.

    Returns {func_name: FuncSummary} for all Python functions found in files.

    Keys stored for each function:
    - ``func_name``           — bare function name (original behaviour)
    - ``module.func_name``    — module-qualified (file stem + "." + name)
    - ``ClassName.func_name`` — class-qualified (for methods inside a class)
    """
    # Pass 1: collect functions whose return values are tainted
    tainted_return: set[str] = set()
    # Store (path, func_node, class_name_or_None) so we can build qualified keys
    func_nodes: list[tuple[Path, "ast.FunctionDef | ast.AsyncFunctionDef", str | None]] = []

    for path in files:
        if not path.suffix == ".py":
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, OSError):
            continue

        # Build a parent-map so we can determine if a FunctionDef is inside a ClassDef
        parent_map: dict[int, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parent_map[id(child)] = parent

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Determine class context (direct parent only)
                parent = parent_map.get(id(node))
                class_name: str | None = None
                if isinstance(parent, ast.ClassDef):
                    class_name = parent.name
                func_nodes.append((path, node, class_name))
                tainted = _propagate_taint(node, frozenset())
                for child in ast.walk(node):
                    if isinstance(child, ast.Return) and child.value is not None:
                        if _is_py_source(child.value) or (tainted and _uses_tainted(child.value, tainted)):
                            tainted_return.add(node.name)
                            break

    frozen_tainted = frozenset(tainted_return)

    # Pass 2: build full summaries with inter-procedural knowledge
    summaries: dict[str, FuncSummary] = {}
    for path, func, class_name in func_nodes:
        summary = _compute_func_summary(func, path, frozen_tainted)
        module_stem = path.stem  # e.g. "views" from "views.py"

        # Register under bare name (original behaviour — keeps backward compat)
        summaries[func.name] = summary
        # Register under module-qualified name: "views.process"
        summaries[f"{module_stem}.{func.name}"] = summary
        # Register under class-qualified name: "MyView.process"
        if class_name:
            summaries[f"{class_name}.{func.name}"] = summary

    return summaries


def scan_interprocedural(
    path: Path,
    func_summaries: "dict[str, FuncSummary]",
    cross_file_funcs: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Inter-procedural taint analysis: detect call sites where tainted arguments
    are passed to functions whose summaries indicate those params reach a sink.

    This catches patterns that single-file analysis misses, e.g.:
        # file a.py
        def process(user_input):           # param 0 → SQL sink
            db.execute("SELECT " + user_input)

        # file b.py
        name = request.args.get("name")
        process(name)                      # ← flagged here
    """
    if not func_summaries:
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines = source.splitlines()
        tree = ast.parse(source)
    except (SyntaxError, OSError):
        return []

    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    all_funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    for func in all_funcs:
        tainted = _propagate_taint(func, cross_file_funcs)
        if not tainted:
            continue

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            call_name = _py_call_name(node)
            last = call_name.rsplit(".", 1)[-1]

            # Resolve summary: try full name first, then last component (method name),
            # and also the full dotted name (covers ClassName.method and module.func).
            summary = (
                func_summaries.get(call_name)
                or func_summaries.get(last)
            )
            if not summary or not summary.sink_params:
                continue

            # Exclude self-calls (recursive)
            if summary.name == func.name:
                continue

            for arg_idx, arg_node in enumerate(node.args):
                if arg_idx not in summary.sink_params:
                    continue
                if not _uses_tainted(arg_node, tainted):
                    continue
                for rule_id, severity, message in summary.sink_params[arg_idx]:
                    key = (node.lineno, rule_id)
                    if key in reported:
                        continue
                    reported.add(key)
                    snippet = lines[node.lineno - 1].strip() if node.lineno <= len(lines) else ""
                    cwe, owasp = RULE_META.get(rule_id, ("", ""))
                    findings.append(Finding(
                        file=str(path),
                        line=node.lineno,
                        severity=severity,
                        rule_id=rule_id,
                        language="python",
                        message=(
                            f"{message} — tainted arg passed to '{summary.name}' "
                            f"(defined in {summary.file.name}, line {summary.lineno})"
                        ),
                        code_snippet=snippet[:120],
                        confidence="HIGH",
                        cwe=cwe,
                        owasp=owasp,
                    ))

    return findings


# ── SCA — Software Composition Analysis via OSV ───────────────────────────────

import urllib.request
import urllib.error

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

_SCA_RULE_META = ("CWE-1395", "A06:2021")
RULE_META["SCA001"] = _SCA_RULE_META


def _query_osv_batch(packages: list[dict]) -> list[list[dict]]:
    """
    Query OSV /v1/querybatch for a list of {ecosystem, name, version} dicts.
    Returns a list of vuln-lists, one per package (same order).
    """
    if not packages:
        return []

    queries = []
    for pkg in packages:
        q: dict = {"package": {"name": pkg["name"], "ecosystem": pkg["ecosystem"]}}
        if pkg.get("version"):
            q["version"] = pkg["version"]
        queries.append(q)

    body = json.dumps({"queries": queries}).encode()
    req  = urllib.request.Request(
        _OSV_BATCH_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError):
        return [[] for _ in packages]

    results = data.get("results", [])
    out: list[list[dict]] = []
    for r in results:
        out.append(r.get("vulns", []))
    while len(out) < len(packages):
        out.append([])
    return out


def _parse_requirements(path: Path) -> list[dict]:
    """Parse requirements.txt / requirements-*.txt into [{name, version, line}]."""
    pkgs = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Strip extras and environment markers
        line = re.sub(r"\[.*?\]", "", line)
        line = line.split(";")[0].strip()
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*(?:[=~!<>]+\s*([\w\.]+))?", line)
        if m:
            pkgs.append({"name": m.group(1), "version": m.group(2) or "", "line": i, "ecosystem": "PyPI"})
    return pkgs


def _parse_package_json(path: Path) -> list[dict]:
    """Parse package.json dependencies into [{name, version, line}]."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except json.JSONDecodeError:
        return []
    pkgs = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, ver in (data.get(section) or {}).items():
            ver_clean = re.sub(r"[^0-9\.]", "", ver).strip(".")
            pkgs.append({"name": name, "version": ver_clean, "line": 1, "ecosystem": "npm"})
    return pkgs


def _parse_go_mod(path: Path) -> list[dict]:
    """Parse go.mod require blocks into [{name, version, line}]."""
    pkgs = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        m = re.match(r"^\s*require\s+(\S+)\s+(v[\w\.\-]+)", raw)
        if not m:
            m = re.match(r"^\s+(\S+)\s+(v[\w\.\-]+)", raw)
        if m:
            ver = m.group(2).lstrip("v")
            pkgs.append({"name": m.group(1), "version": ver, "line": i, "ecosystem": "Go"})
    return pkgs


def _parse_pom_xml(path: Path) -> list[dict]:
    """Parse pom.xml <dependency> blocks into [{name, version, line}]."""
    import xml.etree.ElementTree as ET
    pkgs = []
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        ns   = re.match(r"\{.*\}", root.tag)
        ns   = ns.group(0) if ns else ""
        for dep in root.iter(f"{ns}dependency"):
            group    = (dep.find(f"{ns}groupId")    or ET.Element("x")).text or ""
            artifact = (dep.find(f"{ns}artifactId") or ET.Element("x")).text or ""
            ver_el   = dep.find(f"{ns}version")
            version  = (ver_el.text or "").strip("${}") if ver_el is not None else ""
            if artifact:
                name = f"{group}:{artifact}" if group else artifact
                pkgs.append({"name": name, "version": version, "line": 1, "ecosystem": "Maven"})
    except Exception:
        pass
    return pkgs


def scan_sca(root: Path, exclude: list[str] | None = None) -> list[Finding]:
    """
    Software Composition Analysis: parse dependency manifests and query the OSV
    database for known CVEs / GHSAs.

    Manifest files detected:
      requirements*.txt  → PyPI
      package.json       → npm
      go.mod             → Go
      pom.xml            → Maven
    """
    exclude = exclude or []
    manifest_parsers = [
        (re.compile(r"requirements.*\.txt$"), _parse_requirements),
        (re.compile(r"package\.json$"),       _parse_package_json),
        (re.compile(r"go\.mod$"),             _parse_go_mod),
        (re.compile(r"pom\.xml$"),            _parse_pom_xml),
    ]

    # Collect all manifests
    manifests: list[tuple[Path, callable]] = []
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(ex in f.parts for ex in exclude):
            continue
        for pattern, parser in manifest_parsers:
            if pattern.search(f.name):
                manifests.append((f, parser))
                break

    if not manifests:
        return []

    # Parse each manifest and batch-query OSV
    findings: list[Finding] = []

    for manifest_path, parser in manifests:
        try:
            pkgs = parser(manifest_path)
        except Exception:
            pkgs = []
        if not pkgs:
            continue

        print(f"  SCA: checking {len(pkgs)} package(s) in {manifest_path.name} …")
        vuln_lists = _query_osv_batch(pkgs)

        for pkg, vulns in zip(pkgs, vuln_lists):
            for vuln in vulns[:3]:  # cap at 3 CVEs per package to avoid noise
                vid      = vuln.get("id", "UNKNOWN")
                summary  = vuln.get("summary", "Known vulnerability")
                severity = "HIGH"
                # Try to derive severity from CVSS if available
                for sev_info in vuln.get("severity", []):
                    score_str = sev_info.get("score", "")
                    m = re.search(r"CVSS:[\d\.]+/.*?/S(?:core)?:(\d+\.?\d*)", score_str)
                    if not m:
                        m = re.search(r"(\d+\.\d+)", score_str)
                    if m:
                        score = float(m.group(1))
                        if score >= 7.0:
                            severity = "HIGH"
                        elif score >= 4.0:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        break

                ver_info = f" {pkg['version']}" if pkg.get("version") else ""
                ecosystem = pkg.get("ecosystem", "")
                message = (
                    f"[SCA] {ecosystem} package '{pkg['name']}'{ver_info} "
                    f"has known vulnerability {vid}: {summary}"
                )
                findings.append(Finding(
                    file=str(manifest_path),
                    line=pkg["line"],
                    severity=severity,
                    rule_id="SCA001",
                    language="sca",
                    message=message[:300],
                    code_snippet=f"{pkg['name']}{ver_info}",
                    confidence="HIGH",
                    cwe="CWE-1395",
                    owasp="A06:2021",
                ))

    return findings


# ── Parallel scanning ─────────────────────────────────────────────────────────

# scan_python_ast_taint uses a module-level set that is read-only after the
# cross-file pre-pass, so thread safety is fine.
_print_lock = threading.Lock()


def _scan_file_worker(
    path: Path,
    taint_window: int,
    cross_file_funcs: frozenset[str],
    func_summaries: "dict[str, FuncSummary] | None" = None,
) -> list[Finding]:
    return scan_file(
        path,
        taint_window=taint_window,
        cross_file_funcs=cross_file_funcs,
        func_summaries=func_summaries,
    )


def scan_files_parallel(
    files: list[Path],
    taint_window: int = 25,
    cross_file_funcs: frozenset[str] = frozenset(),
    jobs: int = 4,
    func_summaries: "dict[str, FuncSummary] | None" = None,
) -> list[Finding]:
    """
    Scan a list of files in parallel using a thread pool.

    Python's GIL means I/O-bound work (file reads, regex) gets real concurrency
    here; AST parsing also releases the GIL for most operations.
    """
    results: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_scan_file_worker, f, taint_window, cross_file_funcs, func_summaries): f
            for f in files
        }
        for fut in concurrent.futures.as_completed(futures):
            try:
                results.extend(fut.result())
            except Exception as exc:
                with _print_lock:
                    print(f"  Warning: error scanning {futures[fut]}: {exc}")
    return results


# ── Baseline suppression ──────────────────────────────────────────────────────

def _finding_fingerprint(f: Finding) -> str:
    """Stable key that identifies a finding independent of line drift."""
    return f"{f.rule_id}:{f.file}:{f.code_snippet[:80]}"


def load_baseline(baseline_path: str) -> set[str]:
    """Load a baseline file and return the set of known finding fingerprints."""
    p = Path(baseline_path)
    if not p.exists():
        return set()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return set(data.get("fingerprints", []))
    except Exception:
        return set()


def save_baseline(findings: list[Finding], baseline_path: str) -> None:
    """Write current findings as the new baseline (suppressed in future runs)."""
    fingerprints = sorted({_finding_fingerprint(f) for f in findings})
    data = {
        "version": 1,
        "count": len(fingerprints),
        "fingerprints": fingerprints,
    }
    Path(baseline_path).write_text(json.dumps(data, indent=2))
    print(f"  Baseline saved: {len(fingerprints)} finding(s) → {baseline_path}")


def filter_baseline(findings: list[Finding], known: set[str]) -> tuple[list[Finding], int]:
    """
    Remove findings whose fingerprint is in the baseline.
    Returns (new_findings, suppressed_count).
    """
    new, suppressed = [], 0
    for f in findings:
        if _finding_fingerprint(f) in known:
            suppressed += 1
        else:
            new.append(f)
    return new, suppressed


# ── Git history secret scanning ───────────────────────────────────────────────

_HISTORY_RULE_META = ("CWE-798", "A07:2021")
RULE_META["SEC001H"] = _HISTORY_RULE_META

# Reuse the entropy scanner; patches are plain text so we parse the diff hunks
_DIFF_FILE_RE   = re.compile(r"^diff --git a/(.+) b/\1")
_DIFF_HUNK_RE   = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_DIFF_ADDED_RE  = re.compile(r"^\+(?!\+\+)")  # added lines start with +, not +++


def scan_git_history(
    root: Path,
    max_commits: int = 100,
    since: str = "",
) -> list[Finding]:
    """
    Walk the last `max_commits` commits in the git repo at `root`, extract
    added lines from each patch, and apply entropy + known-prefix secret
    detection to catch credentials committed in the past.

    Returns Finding objects with:
      file    = path as it appeared in the commit
      line    = line number within the file at that commit
      rule_id = SEC001H
      message = includes the commit hash
    """
    cmd = ["git", "-C", str(root), "log",
           "--all", "--oneline", "--no-merges",
           f"-{max_commits}"]
    if since:
        cmd += [f"--since={since}"]

    try:
        log = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []

    commits = [line.split(" ", 1)[0] for line in log.splitlines() if line.strip()]
    if not commits:
        return []

    print(f"  History scan: inspecting {len(commits)} commit(s) …")
    findings: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()

    for sha in commits:
        try:
            patch = subprocess.check_output(
                ["git", "-C", str(root), "show", "--unified=0", "--no-color", sha],
                stderr=subprocess.DEVNULL,
                text=True,
                errors="ignore",
            )
        except subprocess.CalledProcessError:
            continue

        cur_file = ""
        cur_line = 0

        for raw in patch.splitlines():
            m = _DIFF_FILE_RE.match(raw)
            if m:
                cur_file = m.group(1)
                cur_line = 0
                continue

            m = _DIFF_HUNK_RE.match(raw)
            if m:
                cur_line = int(m.group(1))
                continue

            if not _DIFF_ADDED_RE.match(raw):
                continue

            added_text = raw[1:]  # strip leading +
            cur_line  += 1

            # Skip lines that are clearly not secrets
            stripped = added_text.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue

            # Check for known secret prefixes first (fast path)
            hit_prefix = any(pf in added_text for pf in _SECRET_PREFIXES)

            # Extract string literals and check entropy
            secret_val = ""
            for m2 in _STRING_LITERAL_RE.finditer(added_text):
                val = m2.group(1) or m2.group(2)
                if _looks_like_secret(val):
                    secret_val = val
                    break

            if not hit_prefix and not secret_val:
                continue

            key = (sha, cur_file, cur_line)
            if key in seen:
                continue
            seen.add(key)

            if hit_prefix and not secret_val:
                # Flag the whole line (known-prefix pattern)
                snippet = stripped[:100]
                msg = f"Possible hardcoded secret in git history (commit {sha[:8]})"
            else:
                snippet = secret_val[:100]
                msg = (f"High-entropy string in git history (commit {sha[:8]}) "
                       f"— possible leaked credential")

            findings.append(Finding(
                file=cur_file,
                line=cur_line,
                severity="HIGH",
                rule_id="SEC001H",
                language="secret",
                message=msg,
                code_snippet=snippet,
                confidence="MEDIUM",
                cwe="CWE-798",
                owasp="A07:2021",
            ))

    return findings


_CONFIDENCE_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

_SEVERITY_TO_SARIF = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def _to_sarif(findings: list[Finding], scan_path: str) -> dict:
    """
    Convert a list of Finding objects to a SARIF 2.1.0 dict.
    """
    # Deduplicate rules by rule_id, using first occurrence
    seen_rules: dict[str, dict] = {}
    for f in findings:
        if f.rule_id not in seen_rules:
            cwe_num = f.cwe.replace("CWE-", "") if f.cwe else ""
            help_uri = (
                f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
                if cwe_num else ""
            )
            seen_rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message},
                "helpUri": help_uri,
                "properties": {
                    "tags": ["security"],
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                },
            }

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SEVERITY_TO_SARIF.get(f.severity, "note"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f.file,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {"startLine": f.line},
                }
            }],
            "properties": {
                "confidence": f.confidence,
                "language": f.language,
                "cwe": f.cwe,
                "owasp": f.owasp,
            },
        })

    return {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "git-better-scanner",
                    "version": "1.0.0",
                    "rules": list(seen_rules.values()),
                }
            },
            "results": results,
        }],
    }


def _is_third_party_library(path: Path) -> bool:
    """
    Check if a file is a known third-party library file to reduce false positives.
    Returns True if the file should be excluded.
    """
    # Common third-party library filenames (case-insensitive)
    library_files = {
        "parsedown.php", "markdown.php", "smarty.class.php", "geshi.php",
        "htmlpurifier.auto.php", "swift_required.php", "phpmailer.php",
        "jquery.min.js", "bootstrap.min.js", "angular.min.js", "react.min.js",
        "lodash.min.js", "moment.min.js", "d3.min.js"
    }

    filename_lower = path.name.lower()

    # Check for exact library file matches
    if filename_lower in library_files:
        return True

    # Exclude minified JS/CSS files (common in third-party libraries)
    if filename_lower.endswith('.min.js') or filename_lower.endswith('.min.css'):
        return True

    # Exclude files in common third-party include directories
    if any(part in ('includes', 'lib', 'libs', 'third_party', 'thirdparty', 'external')
           for part in path.parts):
        # Only exclude if it's a known library pattern
        if any(lib in filename_lower for lib in ['jquery', 'bootstrap', 'parsedown', 'markdown', 'tinymce']):
            return True

    return False


def main():
    parser = argparse.ArgumentParser(
        description="Multi-language vulnerability scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan, JSON output
  python vuln_scanner.py --path ./src --output report.json

  # SARIF output for GitHub Advanced Security
  python vuln_scanner.py --path . --format sarif --output results.sarif

  # Incremental scan — only files changed since last commit
  python vuln_scanner.py --path . --diff --base-ref HEAD~1

  # Load custom YAML rules
  python vuln_scanner.py --path ./src --rules rules/custom.yaml

  # AI-assisted triage of HIGH findings (requires ANTHROPIC_API_KEY)
  python vuln_scanner.py --path ./src --ai-explain
""",
    )
    parser.add_argument("--path",    default=".",  help="File or directory to scan")
    parser.add_argument("--output",  default="scan-report.json")
    parser.add_argument("--exclude", nargs="*",
                        default=["venv", ".venv", "node_modules", "__pycache__", "dist", "build",
                                 "vendor", ".git", ".svn", "bower_components", "jspm_packages",
                                 ".eggs", "*.egg-info", "htmlcov", ".tox", ".pytest_cache",
                                 "site-packages", "lib/python", "env", ".bundle"])
    parser.add_argument("--taint-window", type=int, default=25,
                        help="Lines to look back for taint sources (default: 25)")
    parser.add_argument("--format", choices=["json", "sarif"], default="json",
                        help="Output format: json (default) or sarif")
    parser.add_argument("--min-confidence", choices=["LOW", "MEDIUM", "HIGH"], default="LOW",
                        help="Minimum confidence level for findings (default: LOW)")
    # New: diff / incremental scanning
    parser.add_argument("--diff", action="store_true",
                        help="Only scan files changed relative to --base-ref (git diff)")
    parser.add_argument("--base-ref", default="HEAD~1", metavar="REF",
                        help="Git ref to diff against when --diff is used (default: HEAD~1)")
    # New: YAML custom rules
    parser.add_argument("--rules", nargs="*", metavar="FILE",
                        help="YAML rule files to load in addition to built-in rules")
    # New: AI-assisted triage
    parser.add_argument("--ai-explain", action="store_true",
                        help="Use Anthropic API to triage HIGH findings (requires ANTHROPIC_API_KEY)")
    parser.add_argument("--ai-model", default="claude-haiku-4-5-20251001", metavar="MODEL",
                        help="Anthropic model for AI triage (default: claude-haiku-4-5-20251001)")
    # New: SCA
    parser.add_argument("--no-sca", action="store_true",
                        help="Skip Software Composition Analysis (OSV network calls)")
    # New: parallel scanning
    parser.add_argument("--jobs", type=int, default=4, metavar="N",
                        help="Parallel scan workers (default: 4)")
    # New: baseline suppression
    parser.add_argument("--baseline", metavar="FILE",
                        help="Suppress findings present in this baseline file")
    parser.add_argument("--update-baseline", metavar="FILE",
                        help="After scanning, write all findings as the new baseline")
    # New: git history secret scanning
    parser.add_argument("--scan-history", action="store_true",
                        help="Scan git commit history for committed secrets")
    parser.add_argument("--history-commits", type=int, default=100, metavar="N",
                        help="Number of commits to inspect (default: 100)")
    parser.add_argument("--history-since", default="", metavar="DATE",
                        help="Only scan commits after this date, e.g. '2024-01-01'")

    args = parser.parse_args()

    # Load custom YAML rules before building the file list
    if args.rules:
        _load_yaml_rules(args.rules)

    root = Path(args.path).resolve()

    # Determine the file list
    if args.diff:
        # Incremental: only changed files
        scan_files = _get_diff_files(args.base_ref, root)
        # Apply extension filter and exclude list
        scan_files = [
            f for f in scan_files
            if _detect_language(f) is not None
            and not any(ex in f.parts for ex in (args.exclude or []))
            and not _is_third_party_library(f)
        ]
        print(f"  Diff mode: {len(scan_files)} changed file(s) relative to {args.base_ref}")
    elif root.is_file():
        scan_files = [root] if _detect_language(root) is not None else []
    elif root.is_dir():
        scan_files = [
            f for f in root.rglob("*")
            if f.is_file()
            and _detect_language(f) is not None
            and not any(ex in f.parts for ex in (args.exclude or []))
            and not _is_third_party_library(f)
        ]
    else:
        print(f"Error: {root} is not a valid file or directory")
        sys.exit(1)

    # Cross-file taint pre-pass (Python only) — build inter-procedural function summaries
    python_files = [f for f in scan_files if f.suffix == ".py"]
    cross_file_funcs: frozenset[str] = frozenset()
    func_summaries: dict[str, FuncSummary] = {}
    if python_files:
        print(f"  Cross-file taint: analysing {len(python_files)} Python file(s) …")
        func_summaries = _build_func_summaries(python_files)
        cross_file_funcs = frozenset(
            name for name, s in func_summaries.items() if s.returns_tainted
        )
        sink_funcs = sum(1 for s in func_summaries.values() if s.sink_params)
        print(
            f"  Inter-procedural: {len(func_summaries)} functions analysed, "
            f"{len(cross_file_funcs)} return tainted data, "
            f"{sink_funcs} have sink-reaching parameters"
        )

    # Parallel file scanning
    jobs = max(1, args.jobs)
    if jobs > 1 and len(scan_files) > 1:
        print(f"  Scanning {len(scan_files)} file(s) with {jobs} worker(s) …")
        all_findings: list[Finding] = scan_files_parallel(
            scan_files, taint_window=args.taint_window,
            cross_file_funcs=cross_file_funcs, jobs=jobs,
            func_summaries=func_summaries,
        )
    else:
        all_findings = []
        for f in scan_files:
            all_findings.extend(scan_file(f, taint_window=args.taint_window,
                                          cross_file_funcs=cross_file_funcs,
                                          func_summaries=func_summaries))

    # SCA scan (dependency manifests → OSV API)
    if not args.no_sca and root.is_dir():
        all_findings.extend(scan_sca(root, exclude=args.exclude))

    # Git history secret scanning
    if args.scan_history:
        history_root = root if root.is_dir() else root.parent
        all_findings.extend(
            scan_git_history(history_root,
                             max_commits=args.history_commits,
                             since=args.history_since)
        )

    # Apply --min-confidence filter
    min_conf_level = _CONFIDENCE_ORDER.get(args.min_confidence, 0)
    all_findings = [
        f for f in all_findings
        if _CONFIDENCE_ORDER.get(f.confidence, 0) >= min_conf_level
    ]

    # Baseline suppression — load known fingerprints and filter them out
    suppressed = 0
    if args.baseline:
        known = load_baseline(args.baseline)
        if known:
            all_findings, suppressed = filter_baseline(all_findings, known)
            print(f"  Baseline: {suppressed} known finding(s) suppressed, "
                  f"{len(all_findings)} new finding(s) remain")

    # AI-assisted triage of HIGH findings
    if args.ai_explain:
        _ai_explain_findings(all_findings, model=args.ai_model)

    by_lang: dict[str, list[Finding]] = {}
    for f in all_findings:
        by_lang.setdefault(f.language, []).append(f)

    if args.format == "sarif":
        output_data = _to_sarif(all_findings, args.path)
        Path(args.output).write_text(json.dumps(output_data, indent=2))
    else:
        report = {
            "total":       len(all_findings),
            "critical":    sum(1 for f in all_findings if f.severity == "CRITICAL"),
            "high":        sum(1 for f in all_findings if f.severity == "HIGH"),
            "medium":      sum(1 for f in all_findings if f.severity == "MEDIUM"),
            "low":         sum(1 for f in all_findings if f.severity == "LOW"),
            "suppressed":  suppressed,
            "by_language": {lang: len(fs) for lang, fs in by_lang.items()},
            "findings":    [asdict(f) for f in all_findings],
        }
        Path(args.output).write_text(json.dumps(report, indent=2))

    # Update baseline if requested (snapshot current findings for future runs)
    if args.update_baseline:
        save_baseline(all_findings, args.update_baseline)

    total    = len(all_findings)
    critical = sum(1 for f in all_findings if f.severity == "CRITICAL")
    high     = sum(1 for f in all_findings if f.severity == "HIGH")
    med      = sum(1 for f in all_findings if f.severity == "MEDIUM")
    low      = sum(1 for f in all_findings if f.severity == "LOW")

    _SEV_COLOR = {"CRITICAL": "\033[1;35m", "HIGH": "\033[1;31m",
                  "MEDIUM": "\033[1;33m", "LOW": "\033[1;34m"}
    _RESET = "\033[0m"
    if all_findings:
        print(f"\n{'─'*50}")
        print("  Findings:")
        for f in all_findings:
            color = _SEV_COLOR.get(f.severity, "")
            print(f"  {color}[{f.severity}]{_RESET} {f.rule_id}  "
                  f"{f.file}:{f.line}")
            print(f"         {f.message}")
    print(f"\n{'─'*50}")
    print(f"  Scan complete — {total} finding(s)"
          + (f"  ({suppressed} suppressed by baseline)" if suppressed else ""))
    print(f"  CRITICAL={critical}  HIGH={high}  MEDIUM={med}  LOW={low}")
    print(f"  By language: { {lang: len(flist) for lang, flist in by_lang.items()} }")
    print(f"{'─'*50}\n")

    sys.exit(1 if (critical > 0 or high > 0) else 0)


if __name__ == "__main__":
    main()
