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
        # XXE
        ("SEC067", "MEDIUM", r'\bimport\s+xml(?:\s|$)|\bfrom\s+xml\b',
                             "XML import detected — use defusedxml instead to prevent XXE attacks"),
        ("SEC083", "HIGH",   r'\blxml\.etree\b|\bxml\.sax\b|\bxml\.dom\b|\bxml\.etree\b|\bXMLParser\s*\(',
                             "XML parser usage — ensure external entities are disabled or use defusedxml"),
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
        # Type juggling
        ("SEC093", "HIGH",   r'\bif\s*\(.*==\s*(0|false|null|true|["\'][^"\']*["\'])|===\s*\d+\s*&&|\bswitch\s*\(\s*\$',
                             "Loose PHP comparison (==) — type juggling can bypass authentication checks, use ==="),
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
         r'\b(?:mysql_query|mysqli_query|->query|->prepare|PDO::query)\s*\(',
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
    sources = _TAINT_SOURCES.get(language, [])
    sinks   = _TAINT_SINKS.get(language, [])
    if not sources or not sinks:
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
        for pat in sources:
            if re.search(pat, line, re.IGNORECASE):
                var = _lhs_name(line, language)
                if var:
                    tainted.setdefault(var, []).append(i)

    if not tainted:
        return []

    # Pass 2: match sinks and check for tainted-variable usage
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        for rule_id, severity, sink_pat, message in sinks:
            if not re.search(sink_pat, line, re.IGNORECASE):
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
        # Everything on flask/Django request is tainted: request.args.get(…),
        # request.form.getlist(…), request.get_json(), etc.
        if name.startswith("request."):
            return True
        if name in _PY_SOURCE_CALLS or any(name.endswith("." + s) for s in _PY_SOURCE_CALLS):
            return True
    if isinstance(node, ast.Attribute):
        name = _dotted_name(node)
        if name.startswith("request."):
            return True
    if isinstance(node, ast.Subscript):
        return _is_py_source(node.value)
    # Tuple/List: tainted if *any* element is tainted, e.g. ``a, b = src(), src()``
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_is_py_source(e) for e in node.elts)
    return False


def _uses_tainted(node: ast.expr, tainted: set[str]) -> bool:
    """Return True if the expression tree contains any tainted variable name."""
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.BinOp):
        return _uses_tainted(node.left, tainted) or _uses_tainted(node.right, tainted)
    if isinstance(node, ast.JoinedStr):           # f-string
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted:
                return True
        return False
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_uses_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Dict):
        return any(_uses_tainted(v, tainted) for v in node.values if v)
    if isinstance(node, ast.Call):
        return any(_uses_tainted(a, tainted) for a in node.args) or any(
            _uses_tainted(kw.value, tainted) for kw in node.keywords
        )
    if isinstance(node, ast.Subscript):
        return _uses_tainted(node.value, tainted)
    if isinstance(node, ast.IfExp):
        return _uses_tainted(node.body, tainted) or _uses_tainted(node.orelse, tainted)
    if isinstance(node, ast.Attribute):
        return _uses_tainted(node.value, tainted)
    if isinstance(node, ast.Starred):
        return _uses_tainted(node.value, tainted)
    return False


def _propagate_taint(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_funcs: frozenset[str] = frozenset(),
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
    """
    tainted: set[str] = set()
    while True:
        prev = len(tainted)
        for node in ast.walk(func):
            rhs: ast.expr | None = None
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                rhs, targets = node.value, node.targets
            elif isinstance(node, ast.AnnAssign) and node.value:
                rhs, targets = node.value, [node.target]
            elif isinstance(node, ast.NamedExpr):   # walrus :=
                rhs, targets = node.value, [node.target]
            if rhs is None:
                continue
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
        if len(tainted) == prev:
            break   # fixed point reached
    return tainted


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

    # Phase 2: full analysis with inter-procedural taint
    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    for func in all_funcs:
        tainted = _propagate_taint(func, frozen_tainted_funcs)
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

    return findings


def scan_with_regex(path: Path, language: str) -> list[Finding]:
    findings: list[Finding] = []
    rules = RULES.get(language, [])
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

        for rule_id, severity, pattern, message in rules:
            m = re.search(pattern, line, re.IGNORECASE)
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


def scan_file(
    path: Path,
    taint_window: int = 25,
    cross_file_funcs: frozenset[str] = frozenset(),
) -> list[Finding]:
    """
    Run all scan engines for the given file and return deduplicated findings.

    Engines (in order, each de-duplicated by (line, rule_id)):
      1. scan_with_regex       — fast pattern matching with context filtering
      2. scan_entropy          — Shannon-entropy secret detection (all languages)
      3. scan_multiline        — multi-line/logical-line injection rules (non-Python)
      4. scan_python_ast       — Python AST: assert-statement detection
      5. scan_python_ast_taint — Python AST: intra+inter-procedural + cross-file taint
      6. scan_taint            — cross-line sliding-window taint (all languages)
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

    _merge(scan_taint(path, language, taint_window=taint_window))

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
        for rule in (data or {}).get("rules", []):
            rid      = str(rule.get("id", "")).strip()
            lang     = str(rule.get("language", "")).strip().lower()
            severity = str(rule.get("severity", "MEDIUM")).strip().upper()
            pattern  = str(rule.get("pattern", "")).strip()
            message  = str(rule.get("message", "Custom rule")).strip()
            cwe      = str(rule.get("cwe", "")).strip()
            owasp    = str(rule.get("owasp", "")).strip()

            if not rid or not lang or not pattern:
                print(f"Warning: skipping malformed rule in {rule_file!r}: {rule}")
                continue
            RULES.setdefault(lang, []).append((rid, severity, pattern, message))
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
) -> list[Finding]:
    return scan_file(path, taint_window=taint_window, cross_file_funcs=cross_file_funcs)


def scan_files_parallel(
    files: list[Path],
    taint_window: int = 25,
    cross_file_funcs: frozenset[str] = frozenset(),
    jobs: int = 4,
) -> list[Finding]:
    """
    Scan a list of files in parallel using a thread pool.

    Python's GIL means I/O-bound work (file reads, regex) gets real concurrency
    here; AST parsing also releases the GIL for most operations.
    """
    results: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_scan_file_worker, f, taint_window, cross_file_funcs): f
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
                        default=["venv", ".venv", "node_modules", "__pycache__", "dist", "build"])
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
        ]
    else:
        print(f"Error: {root} is not a valid file or directory")
        sys.exit(1)

    # Cross-file taint pre-pass (Python only) — build set of tainted function names
    python_files = [f for f in scan_files if f.suffix == ".py"]
    cross_file_funcs: frozenset[str] = frozenset()
    if python_files:
        print(f"  Cross-file taint: analysing {len(python_files)} Python file(s) …")
        cross_file_funcs = _build_cross_file_taint_map(python_files)
        if cross_file_funcs:
            print(f"  Cross-file taint: {len(cross_file_funcs)} taint-source function(s) found across files")

    # Parallel file scanning
    jobs = max(1, args.jobs)
    if jobs > 1 and len(scan_files) > 1:
        print(f"  Scanning {len(scan_files)} file(s) with {jobs} worker(s) …")
        all_findings: list[Finding] = scan_files_parallel(
            scan_files, taint_window=args.taint_window,
            cross_file_funcs=cross_file_funcs, jobs=jobs,
        )
    else:
        all_findings = []
        for f in scan_files:
            all_findings.extend(scan_file(f, taint_window=args.taint_window,
                                          cross_file_funcs=cross_file_funcs))

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

    total = len(all_findings)
    high  = sum(1 for f in all_findings if f.severity == "HIGH")
    med   = sum(1 for f in all_findings if f.severity == "MEDIUM")
    low   = sum(1 for f in all_findings if f.severity == "LOW")
    print(f"\n{'─'*50}")
    print(f"  Scan complete — {total} finding(s)"
          + (f"  ({suppressed} suppressed by baseline)" if suppressed else ""))
    print(f"  HIGH={high}  MEDIUM={med}  LOW={low}")
    print(f"  By language: { {lang: len(flist) for lang, flist in by_lang.items()} }")
    print(f"{'─'*50}\n")

    sys.exit(1 if high > 0 else 0)


if __name__ == "__main__":
    main()
