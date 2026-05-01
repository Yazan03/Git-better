"""Web dashboard for the vulnerability scanner.

Run with:
    cd dashboard && python app.py
Then open http://localhost:5000.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask, abort, flash, g, redirect, render_template, request, session, url_for,
)

from models import Finding, Report, User, make_session
from werkzeug.security import check_password_hash, generate_password_hash

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
SCANNER = PROJECT_ROOT / "scripts" / "vuln_scanner.py"
DATA_DIR = ROOT / "data"
UPLOAD_DIR = ROOT / "uploads"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

Session = make_session(str(DATA_DIR / "dashboard.db"))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-in-production")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


# ─────────────────────────── auth ────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user:
            return redirect(url_for("login_page", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not g.current_user:
            return redirect(url_for("login_page", next=request.path))
        if g.current_user.role != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


@app.before_request
def _load_user():
    user_id = session.get("user_id")
    g.current_user = None
    if user_id:
        with Session() as s:
            u = s.query(User).filter_by(id=user_id).first()
            if u:
                s.expunge(u)
            g.current_user = u


@app.context_processor
def _inject_user():
    return {"current_user": g.get("current_user")}


def _seed_admin() -> None:
    username = os.environ.get("ADMIN_USERNAME", "admin")
    password = os.environ.get("ADMIN_PASSWORD")
    if not password:
        return
    with Session() as s:
        if s.query(User).filter_by(username=username).first():
            return
        s.add(User(
            username=username,
            password_hash=generate_password_hash(password),
            role="admin",
        ))
        s.commit()


_seed_admin()


# ─────────────────────────── helpers ─────────────────────────────────────────

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

# Strict allowlist for repository hosts. Only public HTTPS clones are permitted.
ALLOWED_GIT_HOSTS = {
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
}

# Hard ceilings to keep a runaway clone from hanging the request.
CLONE_TIMEOUT_SECONDS = 90
SCAN_TIMEOUT_SECONDS = 180

# Detailed metadata for every scanner rule.
# Fields: title, what, impact, fix, cwe, owasp
RULE_META: dict[str, dict] = {
    "SEC001": {
        "title": "Hardcoded Secret / Credential",
        "what": "A password, API key, or secret token is embedded directly in source code.",
        "impact": "Anyone with read access to the repository can extract the credential and use it to compromise the target system, account, or service.",
        "fix": "Move secrets to environment variables or a secrets manager (Vault, AWS Secrets Manager, etc.). Rotate any exposed credential immediately.",
        "cwe": "CWE-798",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC002": {
        "title": "Dangerous Code Execution / Shell Injection",
        "what": "Functions such as eval(), exec(), os.system(), or pickle.loads() execute arbitrary code or shell commands.",
        "impact": "If any part of the input is attacker-controlled, the attacker can run arbitrary commands on the server (Remote Code Execution).",
        "fix": "Avoid eval/exec entirely. Replace os.system() with subprocess.run() using a list argument (no shell=True). Never deserialise pickle data from untrusted sources; prefer JSON.",
        "cwe": "CWE-78 / CWE-94",
        "owasp": "A03:2021 – Injection",
    },
    "SEC003": {
        "title": "Assert Used for Logic / Security Check",
        "what": "Python's assert statement is removed entirely when the interpreter runs with optimisations (-O flag).",
        "impact": "Security or validation checks written as assert statements silently disappear in production builds, bypassing intended guardrails.",
        "fix": "Replace assert with explicit if / raise checks for any logic that must hold in production.",
        "cwe": "CWE-617",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "SEC004": {
        "title": "SQL Injection",
        "what": "User-supplied data is concatenated directly into a SQL query string.",
        "impact": "Attackers can manipulate the query to dump the entire database, bypass authentication, modify or delete data, or in some configurations execute OS commands.",
        "fix": "Use parameterised queries / prepared statements exclusively. Never build SQL strings with format strings, f-strings, or concatenation involving user input.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection",
    },
    "SEC005": {
        "title": "Weak Cryptographic Hash (MD5 / SHA-1)",
        "what": "MD5 or SHA-1 is used for hashing. Both are considered cryptographically broken.",
        "impact": "Collision attacks against MD5/SHA-1 are practical. Pre-image attacks are feasible for short inputs. Password hashes can be cracked quickly with rainbow tables.",
        "fix": "Use SHA-256 or SHA-3 for general digests. For passwords, use a purpose-built KDF: bcrypt, scrypt, or Argon2.",
        "cwe": "CWE-327",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC006": {
        "title": "Cross-Site Scripting (XSS) — Unsafe DOM Write",
        "what": "innerHTML assignment or document.write() injects HTML directly into the DOM without sanitisation.",
        "impact": "Attackers can inject malicious scripts that run in the victim's browser, stealing cookies/tokens, performing actions on the user's behalf, or redirecting to phishing pages.",
        "fix": "Use textContent instead of innerHTML for plain text. For HTML, sanitise with DOMPurify before inserting. Avoid document.write() entirely.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection",
    },
    "SEC007": {
        "title": "React XSS — dangerouslySetInnerHTML",
        "what": "React's dangerouslySetInnerHTML bypasses its built-in XSS protection and injects raw HTML.",
        "impact": "Any unsanitised user-controlled value passed here executes as JavaScript in the victim's browser.",
        "fix": "Avoid dangerouslySetInnerHTML. If rich HTML is required, sanitise the input with DOMPurify before passing it.",
        "cwe": "CWE-79",
        "owasp": "A03:2021 – Injection",
    },
    "SEC008": {
        "title": "Insecure Randomness — Math.random()",
        "what": "Math.random() is a pseudo-random number generator (PRNG) that is not cryptographically secure.",
        "impact": "Tokens, session IDs, or nonces generated with Math.random() are predictable, enabling attackers to guess or forge them.",
        "fix": "Use the Web Crypto API: crypto.getRandomValues() or crypto.randomUUID() for security-sensitive values.",
        "cwe": "CWE-338",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC009": {
        "title": "Insecure Protocol — HTTP Instead of HTTPS",
        "what": "Plain HTTP URLs are used, meaning data is transmitted in cleartext.",
        "impact": "Network traffic can be intercepted and read or modified by attackers on the same network (man-in-the-middle). Credentials and session tokens are exposed.",
        "fix": "Use HTTPS (and WSS for WebSockets) for all connections. Enforce HSTS headers on your server.",
        "cwe": "CWE-319",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC010": {
        "title": "Debug Logging Left in Code",
        "what": "console.log / debug statements were found, often including sensitive values or internal state.",
        "impact": "Sensitive data (tokens, user info, internal paths) may leak to browser devtools or server logs accessible to unintended parties.",
        "fix": "Remove debug logs before deploying to production. Use a structured logging library with configurable log levels.",
        "cwe": "CWE-532",
        "owasp": "A09:2021 – Security Logging and Monitoring Failures",
    },
    "SEC011": {
        "title": "Unsanitised PHP User Input",
        "what": "Raw superglobal values ($_GET, $_POST, $_REQUEST, $_COOKIE) are used without validation or sanitisation.",
        "impact": "Depending on how the value is used, this can lead to SQL injection, XSS, path traversal, command injection, or other injection attacks.",
        "fix": "Validate and sanitise all user input. Use filter_input() or filter_var() with appropriate flags. For SQL, use PDO prepared statements.",
        "cwe": "CWE-20",
        "owasp": "A03:2021 – Injection",
    },
    "SEC012": {
        "title": "PHP Shell Execution",
        "what": "Functions shell_exec(), system(), or passthru() execute OS shell commands.",
        "impact": "If any part of the command string is user-controlled, the attacker can execute arbitrary commands on the server.",
        "fix": "Avoid shell execution functions. If necessary, use escapeshellarg() on every argument and avoid shell=true-equivalent patterns.",
        "cwe": "CWE-78",
        "owasp": "A03:2021 – Injection",
    },
    "SEC013": {
        "title": "Weak Hashing in PHP — md5() / sha1()",
        "what": "PHP's md5() or sha1() is used, typically for password hashing or integrity checks.",
        "impact": "MD5 and SHA-1 are cryptographically broken. Passwords stored this way can be cracked instantly with rainbow tables.",
        "fix": "Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID for passwords. Use hash('sha256', ...) or hash('sha3-256', ...) for general digests.",
        "cwe": "CWE-327",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC014": {
        "title": "Verbose PHP Error Reporting",
        "what": "error_reporting(E_ALL) displays all errors, warnings, and notices to the user.",
        "impact": "Detailed error messages expose stack traces, file paths, database schemas, and other internal details that help attackers map the application.",
        "fix": "Set error_reporting to E_ALL in development only. In production, log errors to a file (log_errors = On) and disable display_errors.",
        "cwe": "CWE-209",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "SEC015": {
        "title": "Java Runtime.exec() — Command Injection",
        "what": "Runtime.getRuntime().exec() executes OS commands from Java.",
        "impact": "User-controlled input passed to exec() allows arbitrary command execution on the host.",
        "fix": "Use ProcessBuilder with a String[] argument list so the OS does not interpret shell metacharacters. Validate and whitelist all inputs.",
        "cwe": "CWE-78",
        "owasp": "A03:2021 – Injection",
    },
    "SEC016": {
        "title": "Java Deserialization — ObjectInputStream",
        "what": "Java's ObjectInputStream.readObject() deserialises arbitrary bytes into live objects.",
        "impact": "Attackers can craft malicious serialised payloads (gadget chains) that execute arbitrary code during deserialisation — a well-known RCE vector.",
        "fix": "Avoid Java serialisation for untrusted data. Use JSON, Protobuf, or other safe formats. If serialisation is necessary, use look-ahead ObjectInputStream filtering (JEP 290).",
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
    "SEC017": {
        "title": "Stack Trace Exposed",
        "what": "e.printStackTrace() prints full Java stack traces to standard output or standard error.",
        "impact": "In production, this information reaches application logs or HTTP responses, revealing internal class names, file paths, and library versions.",
        "fix": "Use a logging framework (SLF4J/Logback) and log at ERROR level with a structured message. Never print stack traces to HTTP responses.",
        "cwe": "CWE-209",
        "owasp": "A09:2021 – Security Logging and Monitoring Failures",
    },
    "SEC024": {
        "title": "Unicode Normalisation / IDN Injection Risk",
        "what": "Unicode normalisation (NFC/NFD/NFKC/NFKD) is applied to user input, which can change the byte representation of strings.",
        "impact": "Security checks performed before normalisation may be bypassed after normalisation changes the string (e.g., path traversal sequences, special characters). Also relevant to IDN homograph attacks.",
        "fix": "Normalise input as early as possible and perform all security checks on the normalised form. Avoid normalising data that has already been validated.",
        "cwe": "CWE-176",
        "owasp": "A03:2021 – Injection",
    },
    "SEC025": {
        "title": "IDN / Punycode Encoding Risk",
        "what": "Punycode or IDNA encoding/decoding is applied to user-controlled domain names.",
        "impact": "Homograph attacks use visually identical Unicode characters from different scripts to spoof legitimate domains (e.g., аpple.com vs apple.com). Processing without validation enables phishing and SSRF.",
        "fix": "Validate domain names against an allowlist or use a well-tested IDNA library. Display decoded (Unicode) labels to users only after confirming the canonical form is safe.",
        "cwe": "CWE-176",
        "owasp": "A03:2021 – Injection",
    },
    "SEC026": {
        "title": "Server-Side Template Injection (SSTI)",
        "what": "User-controlled data is passed to a template engine's compile or render function, or triple-brace Handlebars syntax is used.",
        "impact": "Template engines can evaluate arbitrary expressions. An attacker can read server files, environment variables, and often achieve full Remote Code Execution.",
        "fix": "Never render user input as a template. Pass user data as template variables (context), not as the template string itself. Use sandboxed environments if dynamic templates are unavoidable.",
        "cwe": "CWE-94",
        "owasp": "A03:2021 – Injection",
    },
    "SEC027": {
        "title": "Path Traversal",
        "what": "Directory traversal sequences (../../) appear in file paths, or os.path.join() is called with an absolute path as a subsequent argument (which discards the base directory).",
        "impact": "Attackers can escape the intended directory and read or write arbitrary files on the server, including /etc/passwd, private keys, or application source.",
        "fix": "Resolve the full canonical path with os.path.realpath() and verify it starts with the expected base directory before opening. Use os.path.join() carefully — subsequent absolute components replace earlier ones.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC028": {
        "title": "Weak Content Security Policy",
        "what": "The Content-Security-Policy header is set with unsafe-inline or unsafe-eval directives.",
        "impact": "These directives defeat the primary purpose of CSP and allow inline scripts/styles and eval() to run, negating XSS protection.",
        "fix": "Remove unsafe-inline and unsafe-eval. Use nonces or hashes for inline scripts. Evaluate a strict CSP using the CSP Evaluator tool.",
        "cwe": "CWE-693",
        "owasp": "A05:2021 – Security Misconfiguration",
    },
    "SEC029": {
        "title": "PHP Unsafe Unserialise",
        "what": "unserialize() is called, potentially on untrusted data, without restricting allowed classes.",
        "impact": "PHP gadget chains in commonly installed libraries (Laravel, Symfony, Guzzle) allow attackers to achieve RCE by supplying a crafted serialised string.",
        "fix": "Avoid unserialize() on untrusted data. Use JSON. If you must deserialise, pass ['allowed_classes' => false] or a whitelist of safe class names.",
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
    "SEC030": {
        "title": "PHP Magic Method Abuse (Deserialisation Gadget)",
        "what": "PHP magic methods (__sleep, __wakeup, __unserialize, __destruct, __toString) are defined, which can be exploited as gadget chain links.",
        "impact": "Classes with dangerous magic methods become gadget chain components that attackers can exploit during deserialisation to execute arbitrary code.",
        "fix": "Audit magic methods for dangerous operations (file writes, system calls, eval). Avoid unserialise() with untrusted data to prevent gadget chain exploitation.",
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
    "SEC031": {
        "title": "PHP Phar Deserialisation",
        "what": "Phar:// stream wrappers or Phar:: class usage can trigger PHP object deserialisation through file-system functions.",
        "impact": "Supplying a crafted Phar archive as input to functions like file_exists(), fopen(), or include() triggers deserialisation, enabling RCE without a direct unserialize() call.",
        "fix": "Disable phar:// in php.ini if unused (phar.readonly = On). Validate file paths before passing to file functions. Avoid user-controlled stream wrappers.",
        "cwe": "CWE-502",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
    },
    "SEC032": {
        "title": "PHP Autoload Injection",
        "what": "spl_autoload_register() or __autoload() is used to load class files dynamically.",
        "impact": "If the class name is derived from user input, attackers can load arbitrary PHP files from the server, executing their contents.",
        "fix": "Never derive autoload paths directly from user input. Use a PSR-4 compliant autoloader (Composer) with a fixed class-to-path mapping.",
        "cwe": "CWE-98",
        "owasp": "A03:2021 – Injection",
    },
    "SEC033": {
        "title": "Unrestricted File Upload",
        "what": "File upload handling is detected. Without proper validation, arbitrary files can be uploaded.",
        "impact": "Uploading a PHP/JSP/ASPX webshell allows the attacker to execute commands on the server. Uploading malicious files can also affect other users.",
        "fix": "Validate the file type by magic bytes (not just extension or MIME header). Store uploads outside the web root. Serve them through a controller, never execute them. Rename files on disk.",
        "cwe": "CWE-434",
        "owasp": "A04:2021 – Insecure Design",
    },
    "SEC034": {
        "title": "Insufficient File Type Validation",
        "what": "File type is checked using extension, MIME type, or content-type header — all of which can be spoofed by an attacker.",
        "impact": "Attackers can upload malicious files disguised as benign ones by manipulating the extension or MIME header.",
        "fix": "Validate file type by inspecting the file's magic bytes (e.g., using python-magic or fileinfo). Combine with server-side extension whitelisting.",
        "cwe": "CWE-434",
        "owasp": "A04:2021 – Insecure Design",
    },
    "SEC035": {
        "title": "Local File Inclusion (LFI) / Path Injection",
        "what": "User-controlled input is used directly in a file open, read, include, or require call.",
        "impact": "Attackers can read arbitrary server files (source code, /etc/passwd, private keys) or, in some setups, include remote code for RCE.",
        "fix": "Never pass user input directly to file functions. Use an allowlist of permitted file identifiers mapped to real paths server-side.",
        "cwe": "CWE-73",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC036": {
        "title": "PHP Remote File Inclusion (RFI) via Stream Wrappers",
        "what": "Dangerous PHP stream wrappers (php://filter, php://input, data://, zip://, phar://) are used or referenced.",
        "impact": "php://input and data:// can inject arbitrary PHP code. php://filter can leak source code. zip:// and phar:// can trigger deserialisation.",
        "fix": "Disable dangerous wrappers in php.ini (allow_url_include = Off, allow_url_fopen = Off). Validate file paths against an allowlist.",
        "cwe": "CWE-98",
        "owasp": "A03:2021 – Injection",
    },
    "SEC037": {
        "title": "Sensitive File Reference",
        "what": "Paths to sensitive system files (/etc/passwd, /etc/shadow, ~/.ssh/id_rsa, /proc/self/environ) appear in the code.",
        "impact": "If these paths reach a file-reading function with user-controlled input, attackers can exfiltrate credentials, private keys, or environment variables.",
        "fix": "Remove hardcoded sensitive paths. Ensure file-reading functions never receive user-controlled input without strict allowlist validation.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC038": {
        "title": "URL-Encoded Path Traversal",
        "what": "URL-encoded or double-encoded traversal sequences (%2e%2e%2f, %252e, %c0%ae) appear in the code or input handling.",
        "impact": "Web servers or application code that decode URLs may be bypassed by encoding traversal sequences, allowing access to files outside the intended directory.",
        "fix": "Decode and normalise paths before applying security checks. Use os.path.realpath() / realpath() and verify the canonical path starts with the expected base directory.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC039": {
        "title": "Null Byte Injection",
        "what": "Null bytes (%00) appear near file or path operations.",
        "impact": "In languages that pass strings to C library functions, a null byte terminates the string, truncating extensions or validation checks (e.g., file.php%00.jpg passes an extension check but is executed as PHP).",
        "fix": "Strip or reject null bytes from user input. Modern PHP (≥5.3.4) mitigates this for open(), but other languages and custom C extensions may still be vulnerable.",
        "cwe": "CWE-626",
        "owasp": "A03:2021 – Injection",
    },
    "SEC040": {
        "title": "Path Traversal Filter Bypass",
        "what": "A str_replace() call tries to remove traversal sequences from a path, which is an insufficient defence.",
        "impact": "Simple string-replacement filters can be bypassed with techniques like ....// (which becomes ../ after ../ is removed once) or URL encoding.",
        "fix": "Do not rely on blacklist filtering for path traversal. Use os.path.realpath() to canonicalise the path and verify it falls within the expected base directory.",
        "cwe": "CWE-22",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC041": {
        "title": "Log File Inclusion (LFI via Logs)",
        "what": "An include or file-read function references web server log files (/var/log/, access.log) or session files.",
        "impact": "If an attacker can inject PHP code into log files (e.g., via the User-Agent header), including those logs executes the injected code (log poisoning RCE).",
        "fix": "Never include or execute log or session files. If log analysis is needed, read and parse them as plain text — never pass their path to include/require.",
        "cwe": "CWE-98",
        "owasp": "A03:2021 – Injection",
    },
    "SEC042": {
        "title": "/proc Filesystem Access",
        "what": "The Linux /proc pseudo-filesystem is accessed in code, exposing process memory maps, environment variables, or open file descriptors.",
        "impact": "Reading /proc/self/environ leaks all environment variables (including secrets). /proc/self/maps reveals memory layout useful for exploit development.",
        "fix": "Remove /proc references from application code. Ensure user-controlled input cannot reach file-reading functions that could be directed at /proc.",
        "cwe": "CWE-200",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC043": {
        "title": "JWT — 'none' Algorithm Accepted",
        "what": "The JWT library is configured to accept the 'none' algorithm, which means tokens require no signature.",
        "impact": "Attackers can forge arbitrary JWT payloads with algorithm=none and no signature, completely bypassing authentication.",
        "fix": "Explicitly specify an allowed algorithm list that excludes 'none'. Never accept algorithm from the token header without verifying it matches an expected value.",
        "cwe": "CWE-347",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC044": {
        "title": "JWT Signature Verification Disabled",
        "what": "JWT decode is called with verify=False, verify_signature: False, or similar options that skip cryptographic verification.",
        "impact": "Tokens are accepted without checking their signature, allowing any attacker to forge a token with arbitrary claims (including admin roles).",
        "fix": "Always verify JWT signatures. Remove verify=False. Ensure the secret or public key used for verification is correct and kept confidential.",
        "cwe": "CWE-347",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC046": {
        "title": "JWT Weak Signing Secret",
        "what": "A JWT is signed with a secret that is 20 characters or fewer — likely a placeholder or weak value.",
        "impact": "Short secrets can be brute-forced offline once an attacker captures a valid token, granting the ability to forge tokens for any user.",
        "fix": "Use a cryptographically random secret of at least 256 bits (32 bytes). Generate it with secrets.token_bytes(32) and load it from a secrets manager, not source code.",
        "cwe": "CWE-326",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC048": {
        "title": "JWT kid Header Injection",
        "what": "The kid (key ID) field from the JWT header is used in a file include, database query, or system call.",
        "impact": "An attacker can set kid to a path (/dev/null, a known file) or SQL fragment to manipulate which key is loaded, potentially forging tokens or achieving SQL/command injection.",
        "fix": "Validate the kid value against a strict whitelist of known key identifiers. Never use kid directly in file paths, SQL queries, or shell commands.",
        "cwe": "CWE-74",
        "owasp": "A03:2021 – Injection",
    },
    "SEC049": {
        "title": "JWT Header Parameter Injection (kid / jku / x5u)",
        "what": "The JWT header parameters kid, jku, or x5u are read from the token without strict validation.",
        "impact": "jku and x5u point to URLs from which the verifier fetches the key — an attacker can point these to their own server and have the verifier accept a token signed with the attacker's key.",
        "fix": "Ignore jku/x5u entirely, or validate them against a strict allowlist of trusted URLs. Validate kid against known key identifiers only.",
        "cwe": "CWE-347",
        "owasp": "A02:2021 – Cryptographic Failures",
    },
    "SEC050": {
        "title": "JWT Expiration Check Disabled",
        "what": "ignoreExpiration: true is set in JWT verification options, meaning expired tokens are accepted.",
        "impact": "Tokens that should have expired continue to be valid indefinitely, extending the window for stolen token abuse.",
        "fix": "Remove ignoreExpiration: true. Ensure tokens have a short, appropriate exp claim (e.g., 15 minutes for access tokens).",
        "cwe": "CWE-613",
        "owasp": "A07:2021 – Identification and Authentication Failures",
    },
    "SEC051": {
        "title": "LDAP Injection — Search",
        "what": "User-controlled input is passed directly to an LDAP search function without escaping.",
        "impact": "Attackers can modify the LDAP filter to bypass authentication, enumerate directory entries, or extract sensitive attributes from the directory.",
        "fix": "Escape all user input using ldap_escape() (PHP) or an equivalent library function before embedding it in LDAP filters. Use a strict attribute allowlist.",
        "cwe": "CWE-90",
        "owasp": "A03:2021 – Injection",
    },
    "SEC052": {
        "title": "LDAP Injection — Bind",
        "what": "User-controlled input is passed directly to an LDAP bind function.",
        "impact": "Attackers may be able to manipulate the DN used for binding, potentially authenticating as a different user or causing errors that reveal directory structure.",
        "fix": "Construct bind DNs from server-side templates with user input only in the value position, properly escaped. Never allow user input to control the DN structure.",
        "cwe": "CWE-90",
        "owasp": "A03:2021 – Injection",
    },
    "SEC053": {
        "title": "LDAP Filter Injection",
        "what": "User input is concatenated into an LDAP filter string, potentially altering its structure.",
        "impact": "Attackers can inject filter operators (&, |, *) to bypass authentication (e.g., )(uid=*)( always matches) or extract arbitrary directory attributes.",
        "fix": "Use parameterised LDAP queries or a library that provides proper escaping for LDAP special characters: ( ) * \\ NUL.",
        "cwe": "CWE-90",
        "owasp": "A03:2021 – Injection",
    },
    "SEC054": {
        "title": "MongoDB $where / NoSQL Injection",
        "what": "The MongoDB $where operator evaluates a JavaScript expression, or user input is used in a query without sanitisation.",
        "impact": "Attackers can inject JavaScript into $where expressions for arbitrary query manipulation, authentication bypass, or data extraction.",
        "fix": "Avoid $where. Use MongoDB's standard query operators with explicit field names and type-validated values. Use a schema validation layer (e.g., Mongoose with strict schemas).",
        "cwe": "CWE-943",
        "owasp": "A03:2021 – Injection",
    },
    "SEC056": {
        "title": "Open Redirect",
        "what": "A redirect target URL is derived from user-controlled input (query parameter, form field) without validation.",
        "impact": "Attackers craft links that appear to point to a trusted domain but redirect users to a malicious site, enabling phishing and credential theft.",
        "fix": "Use a server-side allowlist of permitted redirect destinations. Never reflect a URL from user input directly into a Location header.",
        "cwe": "CWE-601",
        "owasp": "A01:2021 – Broken Access Control",
    },
    "SEC057": {
        "title": "GraphQL Injection",
        "what": "User-controlled input is incorporated into GraphQL queries or operations without sanitisation.",
        "impact": "Attackers can manipulate query structure to access unauthorised data, bypass field-level access controls, or cause denial of service via deeply nested queries.",
        "fix": "Use parameterised GraphQL variables — never string-interpolate user input into query documents. Implement query depth limiting, cost analysis, and field-level authorisation.",
        "cwe": "CWE-89",
        "owasp": "A03:2021 – Injection",
    },
}


@app.context_processor
def inject_rule_meta():
    return {"RULE_META": RULE_META}


def _ingest_report(
    name: str,
    source: str,
    payload: dict,
    parent_id: int | None = None,
    zip_filename: str | None = None,
) -> int:
    """Persist a scanner JSON report to the DB; return the new report id."""
    findings = payload.get("findings", []) or []
    by_lang = payload.get("by_language") or dict(
        Counter(f.get("language", "?") for f in findings)
    )
    sev = Counter(f.get("severity", "").upper() for f in findings)

    with Session() as s:
        r = Report(
            name=name,
            source=source,
            uploaded_at=datetime.now(timezone.utc),
            total=len(findings),
            high=sev.get("HIGH", 0),
            medium=sev.get("MEDIUM", 0),
            low=sev.get("LOW", 0),
            by_language=json.dumps(by_lang),
            parent_id=parent_id,
            zip_filename=zip_filename,
        )
        s.add(r)
        s.flush()
        s.add_all([
            Finding(
                report_id=r.id,
                file=f.get("file", ""),
                line=int(f.get("line", 0) or 0),
                severity=f.get("severity", "").upper(),
                rule_id=f.get("rule_id", ""),
                language=f.get("language", ""),
                message=f.get("message", ""),
                code_snippet=f.get("code_snippet", ""),
            )
            for f in findings
        ])
        s.commit()
        return r.id


def _safe_extract(zip_path: Path, dest: Path) -> None:
    """Extract a zip into dest, rejecting any entry that escapes dest."""
    with zipfile.ZipFile(zip_path) as z:
        base = dest.resolve()
        for member in z.namelist():
            if member.startswith("/") or ".." in Path(member).parts:
                raise ValueError(f"Unsafe entry: {member}")
            target = (dest / member).resolve()
            if base != target and base not in target.parents:
                raise ValueError(f"Unsafe entry: {member}")
        z.extractall(dest)


def _validate_repo_url(url: str) -> tuple[str, str]:
    """Validate a public git URL and return (normalized_url, friendly_name)."""
    url = url.strip()
    if not url:
        raise ValueError("Repository URL is required.")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Only https:// URLs are allowed.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_GIT_HOSTS:
        allowed = ", ".join(sorted(ALLOWED_GIT_HOSTS))
        raise ValueError(f"Host '{host}' not allowed. Use one of: {allowed}.")
    # Strip a trailing .git for naming, but pass the original to git.
    path = parsed.path.rstrip("/")
    if not path or path.count("/") < 2:
        # path like "/owner/repo" → 2 slashes; "/owner" → 1 slash; "" → 0
        # require at least owner/repo
        if path.count("/") < 2 and path.count("/") != 2:
            # accept exactly /owner/repo too — re-evaluate
            pass
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        raise ValueError("URL must point to a repository, e.g. https://github.com/owner/repo")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    friendly = f"{owner}/{repo}"
    # Reconstruct a clean URL — discards anything past /owner/repo (tree paths, etc.)
    clean_url = f"https://{host}/{owner}/{repo}.git"
    return clean_url, friendly


def _clone_repo(url: str, dest: Path, ref: str | None = None) -> None:
    """Shallow-clone a repo into dest. Raises RuntimeError on failure."""
    cmd = [
        "git", "clone",
        "--depth", "1",
        "--no-tags",
        "--single-branch",
    ]
    if ref:
        cmd += ["--branch", ref]
    cmd += [url, str(dest)]
    env = {
        "GIT_TERMINAL_PROMPT": "0",  # never prompt for credentials
        "GIT_LFS_SKIP_SMUDGE": "1",  # skip LFS payloads
        "PATH": "/usr/bin:/bin:/usr/local/bin",
    }
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=CLONE_TIMEOUT_SECONDS, env=env,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Clone timed out after {CLONE_TIMEOUT_SECONDS}s.")
    if proc.returncode != 0:
        # Surface git's error but trim it to one line.
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        msg = err[-1] if err else "git clone failed"
        raise RuntimeError(f"Clone failed: {msg}")


def _scan_repo(
    url: str,
    name: str,
    source: str,
    ref: str | None = None,
    parent_id: int | None = None,
) -> int:
    """Clone a public repo, scan it, ingest a report. Returns the new id."""
    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "repo"
        _clone_repo(url, clone_dir, ref=ref)
        # Strip .git so the scanner doesn't waste time inside it.
        git_dir = clone_dir / ".git"
        if git_dir.exists():
            shutil.rmtree(git_dir, ignore_errors=True)
        payload = _run_scanner_on_dir(clone_dir)
    rid = _ingest_report(name=name, source=source, payload=payload)
    with Session() as s:
        r = s.get(Report, rid)
        if r is not None:
            r.repo_url = url
            r.repo_ref = ref
            r.parent_id = parent_id
            s.commit()
    return rid


def _scan_zip(
    zip_path: Path, name: str, source: str, parent_id: int | None = None
) -> int:
    """Extract zip → run scanner → ingest report → persist zip; return new id."""
    with tempfile.TemporaryDirectory() as tmp:
        extract = Path(tmp) / "src"
        extract.mkdir()
        _safe_extract(zip_path, extract)
        payload = _run_scanner_on_dir(extract)
    rid = _ingest_report(name=name, source=source, payload=payload)
    # Persist the zip under the report id so future re-scans can use it.
    stored = UPLOAD_DIR / f"{rid}.zip"
    shutil.copyfile(zip_path, stored)
    with Session() as s:
        r = s.get(Report, rid)
        if r is not None:
            r.zip_filename = stored.name
            r.parent_id = parent_id
            s.commit()
    return rid


def _run_scanner_on_dir(target: Path) -> dict:
    out = target / "_report.json"
    cmd = [sys.executable, str(SCANNER), "--path", str(target), "--output", str(out)]
    # Scanner exits 1 when HIGH findings exist — that's a successful scan, not an error.
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not out.exists():
        raise RuntimeError(
            f"scanner produced no report\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return json.loads(out.read_text())


def _get_report_or_404(report_id: int):
    with Session() as s:
        r = s.get(Report, report_id)
        if r is None:
            abort(404)
        # Detach so we can use it after session closes
        s.expunge(r)
        return r


def _findings_for(report_id: int, **filters) -> list[Finding]:
    with Session() as s:
        q = s.query(Finding).filter_by(report_id=report_id)
        for k, v in filters.items():
            if v:
                q = q.filter(getattr(Finding, k) == v)
        rows = q.all()
        for f in rows:
            s.expunge(f)
        return rows


# ─────────────────────────── routes ──────────────────────────────────────────

@app.get("/login")
def login_page():
    if g.current_user:
        return redirect(url_for("index"))
    return render_template("login.html", next_url=request.args.get("next", ""), error=None)


@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    with Session() as s:
        u = s.query(User).filter_by(username=username).first()
        if u and check_password_hash(u.password_hash, password):
            s.expunge(u)
            session.clear()
            session["user_id"] = u.id
            next_url = request.form.get("next") or ""
            if next_url.startswith("/") and not next_url.startswith("//"):
                return redirect(next_url)
            return redirect(url_for("index"))
    next_url = request.form.get("next") or ""
    return render_template("login.html", error="Invalid username or password.", next_url=next_url)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.get("/")
@login_required
def index():
    with Session() as s:
        recent = s.query(Report).order_by(Report.uploaded_at.desc()).limit(10).all()
        for r in recent:
            s.expunge(r)
    return render_template("index.html", recent=recent)


@app.post("/upload")
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file selected.")
        return redirect(url_for("index"))

    name = f.filename
    suffix = Path(name).suffix.lower()

    try:
        if suffix == ".json":
            payload = json.loads(f.read().decode("utf-8"))
            rid = _ingest_report(name=name, source="json", payload=payload)
        elif suffix == ".zip":
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = Path(tmp) / "src.zip"
                f.save(zip_path)
                rid = _scan_zip(zip_path, name=name, source="scan")
        else:
            flash("Unsupported file type. Upload a scanner .json report or a .zip of source code.")
            return redirect(url_for("index"))
    except Exception as e:
        flash(f"Upload failed: {e}")
        return redirect(url_for("index"))

    return redirect(url_for("report", report_id=rid))


@app.post("/upload-url")
@login_required
def upload_url():
    raw_url = (request.form.get("repo_url") or "").strip()
    ref = (request.form.get("ref") or "").strip() or None
    try:
        clean_url, friendly = _validate_repo_url(raw_url)
        rid = _scan_repo(clean_url, name=friendly, source="github", ref=ref)
    except (ValueError, RuntimeError) as e:
        flash(str(e))
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Repo scan failed: {e}")
        return redirect(url_for("index"))
    return redirect(url_for("report", report_id=rid))


@app.get("/reports")
@login_required
def reports():
    with Session() as s:
        rows = s.query(Report).order_by(Report.uploaded_at.desc()).all()
        for r in rows:
            s.expunge(r)
    return render_template("reports.html", reports=rows)


@app.post("/reports/<int:report_id>/delete")
@admin_required
def delete_report(report_id: int):
    with Session() as s:
        r = s.get(Report, report_id)
        if r is not None:
            zip_name = r.zip_filename
            s.delete(r)
            s.commit()
            if zip_name:
                stored = UPLOAD_DIR / zip_name
                if stored.exists():
                    stored.unlink()
    return redirect(url_for("reports"))


@app.post("/report/<int:report_id>/rescan")
@login_required
def rescan(report_id: int):
    r = _get_report_or_404(report_id)
    # Chain rescans back to the original root, not to the previous rescan.
    root_id = r.parent_id or r.id
    try:
        if r.repo_url:
            new_id = _scan_repo(
                r.repo_url, name=r.name, source="rescan",
                ref=r.repo_ref, parent_id=root_id,
            )
        elif r.zip_filename and (UPLOAD_DIR / r.zip_filename).exists():
            new_id = _scan_zip(
                UPLOAD_DIR / r.zip_filename, name=r.name,
                source="rescan", parent_id=root_id,
            )
        else:
            flash("Re-scan unavailable: no stored source archive or repo URL.")
            return redirect(url_for("report", report_id=report_id))
    except (RuntimeError, ValueError) as e:
        flash(f"Re-scan failed: {e}")
        return redirect(url_for("report", report_id=report_id))
    except Exception as e:
        flash(f"Re-scan failed: {e}")
        return redirect(url_for("report", report_id=report_id))
    return redirect(url_for("report", report_id=new_id))


@app.get("/report/<int:report_id>")
@login_required
def report(report_id: int):
    r = _get_report_or_404(report_id)
    findings = _findings_for(report_id)

    by_rule = Counter(f.rule_id for f in findings).most_common(10)
    by_file = Counter(f.file for f in findings).most_common(10)
    by_lang = json.loads(r.by_language or "{}")

    # Build the rescan lineage: the root report and every rescan linked to it.
    lineage = []
    with Session() as s:
        root_id = r.parent_id or r.id
        root = s.get(Report, root_id)
        if root is not None:
            chain = [root] + list(
                s.query(Report)
                .filter(Report.parent_id == root_id)
                .order_by(Report.uploaded_at.asc())
                .all()
            )
            for x in chain:
                s.expunge(x)
            lineage = chain

    can_rescan = bool(r.repo_url) or bool(
        r.zip_filename and (UPLOAD_DIR / r.zip_filename).exists()
    )

    return render_template(
        "report.html",
        r=r,
        lineage=lineage,
        can_rescan=can_rescan,
        by_rule=by_rule,
        by_file=by_file,
        by_lang=by_lang,
    )


@app.get("/report/<int:report_id>/findings")
@login_required
def findings(report_id: int):
    r = _get_report_or_404(report_id)
    severity = request.args.get("severity") or ""
    language = request.args.get("language") or ""
    rule_id = request.args.get("rule_id") or ""
    q = (request.args.get("q") or "").strip().lower()

    all_rows = _findings_for(report_id)
    languages = sorted({f.language for f in all_rows})
    rule_ids = sorted({f.rule_id for f in all_rows})

    sev_filter = severity.upper() if severity else None
    rows = [
        f for f in all_rows
        if (not sev_filter or f.severity == sev_filter)
        and (not language or f.language == language)
        and (not rule_id or f.rule_id == rule_id)
    ]
    if q:
        rows = [
            f for f in rows
            if q in f.file.lower()
            or q in f.message.lower()
            or q in f.code_snippet.lower()
        ]
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    return render_template(
        "findings.html",
        r=r,
        rows=rows,
        languages=languages,
        rule_ids=rule_ids,
        active={"severity": severity, "language": language, "rule_id": rule_id, "q": q},
    )


@app.get("/report/<int:report_id>/rule/<rule_id>")
@login_required
def rule(report_id: int, rule_id: str):
    r = _get_report_or_404(report_id)
    rows = _findings_for(report_id, rule_id=rule_id)
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))
    if not rows:
        abort(404)
    return render_template("rule.html", r=r, rule_id=rule_id, rows=rows)


# ─────────────────────────── filters ─────────────────────────────────────────

@app.template_filter("relpath")
def _relpath(path: str) -> str:
    """Show paths relative to the project root when possible."""
    try:
        return str(Path(path).relative_to(PROJECT_ROOT))
    except (ValueError, TypeError):
        return path


@app.template_filter("ago")
def _ago(dt: datetime) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    s = int(delta.total_seconds())
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60}m ago"
    if s < 86400:
        return f"{s // 3600}h ago"
    return f"{s // 86400}d ago"


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
