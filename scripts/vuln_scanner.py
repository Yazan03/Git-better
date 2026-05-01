#!/usr/bin/env python3
"""
Multi-language vulnerability scanner.
Supports: Python, JavaScript/TypeScript, PHP, Java, Go, Bash, C
"""
import ast
import io
import re
import json
import tokenize
import argparse
import sys
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class Finding:
    file: str
    line: int
    severity: str
    rule_id: str
    language: str
    message: str
    code_snippet: str = ""

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
}

FILENAME_MAP = {
    "makefile": "build",
    "gnumakefile": "build",
    "cmakelists.txt": "build",
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


    ],

    "javascript": [
        ("SEC001", "HIGH",   r'\b(password|api_?key|secret|token|access_?token|auth_?token)\s*[=:]\s*["\'][^"\']{4,}["\']',
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


    ],

    "php": [
        ("SEC001", "HIGH",   r'\$?(password|api_key|secret)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC011", "HIGH",   r'\$_(GET|POST|REQUEST|COOKIE)\[', "Unsanitised user input"),
        ("SEC012", "HIGH",   r'\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(',
                             "Shell execution function — injection risk"),
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


    ],

    "java": [
        ("SEC001", "HIGH",   r'\b(password|apiKey|secret)\s*=\s*"[^"]{4,}"',
                             "Hardcoded secret"),
        ("SEC004", "HIGH",   r'(createQuery|executeQuery|prepareStatement)\s*\(.*\+',
                             "Possible SQL injection via string concatenation"),
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
            # CommonJS: require('../../..')
            r"""^\s*(?:(?:const|let|var)\s+[\w{}\s,*]+\s*=\s*)?require\s*\(\s*["'](\.\.\/){2,}[^"'$`{}+]*["']\s*\)""",
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
    ],
    "javascript": [
        r'\breq(?:uest)?\.(query|body|params|headers|cookies)\b',
        r'\bprocess\.argv\b',
        r'\blocation\.(search|hash|href|pathname)\b',
        r'\bdocument\.URL\b',
        r'\bevent\.(target|data|detail)\b',
    ],
    "php": [
        r'\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b',
        r'\bgetenv\s*\(',
        r'\bphp://input\b',
    ],
    "java": [
        r'\brequest\.getParameter\s*\(',
        r'\brequest\.getHeader\s*\(',
        r'\brequest\.(getInputStream|getReader)\s*\(',
        r'\bgetQueryString\s*\(',
    ],
    "go": [
        r'\b(?:r|req)\.(FormValue|PostFormValue)\s*\(',
        r'\b(?:r|req)\.URL\.Query\(\)\.Get\s*\(',
        r'\bc\.(Param|Query|GetHeader)\s*\(',
        r'\bos\.Args\b',
    ],
    "bash": [
        r'(?<!\$)\$\{?(?:[1-9]|@|\*)\}?',   # positional args $1..$9, $@, $*
        r'\bread\s+\w+',
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
    ],
    "javascript": [
        ("SEC004T", "HIGH",
         r'\b(?:query|execute|db\.query|pool\.query|connection\.query)\s*\(',
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
    ],
    "php": [
        ("SEC004T", "HIGH",
         r'\b(?:mysql_query|mysqli_query|->query|->prepare|PDO::query)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC002T", "HIGH",
         r'\b(?:system|exec|shell_exec|passthru|popen)\s*\(',
         "Command sink — user-controlled variable flows into shell execution"),
        ("SEC035T", "HIGH",
         r'\b(?:include|require|include_once|require_once|file_get_contents|fopen)\b',
         "File-inclusion sink — user-controlled variable used as path"),
    ],
    "java": [
        ("SEC004T", "HIGH",
         r'\b(?:createQuery|executeQuery|prepareStatement|execute|executeUpdate)\s*\(',
         "SQL sink — user-controlled variable flows into query"),
        ("SEC002T", "HIGH",
         r'\bRuntime\.getRuntime\(\)\.exec\s*\(',
         "Command sink — user-controlled variable flows into exec()"),
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


def scan_taint(path: Path, language: str) -> list[Finding]:
    """
    Cross-line source-to-sink taint analysis for all supported languages.

    Algorithm
    ---------
    Pass 1 — collect every assignment of the form  ``name = <source>``  and
             record {var_name: [line_numbers]}.
    Pass 2 — for each sink call, check whether any tainted variable appears as
             an argument within WINDOW lines of the most recent source assignment.

    This catches patterns like::

        filename = request.args.get("f")   # source (line N)
        open(filename)                      # sink   (line N+3)  ← flagged

    which single-line regex rules cannot detect.
    """
    WINDOW = 25

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
                nearby = [s for s in src_lines if 0 < i - s <= WINDOW]
                if not nearby:
                    continue
                key = (i, rule_id)
                if key in reported:
                    continue
                reported.add(key)
                findings.append(Finding(
                    file=str(path),
                    line=i,
                    severity=severity,
                    rule_id=rule_id,
                    language=language,
                    message=f"{message} — tainted by user input on line {max(nearby)}",
                    code_snippet=stripped[:120],
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


def _propagate_taint(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """
    Fixed-point taint propagation within a function body.

    Repeatedly walks all assignments until the tainted-variable set stabilises.
    This handles chains like::

        x = request.args.get("q")
        y = x.strip()
        z = f"SELECT … {y}"
        cursor.execute(z)        # ← z is tainted
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
            if _is_py_source(rhs) or _uses_tainted(rhs, tainted):
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


def scan_python_ast_taint(path: Path) -> list[Finding]:
    """
    Intra-function taint analysis for Python using the AST.

    For each function/method in the file:
      1. Compute the fixed-point taint set (variables that hold user-controlled data).
      2. Walk every Call node; if any argument uses a tainted variable and the
         callee is a known dangerous sink, emit a finding.

    This catches multi-assignment taint chains that single-line regex cannot.
    """
    try:
        source = path.read_text(encoding="utf-8", errors="ignore")
        lines  = source.splitlines()
        tree   = ast.parse(source)
    except SyntaxError:
        return []

    findings: list[Finding] = []
    reported: set[tuple[int, str]] = set()

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        tainted = _propagate_taint(func)
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
                findings.append(Finding(
                    file=str(path),
                    line=node.lineno,
                    severity=severity,
                    rule_id=rule_id,
                    language="python",
                    message=message + " (AST taint analysis)",
                    code_snippet=snippet[:120],
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

            findings.append(Finding(
                file=str(path), line=i,
                severity=severity, rule_id=rule_id,
                language=language, message=message,
                code_snippet=stripped[:120],
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
            findings.append(Finding(
                file=str(path), line=node.lineno,
                severity="LOW", rule_id="SEC003",
                language="python",
                message="Assert stripped with python -O — don't use for security checks",
                code_snippet=snippet,
            ))
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def scan_file(path: Path) -> list[Finding]:
    """
    Run all scan engines for the given file and return deduplicated findings.

    Engines (in order, each de-duplicated by (line, rule_id)):
      1. scan_with_regex   — fast pattern matching with context filtering
      2. scan_python_ast   — Python AST: assert-statement detection
      3. scan_python_ast_taint — Python AST: intra-function source→sink taint
      4. scan_taint        — cross-line sliding-window taint (all languages)
    """
    language = EXTENSION_MAP.get(path.suffix.lower())
    if not language:
        language = FILENAME_MAP.get(path.name.lower())
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

    if language == "python":
        _merge(scan_python_ast(path))
        _merge(scan_python_ast_taint(path))

    _merge(scan_taint(path, language))

    return findings


def main():
    parser = argparse.ArgumentParser(description="Multi-language vulnerability scanner")
    parser.add_argument("--path",    default=".",              help="File or directory to scan")
    parser.add_argument("--output",  default="scan-report.json")
    parser.add_argument("--exclude", nargs="*",
                        default=["venv", ".venv", "node_modules", "__pycache__", "dist", "build"])
    args = parser.parse_args()

    root = Path(args.path)

    if root.is_file():
        py_files = [root] if root.suffix in EXTENSION_MAP else []
    elif root.is_dir():
        py_files = [
            f for f in root.rglob("*")
            if f.is_file()
            and f.suffix in EXTENSION_MAP
            and not any(ex in f.parts for ex in args.exclude)
        ]
    else:
        print(f"Error: {root} is not a valid file or directory")
        sys.exit(1)

    all_findings = []
    for f in py_files:
        all_findings.extend(scan_file(f))

    by_lang = {}
    for f in all_findings:
        by_lang.setdefault(f.language, []).append(f)

    report = {
        "total":    len(all_findings),
        "high":     sum(1 for f in all_findings if f.severity == "HIGH"),
        "medium":   sum(1 for f in all_findings if f.severity == "MEDIUM"),
        "low":      sum(1 for f in all_findings if f.severity == "LOW"),
        "by_language": {lang: len(findings) for lang, findings in by_lang.items()},
        "findings": [asdict(f) for f in all_findings],
    }

    Path(args.output).write_text(json.dumps(report, indent=2))
    print(f"\n{'─'*50}")
    print(f"  Scan complete — {report['total']} findings")
    print(f"  HIGH={report['high']}  MEDIUM={report['medium']}  LOW={report['low']}")
    print(f"  By language: {report['by_language']}")
    print(f"{'─'*50}\n")

    sys.exit(1 if report["high"] > 0 else 0)


if __name__ == "__main__":
    main()
