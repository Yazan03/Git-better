#!/usr/bin/env python3
"""
Multi-language vulnerability scanner.
Supports: Python, JavaScript/TypeScript, PHP, Java, Go, Bash
"""
import ast
import re
import json
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
}


RULES = {
    "python": [
        ("SEC001", "HIGH",   r'(-i)(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
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
        ("SEC005", "MEDIUM", r'\bhashlib\.md5\b|\bhashlib\.sha1\b',
                             "Weak hashing algorithm (MD5/SHA1)"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|http-equiv\s*=\s*["\"]Content-Security-Policy["\"][^>]*',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC026", "HIGH",   r'\b(jinja2\.Template|render_template_string|Template\(|\{\{[^}]+\}\})\b',
                             "Possible server-side template injection risk"),
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
        ("SEC024", "MEDIUM", r'\bunicodedata\.normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\b(idna\.(encode|decode)|encodings\.idna)\b',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),


    ],

    "javascript": [
        ("SEC001", "HIGH",   r'(-i)(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC006", "HIGH",   r'innerHTML\s*=',                "XSS risk via innerHTML assignment"),
        ("SEC026", "HIGH",   r'\b(Handlebars|Mustache)\.compile\s*\(|\b_\.template\s*\(|\bng-bind-html\b|\$sce\.trustAsHtml\s*\(|\bv-html\s*=|\{\{\{[^}]+\}\}\}',
                             "Client-side template injection risk"),
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
        ("SEC026", "HIGH",   r'\b(Handlebars|Mustache)\.compile\s*\(|\b_\.template\s*\(|\bng-bind-html\b|\$sce\.trustAsHtml\s*\(|\bv-html\s*=|\{\{\{[^}]+\}\}\}',
                             "Client-side template injection risk"),
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
        ("SEC004", "HIGH",   r'(query|sql)\s*[=+]\s*[`"\'].*\$\{', "Possible SQL injection via template literal"),
        ("SEC008", "MEDIUM", r'Math\.random\s*\(',            "Math.random() is not cryptographically secure"),
        ("SEC009", "MEDIUM", r'(http|ws)://',                 "Insecure protocol (use https/wss)"),
        ("SEC010", "LOW",    r'console\.(log|debug|info)\s*\(', "Debug logging left in code"),
        ("SEC024", "MEDIUM", r'\.normalize\s*\(\s*["\']-(NFC|NFD|NFKC|NFKD)-',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bpunycode\.(toASCII|toUnicode)\s*\(|\b(domainToASCII|domainToUnicode)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),


    ],

    "php": [
        ("SEC001", "HIGH",   r'(-i)(password|api_key|secret)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC011", "HIGH",   r'\$_(GET|POST|REQUEST|COOKIE)\[', "Unsanitised user input"),
        ("SEC012", "HIGH",   r'\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(',
                             "Shell execution function — injection risk"),
        ("SEC004", "HIGH",   r'mysql_query\s*\(.*\$',        "Possible SQL injection"),
        ("SEC013", "HIGH",   r'\bmd5\s*\(|\bsha1\s*\(',      "Weak hashing (MD5/SHA1)"),
        ("SEC028", "HIGH",   r'Content-Security-Policy.*(unsafe-inline|unsafe-eval)|header\s*\(\s*["\"]Content-Security-Policy["\"]|http-equiv\s*=\s*["\"]Content-Security-Policy["\"]',
                             "CSP includes unsafe directives (unsafe-inline/unsafe-eval) or insecure meta policy"),
        ("SEC033", "HIGH",   r'\b(move_uploaded_file|is_uploaded_file)\s*\(',
                             "High-risk PHP upload sink detected - require strong canonicalization/allowlist before write"),
        ("SEC033B", "LOW",   r'\b\$_FILES\b',
                             "PHP file upload data variable used - ensure strict validation of file type/size/filename"),
        ("SEC034", "MEDIUM", r'\b(pathinfo\s*\(.*PATHINFO_EXTENSION|mime_content_type\(|finfo_file\()\b',
                             "File type/extension detection is in place; ensure allowlist is used and not bypassed"),
        ("SEC026", "HIGH",   r'\b(template\(|Twig::create|\{\{[^}]+\}\})\b',
                             "Template injection risk"),
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
        ("SEC014", "MEDIUM", r'error_reporting\s*\(\s*E_ALL', "Verbose error reporting enabled"),
        ("SEC024", "MEDIUM", r'\bNormalizer::normalize\s*\(|\bnormalizer_normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bidn_to_(ascii|utf8)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),


    ],

    "java": [
        ("SEC001", "HIGH",   r'(-i)(password|apiKey|secret)\s*=\s*"[^"]{4,}"',
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
        ("SEC024", "MEDIUM", r'\bNormalizer\.normalize\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\bIDN\.(toASCII|toUnicode)\s*\(',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),


    ],

    "go": [
        ("SEC001", "HIGH",   r'(-i)(password|apiKey|secret)\s*:-=\s*"[^"]{4,}"',
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
        ("SEC034", "MEDIUM", r'\b(archive\.Zip|os\.Create|filepath\.Clean|filepath\.Abs)\b',
                             "Path sanitization call found - ensure it is applied to uploaded file destination paths"),
        ("SEC026", "HIGH",   r'\b(template\.Execute|template\.Parse|html/template|text/template)\b',
                             "Possible template injection risk"),
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
        ("SEC024", "MEDIUM", r'\bnorm\.(NFC|NFD|NFKC|NFKD)\.(String|Bytes)\s*\(',
                             "Unicode normalization on input - potential normalization/IDN injection risk"),        ("SEC025", "MEDIUM", r'\b(idna\.(ToASCII|ToUnicode)|golang\.org/x/net/idna)\b',
                             "IDN/punycode conversion - potential homograph/normalization injection risk"),


    ],

    "bash": [
        ("SEC001", "HIGH",   r'(-i)(PASSWORD|API_KEY|SECRET|TOKEN)=["\']-[^"\'$\s]{4,}',
                             "Hardcoded secret in env variable"),
        ("SEC020", "HIGH",   r'curl.*(-k|--insecure)',       "curl with SSL verification disabled"),
        ("SEC021", "HIGH",   r'eval\s+',                     "Use of eval in shell script"),
        ("SEC022", "MEDIUM", r'chmod\s+777',                 "Overly permissive file permissions"),
        ("SEC023", "MEDIUM", r'\$[A-Za-z_]+\s*without quotes', "Unquoted variable — word splitting risk"),
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
        ("SEC009", "MEDIUM", r'http://',                     "Insecure HTTP protocol"),
    ],
}



def scan_with_regex(path: Path, language: str) -> list[Finding]:
    findings = []
    rules = RULES.get(language, [])
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, severity, pattern, message in rules:
            if re.search(pattern, line, re.IGNORECASE):
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
    language = EXTENSION_MAP.get(path.suffix.lower())
    if not language:
        return []

    findings = scan_with_regex(path, language)

    if language == "python":
        ast_findings = scan_python_ast(path)
        existing_lines = {f.line for f in findings}
        findings += [f for f in ast_findings if f.line not in existing_lines]

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
