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
        ("SEC001", "HIGH",   r'(?i)(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret in variable"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC002", "HIGH",   r'\bexec\s*\(',                  "Use of exec()"),
        ("SEC002", "HIGH",   r'\bos\.system\s*\(',            "Use of os.system() — shell injection risk"),
        ("SEC002", "HIGH",   r'\bpickle\.loads\s*\(',         "Unsafe pickle deserialization"),
        ("SEC002", "MEDIUM", r'\bsubprocess\.call\s*\(',      "Subprocess usage — sanitise inputs"),
        ("SEC002", "MEDIUM", r'\bcompile\s*\(',               "Dynamic code compilation"),
        ("SEC003", "LOW",    r'\bassert\b',                   "Assert stripped with python -O"),
        ("SEC004", "HIGH",   r'(f["\']|%\s*["\']|\.format\s*\().*?(SELECT|INSERT|UPDATE|DELETE)',
                             "Possible SQL injection via string formatting"),
        ("SEC005", "MEDIUM", r'\bhashlib\.md5\b|\bhashlib\.sha1\b',
                             "Weak hashing algorithm (MD5/SHA1)"),
    ],

    "javascript": [
        ("SEC001", "HIGH",   r'(?i)(password|api_key|secret|token)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC006", "HIGH",   r'innerHTML\s*=',                "XSS risk via innerHTML assignment"),
        ("SEC006", "HIGH",   r'document\.write\s*\(',         "XSS risk via document.write()"),
        ("SEC007", "HIGH",   r'dangerouslySetInnerHTML',      "React XSS risk — dangerouslySetInnerHTML"),
        ("SEC004", "HIGH",   r'(query|sql)\s*[=+]\s*[`"\'].*\$\{', "Possible SQL injection via template literal"),
        ("SEC008", "MEDIUM", r'Math\.random\s*\(',            "Math.random() is not cryptographically secure"),
        ("SEC009", "MEDIUM", r'(http|ws)://',                 "Insecure protocol (use https/wss)"),
        ("SEC010", "LOW",    r'console\.(log|debug|info)\s*\(', "Debug logging left in code"),
    ],

    "php": [
        ("SEC001", "HIGH",   r'(?i)(password|api_key|secret)\s*=\s*["\'][^"\']{4,}["\']',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\beval\s*\(',                  "Use of eval()"),
        ("SEC011", "HIGH",   r'\$_(GET|POST|REQUEST|COOKIE)\[', "Unsanitised user input"),
        ("SEC012", "HIGH",   r'\bshell_exec\s*\(|\bsystem\s*\(|\bpassthru\s*\(',
                             "Shell execution function — injection risk"),
        ("SEC004", "HIGH",   r'mysql_query\s*\(.*\$',        "Possible SQL injection"),
        ("SEC013", "HIGH",   r'\bmd5\s*\(|\bsha1\s*\(',      "Weak hashing (MD5/SHA1)"),
        ("SEC014", "MEDIUM", r'error_reporting\s*\(\s*E_ALL', "Verbose error reporting enabled"),
    ],

    "java": [
        ("SEC001", "HIGH",   r'(?i)(password|apiKey|secret)\s*=\s*"[^"]{4,}"',
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
    ],

    "go": [
        ("SEC001", "HIGH",   r'(?i)(password|apiKey|secret)\s*:?=\s*"[^"]{4,}"',
                             "Hardcoded secret"),
        ("SEC002", "HIGH",   r'\bexec\.Command\s*\(',        "OS command execution"),
        ("SEC004", "HIGH",   r'(Query|Exec)\s*\(.*\+',       "Possible SQL injection via concatenation"),
        ("SEC009", "MEDIUM", r'"http://',                    "Insecure HTTP protocol"),
        ("SEC018", "MEDIUM", r'math/rand',                   "math/rand is not cryptographically secure — use crypto/rand"),
        ("SEC019", "LOW",    r'fmt\.Println\s*\(',           "Debug print statement"),
    ],

    "bash": [
        ("SEC001", "HIGH",   r'(?i)(PASSWORD|API_KEY|SECRET|TOKEN)=["\']?[^"\'$\s]{4,}',
                             "Hardcoded secret in env variable"),
        ("SEC020", "HIGH",   r'curl.*(-k|--insecure)',       "curl with SSL verification disabled"),
        ("SEC021", "HIGH",   r'eval\s+',                     "Use of eval in shell script"),
        ("SEC022", "MEDIUM", r'chmod\s+777',                 "Overly permissive file permissions"),
        ("SEC023", "MEDIUM", r'\$[A-Za-z_]+\s*without quotes', "Unquoted variable — word splitting risk"),
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