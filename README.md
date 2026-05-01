# Git Better: A DevSecOps-Based Static Code Security Scanning System

A static analysis security scanner that detects vulnerabilities across **6 programming languages**, integrated into a GitHub Actions CI pipeline alongside [Bandit](https://github.com/PyCQA/bandit) and [Safety](https://github.com/pyupio/safety).

## Supported Languages

| Language | Extensions |
|----------|------------|
| Python | `.py` |
| JavaScript / TypeScript | `.js`, `.ts`, `.jsx`, `.tsx` |
| PHP | `.php` |
| Java | `.java` |
| Go | `.go` |
| Bash | `.sh`, `.bash` |

## Detection Rules

**178 rules** across 6 languages, organized into the following categories:

### Secrets & Credentials
| Rule | Severity | Description |
|------|----------|-------------|
| SEC001 | HIGH | Hardcoded passwords, API keys, secrets, and tokens |

### Dangerous Functions & Code Execution
| Rule | Severity | Description |
|------|----------|-------------|
| SEC002 | HIGH | `eval()`, `exec()`, `os.system()`, `pickle.loads()`, `shell_exec()` |
| SEC003 | LOW | `assert` statements stripped with `python -O` |
| SEC012 | HIGH | PHP shell execution (`shell_exec`, `system`, `passthru`) |
| SEC015 | HIGH | Java `Runtime.exec()` — OS command injection |
| SEC021 | HIGH | `eval` in shell scripts |

### SQL Injection
| Rule | Severity | Description |
|------|----------|-------------|
| SEC004 | HIGH | String formatting/concatenation in SQL queries |

### Cross-Site Scripting (XSS)
| Rule | Severity | Description |
|------|----------|-------------|
| SEC006 | HIGH | `innerHTML`, `document.write()` |
| SEC007 | HIGH | React `dangerouslySetInnerHTML` |
| SEC011 | HIGH | Unsanitized PHP superglobals (`$_GET`, `$_POST`, etc.) |

### Weak Cryptography
| Rule | Severity | Description |
|------|----------|-------------|
| SEC005 | MEDIUM | MD5/SHA1 hashing |
| SEC008 | MEDIUM | `Math.random()` (not cryptographically secure) |
| SEC013 | HIGH | PHP `md5()`/`sha1()` |
| SEC018 | MEDIUM | Go `math/rand` instead of `crypto/rand` |

### Path Traversal & File Inclusion (LFI/RFI)
| Rule | Severity | Description |
|------|----------|-------------|
| SEC035 | HIGH | File operations with user-controlled input (`request.args`, `$_GET`, `req.params`, etc.) |
| SEC035B | HIGH | Framework file-serving with user input (Flask `send_file`, Express `res.sendFile`, Go `http.ServeFile`) |
| SEC035C | HIGH | PHP `file_get_contents`/`fopen`/`readfile` with superglobals; Java `RequestDispatcher` with request params |
| SEC036 | HIGH | PHP stream wrappers (`php://filter`, `php://input`, `expect://`, `data://`, `zip://`, `phar://`) |
| SEC027 | HIGH | `os.path.join()` absolute path bypass (Python); deep traversal sequences (3+ levels) |
| SEC038 | HIGH | Encoded traversal (`%2e%2e%2f`, double-encoding `%252e`, UTF-8 overlong `%c0%ae`) |
| SEC039 | HIGH | Null byte injection in file path context |
| SEC040 | MEDIUM | Naive `str_replace("../", "")` filters (bypassable with `....//` or encoding) |
| SEC041 | MEDIUM | Log file inclusion — log poisoning vector |
| SEC041B | MEDIUM | PHP session file inclusion — session poisoning |
| SEC037 | MEDIUM | References to sensitive files (`/etc/passwd`, `/etc/shadow`, `.ssh/id_rsa`, `win.ini`) |
| SEC042 | MEDIUM | `/proc` filesystem access (`/proc/self/environ`, `fd/`, `cmdline`) |

### Template Injection (SSTI/CSTI)
| Rule | Severity | Description |
|------|----------|-------------|
| SEC026 | HIGH | Server/client-side template injection (Jinja2, Handlebars, Twig, Velocity, etc.) |

### Content Security Policy (CSP)
| Rule | Severity | Description |
|------|----------|-------------|
| SEC028 | HIGH | `unsafe-inline`/`unsafe-eval` in CSP directives |

### Deserialization
| Rule | Severity | Description |
|------|----------|-------------|
| SEC016 | HIGH | Java `ObjectInputStream` deserialization |
| SEC029 | HIGH | PHP `unserialize()` without `allowed_classes` |
| SEC030 | HIGH | PHP magic methods in deserialization context |
| SEC031 | HIGH | `phar://` in deserialization/file access context |
| SEC032 | HIGH | Autoload hooks in deserialization chains |

### File Upload
| Rule | Severity | Description |
|------|----------|-------------|
| SEC033 | HIGH | Dangerous upload sinks (`move_uploaded_file`, `multer`, `FormFile`, etc.) |
| SEC034 | MEDIUM | File type/extension inspection — verify allowlist enforcement |

### JWT (JSON Web Token) Attacks
| Rule | Severity | Description |
|------|----------|-------------|
| SEC043 | HIGH | Algorithm `none` — unsigned token forgery |
| SEC044 | HIGH | Signature verification disabled (`verify=False`, `parseClaimsJwt()`, `jwt.Parse(_, nil)`, manual base64 decode) |
| SEC044B | HIGH | `verify_signature` option set to `False` |
| SEC044C | HIGH | `verify_exp` option set to `False` — expired tokens accepted |
| SEC046 | HIGH | Short hardcoded JWT secret (<=20 chars) — offline crackable via hashcat |
| SEC048 | HIGH | JWT `kid` header value flows into dangerous sink (`include`, `query`, `exec`) |
| SEC049 | MEDIUM | JWT `kid`/`jku`/`x5u` header extraction — injection surface |
| SEC050 | HIGH | `ignoreExpiration: true` — expired tokens accepted |

### LDAP Injection
| Rule | Severity | Description |
|------|----------|-------------|
| SEC051 | HIGH | LDAP search/query with user-controlled input (`request.args`, `$_GET`, `req.params`, `request.getParameter`, `r.FormValue`, `ldapsearch $VAR`) |
| SEC051B | HIGH | PHP `ldap_list`/`ldap_read` with superglobal input |
| SEC052 | HIGH | LDAP bind/auth with user input — authentication bypass risk |
| SEC053 | HIGH | LDAP filter built via string concatenation, f-strings, `Sprintf`, or template literals with attribute names (`uid`, `cn`, `sn`, `mail`, `sAMAccountName`, etc.) |
| SEC053B | HIGH | LDAP filter built via PHP string concatenation (`. $var`) |

### Unicode & IDN
| Rule | Severity | Description |
|------|----------|-------------|
| SEC024 | MEDIUM | Unicode normalization — potential normalization injection |
| SEC025 | MEDIUM | IDN/punycode conversion — homograph attack risk |

### Other
| Rule | Severity | Description |
|------|----------|-------------|
| SEC009 | MEDIUM | Insecure HTTP/WS protocol |
| SEC010 | LOW | Debug logging left in code |
| SEC014 | MEDIUM | Verbose PHP `error_reporting` |
| SEC017 | MEDIUM | Java `.printStackTrace()` — info leakage |
| SEC019 | LOW | Go `fmt.Println` debug statement |
| SEC020 | HIGH | `curl --insecure` (SSL verification disabled) |
| SEC022 | MEDIUM | `chmod 777` — overly permissive |

## How It Works

```
Source Code
    │
    ▼
┌──────────────────────┐
│   vuln_scanner.py    │  Regex rules (all 6 languages) + Python AST analysis
│   178 rules          │
└──────────┬─────────��─┘
           │
           ▼
┌──────────────────────┐
│  evaluate_results.py │  Aggregates results from Bandit + Safety + custom scanner
└──────────┬───────────┘
           │
           ▼
    CI pass / fail
```

1. **Regex scan** — Each source file is matched line-by-line against language-specific rules
2. **AST scan** — Python files get a second pass using `ast.parse()` for deeper analysis
3. **Evaluation** — Results from Bandit, Safety, and the custom scanner are combined; the build fails if any HIGH severity issues or vulnerable dependencies are found

## Usage

### Run locally

```bash
# Scan a directory
python3 scripts/vuln_scanner.py --path ./src --output report.json

# Scan a single file
python3 scripts/vuln_scanner.py --path app.py --output report.json

# Exclude directories
python3 scripts/vuln_scanner.py --path . --exclude venv node_modules dist
```

The scanner outputs a JSON report and exits with code `1` if any HIGH findings are detected.

### Output format

```json
{
  "total": 5,
  "high": 2,
  "medium": 2,
  "low": 1,
  "by_language": { "python": 3, "javascript": 2 },
  "findings": [
    {
      "file": "app.py",
      "line": 42,
      "severity": "HIGH",
      "rule_id": "SEC035",
      "language": "python",
      "message": "File operation with user-controlled input — path traversal / LFI risk",
      "code_snippet": "f = open(request.args.get('file'))"
    }
  ]
}
```

### Web dashboard

A Flask dashboard ships in `dashboard/` for browsing scan results visually:
upload an existing JSON report or a `.zip` of source code (which the dashboard
will scan for you), then explore findings with severity breakdowns, per-rule
drill-downs, filterable tables, and inline code snippets.

```bash
pip install -r dashboard/requirements.txt
python3 dashboard/app.py
# open http://127.0.0.1:5000
```

Reports are persisted in `dashboard/data/dashboard.db` (SQLite) and survive
across restarts.

### CI pipeline

The GitHub Actions workflow runs on every push and pull request:

```
Checkout → Install tools → Bandit → Safety → Custom scanner → Evaluate → Upload reports
```

> **Note:** Rename `github_workflow/` to `.github/` to activate the workflow.

```bash
mv github_workflow .github
```

## Project Structure

```
.
├── scripts/
│   ├── vuln_scanner.py        # Multi-language vulnerability scanner (178 rules)
│   └── evaluate_results.py    # Aggregates scan results, gates CI
├── github_workflow/
│   └── workflows/
│       └── secure-ci.yml      # GitHub Actions pipeline
├── test/
│   └── t.py                   # Intentionally vulnerable test file
└── requirements-dev.txt
```

---

## CI Build Webhook & Dashboard

A Node.js service in `ci-webhook/` that receives build reports from any CI pipeline via a signed webhook and displays them in a live dashboard.

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `SESSION_SECRET` | ✓ | Random string used to sign session cookies — `openssl rand -hex 32` |
| `ADMIN_USERNAME` | First run | Username for the seeded admin account |
| `ADMIN_PASSWORD` | First run | Password for the seeded admin account |
| `PORT` | | HTTP port (default `3000`) |
| `DB_PATH` | | Path to SQLite database (default `./reports.db`) |

### Quick start

```bash
cd ci-webhook
npm install
cp .env.example .env      # fill in SESSION_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD
npm start
# open http://localhost:3000/login  →  sign in as admin
# open http://localhost:3000/admin  →  copy your webhook secret
```

The first time the server starts it seeds the admin account from `ADMIN_USERNAME` / `ADMIN_PASSWORD` and prints the generated webhook secret to stdout.

### How to create users and get webhook secrets

1. Sign in at `/login` with the admin credentials.
2. Go to `/admin` → click **Invite** to create a user. The temporary password is printed to the server log.
3. The user's webhook secret is shown in the **Webhook Secret** column. Click **Copy** to copy it.
4. Click **Regen secret** to rotate a user's secret (the old secret stops working immediately).

### Wiring up the webhook

The `X-Webhook-Secret` is a per-user 64-char hex token shown in the admin panel. Copy it and store it as a CI secret — it both authenticates the request and identifies the report owner.

#### curl (manual test)

```bash
# Set YOUR_WEBHOOK_SECRET to the token from the admin panel
curl -X POST http://localhost:3000/api/reports \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Secret: $YOUR_WEBHOOK_SECRET" \
  -d '{
    "buildId":   "run-12345",
    "branch":    "main",
    "commit":    { "sha": "abc1234", "message": "chore: bump version", "author": "alice" },
    "status":    "success",
    "timestamp": "2024-04-30T12:00:00Z",
    "duration":  47000,
    "pipeline":  { "name": "GitHub Actions", "url": "https://github.com/org/repo/actions/runs/12345" },
    "testResults": { "passed": 42, "failed": 0, "skipped": 3 }
  }'
```

#### GitHub Actions

Store the webhook secret from the admin panel as `CI_WEBHOOK_SECRET` (Settings → Secrets and variables → Actions), and the server URL as `CI_WEBHOOK_URL`.

```yaml
- name: Send build report
  if: always()
  env:
    CI_WEBHOOK_SECRET: ${{ secrets.CI_WEBHOOK_SECRET }}
    CI_WEBHOOK_URL:    ${{ secrets.CI_WEBHOOK_URL }}
  run: |
    STATUS="success"
    if [ "${{ job.status }}" != "success" ]; then STATUS="failure"; fi
    curl -sf -X POST "$CI_WEBHOOK_URL/api/reports" \
      -H "Content-Type: application/json" \
      -H "X-Webhook-Secret: $CI_WEBHOOK_SECRET" \
      -d "{
        \"buildId\":   \"${{ github.run_id }}-${{ github.run_attempt }}\",
        \"branch\":    \"${{ github.ref_name }}\",
        \"commit\":    { \"sha\": \"${{ github.sha }}\", \"message\": $(echo '${{ github.event.head_commit.message }}' | jq -Rs .), \"author\": \"${{ github.actor }}\" },
        \"status\":    \"$STATUS\",
        \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"pipeline\":  { \"name\": \"${{ github.workflow }}\", \"url\": \"https://github.com/${{ github.repository }}/actions/runs/${{ github.run_id }}\" }
      }"
```

#### GitLab CI

Set `CI_WEBHOOK_SECRET` and `CI_WEBHOOK_URL` in **Settings → CI/CD → Variables**.

```yaml
send_build_report:
  stage: .post
  when: always
  script:
    - |
      STATUS="success"
      if [ "$CI_JOB_STATUS" != "success" ]; then STATUS="failure"; fi
      curl -sf -X POST "$CI_WEBHOOK_URL/api/reports" \
        -H "Content-Type: application/json" \
        -H "X-Webhook-Secret: $CI_WEBHOOK_SECRET" \
        -d "{
          \"buildId\":   \"$CI_PIPELINE_ID-$CI_JOB_ID\",
          \"branch\":    \"$CI_COMMIT_BRANCH\",
          \"commit\":    { \"sha\": \"$CI_COMMIT_SHA\", \"message\": $(echo \"$CI_COMMIT_MESSAGE\" | jq -Rs .), \"author\": \"$GITLAB_USER_LOGIN\" },
          \"status\":    \"$STATUS\",
          \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
          \"pipeline\":  { \"name\": \"$CI_PIPELINE_NAME\", \"url\": \"$CI_PIPELINE_URL\" }
        }"
```

### JSON payload reference

| Field | Type | Required | Description |
|---|---|---|---|
| `buildId` | string | ✓ | Unique identifier for this run (must be unique across all reports) |
| `branch` | string | ✓ | Git branch name |
| `commit.sha` | string | ✓ | Full or short commit SHA |
| `commit.author` | string | ✓ | Author login or name |
| `commit.message` | string | | Commit message |
| `status` | string | ✓ | `success`, `failure`, or `cancelled` |
| `timestamp` | string | ✓ | ISO-8601 build start time |
| `duration` | number | | Build duration in milliseconds |
| `pipeline.name` | string | | CI pipeline / workflow name |
| `pipeline.url` | string | | Link to the pipeline run |
| `testResults.passed` | number | | Passing test count |
| `testResults.failed` | number | | Failing test count |
| `testResults.skipped` | number | | Skipped test count |
| `artifacts` | array | | Arbitrary artifact metadata |
| `metadata` | object | | Any additional CI-specific fields |

### API endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/reports` | `X-Webhook-Secret` (per-user) | Ingest a build report |
| `GET` | `/api/reports` | Session | List reports — `?page=1&limit=20&branch=main&status=success` |
| `GET` | `/api/reports/:buildId` | Session | Fetch a single report |
| `GET` | `/api/health` | None | Uptime and report count |
| `GET` | `/dashboard` | Session | Live HTML dashboard |
| `GET` | `/admin` | Session (admin role) | User management panel |

Members see only their own reports. Admins see everything.

---

## False Positive Mitigation

The rules are designed to minimize noise:

- **User input required** — File operation rules (SEC035) only fire when a file function AND a user input source (e.g., `request.args`, `$_GET`, `req.params`) appear on the same line
- **Depth thresholds** — Directory traversal (SEC027) requires 3+ levels (`../../../`) to avoid flagging normal relative imports like `../../utils`
- **Language-aware severity** — `/etc/passwd` references are MEDIUM in web languages but LOW in bash (where they're common)
- **Specific over broad** — JWT secret rules (SEC046) only flag inline string literals under 20 characters, not variable references
- **Context-sensitive** — PHP stream wrappers (SEC036), `parseClaimsJwt()` (SEC044), and `jwt.decode()` (SEC044) are flagged because they are inherently unsafe patterns, not just suspicious keywords
