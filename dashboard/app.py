"""Web dashboard for the vulnerability scanner.

Run with:
    cd dashboard && python app.py
Then open http://localhost:5000.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request, url_for,
)

from models import Finding, Report, make_session

ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = ROOT.parent
SCANNER = PROJECT_ROOT / "scripts" / "vuln_scanner.py"
DATA_DIR = ROOT / "data"
UPLOAD_DIR = ROOT / "uploads"
DATA_DIR.mkdir(exist_ok=True)
UPLOAD_DIR.mkdir(exist_ok=True)

Session = make_session(str(DATA_DIR / "dashboard.db"))

app = Flask(__name__)
app.secret_key = "dev-only-not-used-for-auth"
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


# ─────────────────────────── helpers ─────────────────────────────────────────

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _ingest_report(name: str, source: str, payload: dict) -> int:
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
            uploaded_at=datetime.utcnow(),
            total=len(findings),
            high=sev.get("HIGH", 0),
            medium=sev.get("MEDIUM", 0),
            low=sev.get("LOW", 0),
            by_language=json.dumps(by_lang),
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

@app.get("/")
def index():
    with Session() as s:
        recent = s.query(Report).order_by(Report.uploaded_at.desc()).limit(10).all()
        for r in recent:
            s.expunge(r)
    return render_template("index.html", recent=recent)


@app.post("/upload")
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
                tmp_path = Path(tmp)
                zip_path = tmp_path / "src.zip"
                f.save(zip_path)
                extract = tmp_path / "src"
                extract.mkdir()
                with zipfile.ZipFile(zip_path) as z:
                    # Reject path-traversal entries
                    for member in z.namelist():
                        if member.startswith("/") or ".." in Path(member).parts:
                            flash(f"Rejected unsafe entry in archive: {member}")
                            return redirect(url_for("index"))
                    z.extractall(extract)
                payload = _run_scanner_on_dir(extract)
                rid = _ingest_report(name=name, source="scan", payload=payload)
        else:
            flash("Unsupported file type. Upload a scanner .json report or a .zip of source code.")
            return redirect(url_for("index"))
    except Exception as e:
        flash(f"Upload failed: {e}")
        return redirect(url_for("index"))

    return redirect(url_for("report", report_id=rid))


@app.get("/reports")
def reports():
    with Session() as s:
        rows = s.query(Report).order_by(Report.uploaded_at.desc()).all()
        for r in rows:
            s.expunge(r)
    return render_template("reports.html", reports=rows)


@app.post("/reports/<int:report_id>/delete")
def delete_report(report_id: int):
    with Session() as s:
        r = s.get(Report, report_id)
        if r is not None:
            s.delete(r)
            s.commit()
    return redirect(url_for("reports"))


@app.get("/report/<int:report_id>")
def report(report_id: int):
    r = _get_report_or_404(report_id)
    findings = _findings_for(report_id)

    by_rule = Counter(f.rule_id for f in findings).most_common(10)
    by_file = Counter(f.file for f in findings).most_common(10)
    by_lang = json.loads(r.by_language or "{}")

    return render_template(
        "report.html",
        r=r,
        by_rule=by_rule,
        by_file=by_file,
        by_lang=by_lang,
    )


@app.get("/report/<int:report_id>/findings")
def findings(report_id: int):
    r = _get_report_or_404(report_id)
    severity = request.args.get("severity") or ""
    language = request.args.get("language") or ""
    rule_id = request.args.get("rule_id") or ""
    q = (request.args.get("q") or "").strip().lower()

    rows = _findings_for(
        report_id,
        severity=severity.upper() if severity else None,
        language=language or None,
        rule_id=rule_id or None,
    )
    if q:
        rows = [
            f for f in rows
            if q in f.file.lower()
            or q in f.message.lower()
            or q in f.code_snippet.lower()
        ]
    rows.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    languages = sorted({f.language for f in _findings_for(report_id)})
    rule_ids = sorted({f.rule_id for f in _findings_for(report_id)})

    return render_template(
        "findings.html",
        r=r,
        rows=rows,
        languages=languages,
        rule_ids=rule_ids,
        active={"severity": severity, "language": language, "rule_id": rule_id, "q": q},
    )


@app.get("/report/<int:report_id>/rule/<rule_id>")
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
    delta = datetime.utcnow() - dt
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
