import csv
import json
import tempfile
from pathlib import Path
from passguard.reporter import AuditReport, Finding, to_json, to_csv, to_html


def test_reports_do_not_contain_plaintext_password():
    report = AuditReport(source_platform="windows")
    report.add(Finding(
        username="younes",
        source="synthetic-test",
        algorithm="NTLM",
        status="weak",
        matched_password_masked="1*******",
        salt=None,
        notes="Synthetic test only",
    ))
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        json_path = to_json(report, str(base / "audit.json"))
        csv_path = to_csv(report, str(base / "audit.csv"))
        html_path = to_html(report, str(base / "audit.html"))
        secret = "12345678"
        for path in (json_path, csv_path, html_path):
            assert secret not in Path(path).read_text(encoding="utf-8-sig")
