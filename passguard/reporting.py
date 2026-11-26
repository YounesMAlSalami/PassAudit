"""Safe report creation and export for completed local account audits."""
from __future__ import annotations

import csv
import html
import json
import platform
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence
from uuid import uuid4

from .password_utils import detect_linux_hash_algorithm, is_valid_nt_hash, mask_hash


@dataclass
class AccountReportResult:
    username: str
    hash_availability: str
    hash_algorithm: str
    hash_format: str
    salt_availability: str
    salt_length: int | None
    hash_preview: str
    hash_parsing_status: str
    unsupported_reason: str
    wordlist_match_status: str
    password_strength: str
    audit_result: str
    technical_notes: str
    hash_length: int | None = None
    hash_format_validation: str = "Not validated"
    hash_source: str = "Unknown"


@dataclass
class AuditReport:
    report_id: str
    audit_date: str
    operating_system: str
    audit_type: str
    total_accounts: int | None
    accounts_audited: int
    weak_passwords_found: int
    passwords_not_found_in_wordlist: int
    unsupported_hashes: int
    audit_errors: int
    audit_duration_seconds: float
    errors: list[str]
    account_results: list[AccountReportResult]

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "AuditReport":
        return cls(
            report_id=str(data["report_id"]),
            audit_date=str(data["audit_date"]),
            operating_system=str(data["operating_system"]),
            audit_type=str(data["audit_type"]),
            total_accounts=(
                int(data["total_accounts"])
                if data.get("total_accounts") is not None
                else None
            ),
            accounts_audited=int(data["accounts_audited"]),
            weak_passwords_found=int(data["weak_passwords_found"]),
            passwords_not_found_in_wordlist=int(
                data["passwords_not_found_in_wordlist"]
            ),
            unsupported_hashes=int(data["unsupported_hashes"]),
            audit_errors=int(data["audit_errors"]),
            audit_duration_seconds=float(data["audit_duration_seconds"]),
            errors=[str(item) for item in data.get("errors", [])],
            account_results=[
                AccountReportResult(**item)
                for item in data.get("account_results", [])
            ],
        )


def _system_name() -> str:
    return platform.system() or sys.platform


def _hash_details(
    raw_hash: str | None,
    operating_system: str,
) -> tuple[str, str, int | None, str, str, int | None, str]:
    if not raw_hash:
        if operating_system.lower() == "windows":
            return (
                "Unavailable",
                "Unknown (hash unavailable)",
                None,
                "Hash value unavailable; parsing not performed",
                "",
                None,
                "Unavailable",
            )
        return (
            "Unavailable",
            "Unavailable",
            None,
            "Hash unavailable",
            "",
            None,
            "Unavailable",
        )

    preview = mask_hash(raw_hash)
    if operating_system.lower() == "windows":
        length = len(raw_hash)
        if is_valid_nt_hash(raw_hash):
            return (
                "32-character hexadecimal",
                "Not applicable (NT hash is unsalted)",
                None,
                "Parsed",
                preview,
                length,
                "Valid NT hash",
            )
        return (
            "Invalid Format",
            "Unknown (invalid NT hash format)",
            None,
            "Invalid Format",
            preview,
            length,
            "Invalid Format",
        )

    if operating_system.lower() != "linux":
        return (
            "Unknown",
            "Unknown",
            None,
            "Hash present; format not parsed",
            preview,
            len(raw_hash),
            "Not validated",
        )

    algorithm = detect_linux_hash_algorithm(raw_hash)
    match = re.fullmatch(r"\$(1|5|6|y)\$(.+)", raw_hash)
    if match:
        fields = raw_hash.split("$")
        identifier = fields[1]
        salt_index = 3 if identifier == "y" else 2
        if identifier in ("5", "6") and len(fields) > 2 and fields[2].startswith("rounds="):
            salt_index = 3
        if (
            len(fields) > salt_index + 1
            and fields[salt_index]
            and fields[salt_index + 1]
        ):
            salt = fields[salt_index]
            formats = {
                "1": "Modular Crypt Format ($1$)",
                "5": "Modular Crypt Format ($5$)",
                "6": "Modular Crypt Format ($6$)",
                "y": "Modular Crypt Format ($y$)",
            }
            return (
                formats[identifier],
                "Available",
                len(salt),
                "Parsed",
                preview,
                len(raw_hash),
                "Valid structure",
            )
        return (
            f"Modular Crypt Format (${identifier}$)",
            "Unknown",
            None,
            "Malformed hash fields",
            preview,
            len(raw_hash),
            "Invalid Format",
        )

    bcrypt_match = re.fullmatch(r"\$(2[aby])\$(\d{2})\$([./A-Za-z0-9]{53})", raw_hash)
    if bcrypt_match:
        return (
            f"bcrypt ({bcrypt_match.group(1)})",
            "Available",
            22,
            "Parsed",
            preview,
            len(raw_hash),
            "Valid structure",
        )

    if re.fullmatch(r"[./A-Za-z0-9]{13}", raw_hash):
        return (
            "Traditional DES crypt",
            "Available",
            2,
            "Parsed",
            preview,
            len(raw_hash),
            "Valid structure",
        )

    return (
        "Unknown",
        "Unknown",
        None,
        "Unsupported or unrecognized hash format",
        preview,
        len(raw_hash),
        "Unknown",
    )


def _safe_account_result(
    record: Mapping[str, object],
    operating_system: str,
) -> AccountReportResult:
    username = str(record.get("account", record.get("username", "Unknown")))
    algorithm = str(record.get("hash_algorithm", "Unknown"))
    availability = str(record.get("hash_status", "Unavailable"))
    audit_result = str(record.get("audit_result", "Error"))
    wordlist_status = str(record.get("wordlist_status", "Not evaluated"))
    strength = str(record.get("password_strength", "Unknown"))
    raw_hash = record.get("hash_value")
    raw_hash = raw_hash if isinstance(raw_hash, str) else None
    is_windows = operating_system.lower() == "windows"
    if is_windows:
        if not raw_hash:
            availability = "Unavailable"
            if audit_result in ("Weak", "Not in wordlist"):
                audit_result = "Error"
                wordlist_status = "Error"
                strength = "Not evaluated"
        algorithm = (
            "NT Hash (NTLM)"
            if raw_hash and is_valid_nt_hash(raw_hash)
            else "Unknown"
        )
        if audit_result == "Weak":
            wordlist_status = "Wordlist Match"
        elif audit_result == "Not in wordlist":
            wordlist_status = "Not Found in Wordlist"
        if raw_hash and not is_valid_nt_hash(raw_hash):
            audit_result = "Error"
            wordlist_status = "Error"
            strength = "Not evaluated"

    hash_source = str(
        record.get(
            "hash_source",
            "SAM" if is_windows else "/etc/shadow"
            if operating_system.lower() == "linux"
            else "Unknown",
        )
    )
    if hash_source not in ("SAM", "Imported NTLM File", "/etc/shadow"):
        hash_source = "Unknown"

    (
        hash_format,
        salt_status,
        salt_length,
        parsing_status,
        preview,
        hash_length,
        format_validation,
    ) = _hash_details(raw_hash, operating_system)
    unsupported_reason = ""
    notes = ""

    if audit_result == "Unsupported":
        supplied_reason = str(record.get("unsupported_reason", "")).casefold()
        if "yescrypt verification library is unavailable" in supplied_reason:
            unsupported_reason = (
                "Yescrypt verification library is unavailable; "
                "this account was not evaluated."
            )
        elif "password hash verification library is unavailable" in supplied_reason:
            unsupported_reason = (
                "The password-hash verification library is unavailable; "
                "this account was not evaluated."
            )
        elif "unsupported hash format or algorithm" in supplied_reason:
            unsupported_reason = (
                "The hash format or algorithm is unsupported; "
                "this account was not evaluated."
            )
        else:
            unsupported_reason = (
                "The hash format or verification backend is unsupported; "
                "this account was not evaluated."
            )
        notes = "No weak or strong conclusion can be drawn."
    elif audit_result.lower().startswith("error") or audit_result == "Verification Error":
        notes = (
            "Invalid NT hash format; account was not evaluated."
            if is_windows and raw_hash and not is_valid_nt_hash(raw_hash)
            else "Verification failed; this account was not evaluated."
        )
    elif audit_result == "Weak":
        notes = "A supplied wordlist candidate matched; reset this password."
    elif wordlist_status in (
        "Not Found",
        "Not in wordlist",
        "Not Found in Wordlist",
    ):
        notes = "No candidate matched; this does not prove the password is secure."

    return AccountReportResult(
        username=username,
        hash_availability=availability,
        hash_algorithm=algorithm,
        hash_format=hash_format,
        salt_availability=salt_status,
        salt_length=salt_length,
        hash_preview=preview,
        hash_parsing_status=parsing_status,
        unsupported_reason=unsupported_reason,
        wordlist_match_status=wordlist_status,
        password_strength=(
            strength
            if audit_result not in ("Unsupported", "Error", "Verification Error")
            else "Not evaluated"
        ),
        audit_result=audit_result,
        technical_notes=notes,
        hash_length=hash_length,
        hash_format_validation=format_validation,
        hash_source=hash_source,
    )


def create_audit_report(
    audit_type: str,
    records: Sequence[Mapping[str, object]],
    *,
    total_accounts: int | None,
    started_at: datetime,
    duration_seconds: float,
    errors: Sequence[str] = (),
    operating_system: str | None = None,
) -> AuditReport:
    """Create a report containing only safe, non-credential audit metadata."""
    os_name = operating_system or _system_name()
    accounts = [
        _safe_account_result(record, os_name)
        for record in records
    ]
    error_list = [str(error) for error in errors]
    weak = sum(record.audit_result == "Weak" for record in accounts)
    not_found = sum(
        record.wordlist_match_status in (
            "Not Found",
            "Not in wordlist",
            "Not Found in Wordlist",
        )
        for record in accounts
    )
    unsupported = sum(record.audit_result == "Unsupported" for record in accounts)
    row_errors = sum(
        record.audit_result.lower().startswith("error")
        or record.audit_result == "Verification Error"
        for record in accounts
    )
    return AuditReport(
        report_id=str(uuid4()),
        audit_date=started_at.astimezone().isoformat(timespec="seconds"),
        operating_system=os_name,
        audit_type=audit_type,
        total_accounts=total_accounts,
        accounts_audited=len(accounts),
        weak_passwords_found=weak,
        passwords_not_found_in_wordlist=not_found,
        unsupported_hashes=unsupported,
        audit_errors=len(error_list) + row_errors,
        audit_duration_seconds=max(0.0, float(duration_seconds)),
        errors=error_list,
        account_results=accounts,
    )


def report_recommendations(report: AuditReport) -> list[str]:
    recommendations = []
    if report.weak_passwords_found:
        recommendations.append(
            "Reset accounts whose passwords matched the supplied wordlist."
        )
    if report.unsupported_hashes:
        recommendations.append(
            "Re-audit unsupported hashes with a trusted, compatible verifier; "
            "these accounts were not evaluated."
        )
    if report.audit_errors:
        recommendations.append(
            "Resolve the reported audit errors and repeat the audit."
        )
    if report.passwords_not_found_in_wordlist:
        recommendations.append(
            "A wordlist non-match is not evidence of a strong or uncompromised password."
        )
    if not recommendations:
        recommendations.append(
            "No weak matches, unsupported hashes, or audit errors were recorded; "
            "this limited wordlist audit is not a security guarantee."
        )
    return recommendations


def _account_rows(report: AuditReport) -> list[list[object]]:
    return [
        [
            item.username,
            item.hash_availability,
            item.hash_algorithm,
            item.hash_format,
            item.hash_length if item.hash_length is not None else "",
            item.hash_format_validation,
            item.hash_source,
            item.salt_availability,
            item.salt_length if item.salt_length is not None else "",
            item.hash_preview,
            item.hash_parsing_status,
            item.wordlist_match_status,
            item.password_strength,
            item.audit_result,
            item.unsupported_reason,
            item.technical_notes,
        ]
        for item in report.account_results
    ]


def _csv_content(report: AuditReport) -> str:
    from io import StringIO

    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["PassGuard Password Auditor"])
    writer.writerow([
        "Report Generated At",
        datetime.now().astimezone().isoformat(timespec="seconds"),
    ])
    writer.writerow(["Report ID", report.report_id])
    writer.writerow(["Audit Date and Time", report.audit_date])
    writer.writerow(["Operating System", report.operating_system])
    writer.writerow(["Audit Type", report.audit_type])
    writer.writerow(["Total Accounts", report.total_accounts if report.total_accounts is not None else "Unknown"])
    writer.writerow(["Accounts Audited", report.accounts_audited])
    writer.writerow(["Weak Passwords Found", report.weak_passwords_found])
    writer.writerow(["Passwords Not Found in Wordlist", report.passwords_not_found_in_wordlist])
    writer.writerow(["Unsupported Hashes", report.unsupported_hashes])
    writer.writerow(["Audit Errors", report.audit_errors])
    writer.writerow(["Audit Duration (seconds)", f"{report.audit_duration_seconds:.3f}"])
    for error in report.errors:
        writer.writerow(["Audit Error", error])
    for recommendation in report_recommendations(report):
        writer.writerow(["Recommendation", recommendation])
    writer.writerow([])
    writer.writerow([
        "Username", "Hash Availability", "Hash Algorithm", "Hash Format",
        "Hash Length", "Hash Format Validation", "Hash Source",
        "Salt Availability", "Salt Length", "Hash Preview", "Hash Parsing Status",
        "Wordlist Match Status", "Password Strength", "Audit Result",
        "Unsupported Reason", "Technical Notes",
    ])
    writer.writerows(_account_rows(report))
    return output.getvalue()


def _html_content(report: AuditReport) -> str:
    esc = lambda value: html.escape(str(value), quote=True)
    summary = [
        ("Report ID", report.report_id),
        ("Audit Date and Time", report.audit_date),
        ("Operating System", report.operating_system),
        ("Audit Type", report.audit_type),
        ("Total Accounts", report.total_accounts if report.total_accounts is not None else "Unknown"),
        ("Accounts Audited", report.accounts_audited),
        ("Weak Passwords Found", report.weak_passwords_found),
        ("Passwords Not Found in Wordlist", report.passwords_not_found_in_wordlist),
        ("Unsupported Hashes", report.unsupported_hashes),
        ("Audit Errors", report.audit_errors),
        ("Audit Duration", f"{report.audit_duration_seconds:.3f} seconds"),
    ]
    headers = [
        "Username", "Hash Availability", "Hash Algorithm", "Hash Format",
        "Hash Length", "Hash Format Validation", "Hash Source",
        "Salt Information", "Salt Length", "Hash Preview", "Hash Parsing Status",
        "Wordlist Match Status", "Password Strength", "Audit Result",
        "Unsupported Reason", "Technical Notes",
    ]
    table_rows = "".join(
        "<tr>" + "".join(f"<td>{esc(value)}</td>" for value in row) + "</tr>"
        for row in _account_rows(report)
    )
    error_items = "".join(f"<li>{esc(error)}</li>" for error in report.errors)
    recommendation_items = "".join(
        f"<li>{esc(item)}</li>" for item in report_recommendations(report)
    )
    summary_rows = "".join(
        f"<tr><th>{esc(label)}</th><td>{esc(value)}</td></tr>"
        for label, value in summary
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PassGuard Password Auditor Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f3f6f7;color:#172125;margin:32px}}
main{{max-width:1400px;margin:auto;background:#fff;padding:28px;border:1px solid #d5dfe1}}
h1{{color:#147f78}}h2{{margin-top:30px;color:#26383c}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}
th,td{{border:1px solid #d5dfe1;padding:8px;text-align:left;vertical-align:top}}
th{{background:#edf3f3}}.results{{font-size:12px}}.notice{{color:#4d5b5e}}
</style></head><body><main>
<h1>PassGuard Password Auditor</h1>
<p>Report generated at: {esc(datetime.now().astimezone().isoformat(timespec="seconds"))}</p>
<p class="notice">Credential values are excluded. Hash previews are partially masked.</p>
<h2>Report Overview</h2><table><tbody>{summary_rows}</tbody></table>
<h2>Detailed Audit Results</h2><table class="results"><thead><tr>
{''.join(f'<th>{esc(header)}</th>' for header in headers)}
</tr></thead><tbody>{table_rows}</tbody></table>
<h2>Audit Errors</h2><ul>{error_items or '<li>None recorded.</li>'}</ul>
<h2>Security Recommendations</h2><ul>{recommendation_items}</ul>
</main></body></html>"""


def export_report(report: AuditReport, destination: str | Path, file_format: str) -> Path:
    path = Path(destination)
    normalized_format = file_format.lower().lstrip(".")
    if normalized_format == "json":
        content = json.dumps(
            {
                "title": "PassGuard Password Auditor",
                "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                "report": report.to_dict(),
                "recommendations": report_recommendations(report),
            },
            ensure_ascii=False,
            indent=2,
        )
    elif normalized_format == "csv":
        content = _csv_content(report)
    elif normalized_format == "html":
        content = _html_content(report)
    else:
        raise ValueError(f"Unsupported report format: {file_format}")

    path.write_text(content, encoding="utf-8", newline="")
    return path
