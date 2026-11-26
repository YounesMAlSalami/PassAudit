import csv
import json
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from passguard.audit_history import AuditHistoryStore
from passguard.password_utils import is_valid_nt_hash, mask_hash
from passguard.reporting import create_audit_report, export_report
from passguard import windows_auditor


class ReportServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.password = "PlaintextCandidate-Secret!"
        self.full_hash = "$6$salt123$" + ("a" * 86)
        self.records = [
            {
                "account": "alice",
                "hash_algorithm": "SHA-512",
                "hash_status": "Available",
                "hash_value": self.full_hash,
                "wordlist_status": "Found",
                "password_strength": "Weak",
                "audit_result": "Weak",
                "details": self.password,
            },
            {
                "account": "unsupported",
                "hash_algorithm": "Yescrypt",
                "hash_status": "Available",
                "hash_value": "$y$j9T$salt123$" + ("b" * 43),
                "wordlist_status": "Unsupported",
                "password_strength": "Not evaluated",
                "audit_result": "Unsupported",
                "unsupported_reason": "Yescrypt verification library is unavailable; account not evaluated",
            },
            {
                "account": "error",
                "hash_algorithm": "SHA-256",
                "hash_status": "Available",
                "hash_value": "$5$salt456$" + ("c" * 43),
                "wordlist_status": "Error",
                "password_strength": "Not evaluated",
                "audit_result": "Error",
                "details": self.password,
            },
        ]
        self.report = create_audit_report(
            "Linux (/etc/shadow)",
            self.records,
            total_accounts=12,
            started_at=datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc),
            duration_seconds=2.75,
            operating_system="Linux",
        )

    def test_hash_details_are_real_and_unsupported_is_not_evaluated(self):
        weak, unsupported, error = self.report.account_results
        self.assertEqual(weak.salt_availability, "Available")
        self.assertEqual(weak.salt_length, len("salt123"))
        self.assertEqual(weak.hash_parsing_status, "Parsed")
        self.assertEqual(unsupported.salt_length, len("salt123"))
        self.assertEqual(unsupported.audit_result, "Unsupported")
        self.assertEqual(unsupported.password_strength, "Not evaluated")
        self.assertIn("Yescrypt", unsupported.unsupported_reason)
        self.assertIn("not evaluated", unsupported.unsupported_reason)
        self.assertEqual(error.audit_result, "Error")
        self.assertEqual(error.password_strength, "Not evaluated")
        self.assertEqual(self.report.weak_passwords_found, 1)
        self.assertEqual(self.report.unsupported_hashes, 1)
        self.assertEqual(self.report.audit_errors, 1)

    def test_html_json_and_csv_exports_are_readable_and_redacted(self):
        paths = {
            extension: Path(self.temp_dir.name) / f"report.{extension}"
            for extension in ("html", "json", "csv")
        }
        for extension, path in paths.items():
            export_report(self.report, path, extension)
            content = path.read_text(encoding="utf-8")
            self.assertIn("PassGuard Password Auditor", content)
            self.assertIn("unsupported", content)
            self.assertNotIn(self.password, content)
            self.assertNotIn(self.full_hash, content)

        payload = json.loads(paths["json"].read_text(encoding="utf-8"))
        self.assertEqual(payload["report"]["unsupported_hashes"], 1)
        with paths["csv"].open(encoding="utf-8", newline="") as report_file:
            rows = list(csv.reader(report_file))
        self.assertTrue(any(row and row[0] == "Username" for row in rows))
        self.assertIn("alice", [cell for row in rows for cell in row])

    def test_sqlite_history_round_trip_and_delete_store_no_credentials(self):
        database = Path(self.temp_dir.name) / "reports" / "history.sqlite3"
        store = AuditHistoryStore(database)
        store.save_report(self.report)
        self.assertEqual(store.get_report(self.report.report_id), self.report)
        export_path = "audit.html"
        self.assertTrue(store.add_export_path(self.report.report_id, export_path))
        self.assertEqual(len(store.list_reports()), 1)

        connection = sqlite3.connect(database)
        try:
            saved_json, saved_paths = connection.execute(
                "SELECT report_json, exported_paths_json FROM audit_history WHERE report_id = ?",
                (self.report.report_id,),
            ).fetchone()
        finally:
            connection.close()
        self.assertNotIn(self.password, saved_json)
        self.assertNotIn(self.full_hash, saved_json)
        self.assertEqual(json.loads(saved_paths), [export_path])
        self.assertTrue(store.delete_report(self.report.report_id))
        self.assertEqual(store.list_reports(), [])

    def test_html_escapes_account_names(self):
        report = create_audit_report(
            "Windows (SAM/NTLM)",
            [{
                "account": "<script>alert(1)</script>",
                "hash_algorithm": "NTLM",
                "hash_status": "Available",
                "wordlist_status": "Not Found",
                "password_strength": "Unknown",
                "audit_result": "Not in wordlist",
            }],
            total_accounts=1,
            started_at=datetime.now().astimezone(),
            duration_seconds=1,
            operating_system="Windows",
        )
        destination = Path(self.temp_dir.name) / "escaped.html"
        export_report(report, destination, "html")
        content = destination.read_text(encoding="utf-8")
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_valid_nt_hash_details_and_format_validation(self):
        value = "0123456789ABCDEF0123456789ABCDEF"
        self.assertTrue(is_valid_nt_hash(value))
        report = create_audit_report(
            "Windows (SAM/NTLM)",
            [{
                "account": "sam-user",
                "hash_status": "Available",
                "hash_value": value,
                "hash_source": "SAM",
                "wordlist_status": "Not Found",
                "password_strength": "Unknown",
                "audit_result": "Not in wordlist",
            }],
            total_accounts=1,
            started_at=datetime.now().astimezone(),
            duration_seconds=0.2,
            operating_system="Windows",
        )
        account = report.account_results[0]
        self.assertEqual(account.hash_algorithm, "NT Hash (NTLM)")
        self.assertEqual(account.hash_format, "32-character hexadecimal")
        self.assertEqual(account.hash_length, 32)
        self.assertEqual(account.hash_format_validation, "Valid NT hash")
        self.assertEqual(account.hash_parsing_status, "Parsed")
        self.assertEqual(account.hash_source, "SAM")
        self.assertEqual(account.salt_availability, "Not applicable (NT hash is unsalted)")
        self.assertEqual(account.hash_preview, mask_hash(value))
        self.assertEqual(account.wordlist_match_status, "Not Found in Wordlist")
        self.assertEqual(account.password_strength, "Unknown")
        self.assertIn("does not prove", account.technical_notes)

    def test_invalid_nt_hash_is_not_mislabeled_or_evaluated(self):
        value = "G" * 32
        self.assertFalse(is_valid_nt_hash(value))
        report = create_audit_report(
            "Windows (SAM/NTLM)",
            [{
                "account": "invalid-user",
                "hash_algorithm": "NTLM",
                "hash_status": "Available",
                "hash_value": value,
                "hash_source": "SAM",
                "wordlist_status": "Not Found",
                "password_strength": "Unknown",
                "audit_result": "Not in wordlist",
            }],
            total_accounts=1,
            started_at=datetime.now().astimezone(),
            duration_seconds=0.2,
            operating_system="Windows",
        )
        account = report.account_results[0]
        self.assertEqual(account.hash_algorithm, "Unknown")
        self.assertEqual(account.hash_format, "Invalid Format")
        self.assertEqual(account.hash_length, 32)
        self.assertEqual(account.hash_format_validation, "Invalid Format")
        self.assertEqual(account.hash_parsing_status, "Invalid Format")
        self.assertEqual(account.audit_result, "Error")
        self.assertEqual(account.wordlist_match_status, "Error")
        self.assertEqual(account.password_strength, "Not evaluated")

    def test_windows_hash_is_redacted_from_exports_and_history(self):
        value = "A1B2C3D4E5F60718293A4B5C6D7E8F90"
        report = create_audit_report(
            "Windows (SAM/NTLM)",
            [{
                "account": "sam-user",
                "hash_status": "Available",
                "hash_value": value,
                "hash_source": "SAM",
                "wordlist_status": "Found",
                "password_strength": "Weak",
                "audit_result": "Weak",
            }],
            total_accounts=1,
            started_at=datetime.now().astimezone(),
            duration_seconds=0.2,
            operating_system="Windows",
        )
        for extension in ("html", "json", "csv"):
            destination = Path(self.temp_dir.name) / f"ntlm.{extension}"
            export_report(report, destination, extension)
            content = destination.read_text(encoding="utf-8")
            self.assertNotIn(value, content)
            self.assertIn(mask_hash(value), content)

        database = Path(self.temp_dir.name) / "ntlm-history.sqlite3"
        AuditHistoryStore(database).save_report(report)
        connection = sqlite3.connect(database)
        try:
            saved_json = connection.execute(
                "SELECT report_json FROM audit_history WHERE report_id = ?",
                (report.report_id,),
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertNotIn(value, saved_json)
        self.assertIn(mask_hash(value), saved_json)

    def test_windows_auditor_keeps_the_legacy_tuple_interface(self):
        password = "test-candidate"
        nt_hash = windows_auditor._ntlm_hash(password)
        wordlist = Path(self.temp_dir.name) / "wordlist.txt"
        wordlist.write_text(password + "\n", encoding="utf-8")
        with (
            patch.object(windows_auditor.sys, "platform", "win32"),
            patch.object(
                windows_auditor,
                "_backup_sam_hives",
                return_value=("SAM", "SYSTEM"),
            ),
            patch.object(
                windows_auditor,
                "extract_windows_ntlm_hashes",
                return_value={"sam-user": nt_hash},
            ),
        ):
            detailed, _ = windows_auditor.audit_windows_detailed_report(wordlist)
            legacy, summary = windows_auditor.audit_windows_report(wordlist)

        self.assertEqual(detailed[0].hash_value, nt_hash)
        self.assertEqual(detailed[0].hash_source, "SAM")
        self.assertEqual(detailed[0].state, "Weak")
        self.assertEqual(legacy[0][0:2], ("sam-user", "Weak"))
        self.assertEqual(len(legacy[0]), 3)
        self.assertNotIn(password, legacy[0][2])
        self.assertIn("Found 1 weak passwords", summary)


if __name__ == "__main__":
    unittest.main()
