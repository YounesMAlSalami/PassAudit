"""SQLite persistence for credential-safe audit history."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .reporting import AuditReport


class AuditHistoryStore:
    def __init__(self, database_path: str | Path) -> None:
        self.database_path = Path(database_path)

    def _connect(self) -> sqlite3.Connection:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_history (
                report_id TEXT PRIMARY KEY,
                audit_date TEXT NOT NULL,
                audit_type TEXT NOT NULL,
                operating_system TEXT NOT NULL,
                total_accounts INTEGER,
                accounts_audited INTEGER NOT NULL,
                weak_passwords_found INTEGER NOT NULL,
                passwords_not_found_in_wordlist INTEGER NOT NULL,
                unsupported_hashes INTEGER NOT NULL,
                audit_errors INTEGER NOT NULL,
                audit_duration_seconds REAL NOT NULL,
                report_json TEXT NOT NULL,
                exported_paths_json TEXT NOT NULL DEFAULT '[]'
            )
            """
        )

    def save_report(self, report: AuditReport) -> None:
        with self._session() as connection:
            self._initialize(connection)
            connection.execute(
                """
                INSERT OR REPLACE INTO audit_history (
                    report_id, audit_date, audit_type, operating_system,
                    total_accounts, accounts_audited, weak_passwords_found,
                    passwords_not_found_in_wordlist, unsupported_hashes,
                    audit_errors, audit_duration_seconds, report_json,
                    exported_paths_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    COALESCE(
                        (SELECT exported_paths_json FROM audit_history
                         WHERE report_id = ?), '[]'
                    ))
                """,
                (
                    report.report_id,
                    report.audit_date,
                    report.audit_type,
                    report.operating_system,
                    report.total_accounts,
                    report.accounts_audited,
                    report.weak_passwords_found,
                    report.passwords_not_found_in_wordlist,
                    report.unsupported_hashes,
                    report.audit_errors,
                    report.audit_duration_seconds,
                    json.dumps(report.to_dict(), ensure_ascii=False),
                    report.report_id,
                ),
            )

    def list_reports(self) -> list[dict[str, object]]:
        with self._session() as connection:
            self._initialize(connection)
            rows = connection.execute(
                """
                SELECT report_id, audit_date, audit_type, operating_system,
                       total_accounts, accounts_audited, weak_passwords_found,
                       passwords_not_found_in_wordlist, unsupported_hashes,
                       audit_errors, audit_duration_seconds
                FROM audit_history
                ORDER BY audit_date DESC, report_id DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def get_report(self, report_id: str) -> AuditReport | None:
        with self._session() as connection:
            self._initialize(connection)
            row = connection.execute(
                "SELECT report_json FROM audit_history WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if row is None:
                return None
            return AuditReport.from_dict(json.loads(row["report_json"]))

    def add_export_path(self, report_id: str, path: str | Path) -> bool:
        with self._session() as connection:
            self._initialize(connection)
            row = connection.execute(
                "SELECT exported_paths_json FROM audit_history WHERE report_id = ?",
                (report_id,),
            ).fetchone()
            if row is None:
                return False
            paths = json.loads(row["exported_paths_json"])
            value = str(path)
            if value not in paths:
                paths.append(value)
            connection.execute(
                "UPDATE audit_history SET exported_paths_json = ? WHERE report_id = ?",
                (json.dumps(paths, ensure_ascii=False), report_id),
            )
            return True

    def delete_report(self, report_id: str) -> bool:
        with self._session() as connection:
            self._initialize(connection)
            cursor = connection.execute(
                "DELETE FROM audit_history WHERE report_id = ?",
                (report_id,),
            )
            return cursor.rowcount > 0
