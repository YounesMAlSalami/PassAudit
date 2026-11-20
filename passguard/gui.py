"""PySide6 desktop interface for PassGuard."""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
from typing import Optional

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from .linux_auditor import audit_linux_shadow
from .password_analyzer import analyze_password, classify_interactive_password
from .password_generator import generate_password
from .reporter import to_csv, to_html, to_json
from .wordlist_loader import load_wordlist_set
from .windows_auditor import audit_windows_hashes, audit_windows_sam_direct


class AuditWorker(QObject):
    progress = Signal(str, int, int)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, audit_callable, cancel_event=None):
        super().__init__()
        self.audit_callable = audit_callable
        self.cancel_event = cancel_event

    def run(self):
        try:
            report = self.audit_callable(
                progress_cb=lambda message, done, total: self.progress.emit(
                    message, int(done), int(total)
                ),
                cancel_event=self.cancel_event,
            )
            self.finished.emit(report)
        except Exception as exc:
            self.failed.emit(str(exc))


class PassGuardWindow(QMainWindow):
    def __init__(self, wordlist_path: Optional[str] = None):
        super().__init__()
        self.wordlist_path = wordlist_path or os.path.abspath(
            os.path.join(os.getcwd(), "wordlists", "wordlist.txt")
        )
        self.wordlist_set = None
        if os.path.exists(self.wordlist_path):
            try:
                self.wordlist_set = load_wordlist_set(
                    self.wordlist_path, case_fold=True
                )
            except Exception:
                self.wordlist_set = None
        self.last_report = None
        self._thread = None
        self._worker = None
        self._cancel_event = None

        self.setWindowTitle("PassGuard")
        self.resize(1100, 760)
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self._build_analyzer_tab(), "Password Analyzer")
        self.tabs.addTab(self._build_auditor_tab(), "System Account Auditor")
        self.tabs.addTab(self._build_generator_tab(), "Password Generator")
        self.tabs.addTab(self._build_reports_tab(), "Reports and History")

    def _build_analyzer_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Enter a password for immediate wordlist analysis"))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.textChanged.connect(self._analyze_live_password)
        layout.addWidget(self.password_input)
        self.analyzer_result = QLabel("ANALYSIS_INCOMPLETE")
        self.analyzer_result.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self.analyzer_result)
        layout.addStretch()
        return page

    def _analyze_live_password(self, password):
        if not password:
            self.analyzer_result.setText("ANALYSIS_INCOMPLETE")
            return
        in_wordlist = (
            password.casefold() in self.wordlist_set
            if self.wordlist_set is not None
            else False
        )
        analysis = analyze_password(
            password,
            in_wordlist=in_wordlist,
            wordlist_checked=self.wordlist_set is not None,
        )
        category = classify_interactive_password(
            analysis, wordlist_checked=self.wordlist_set is not None
        )
        self.analyzer_result.setText(
            f"{category} | Strength: {analysis.level} | Score: {analysis.score}/100"
        )

    def _build_auditor_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)

        linux_row = QHBoxLayout()
        linux_row.addWidget(QLabel("Linux local /etc/shadow audit"))
        linux_button = QPushButton("Start Linux Audit")
        linux_button.clicked.connect(self._start_linux_audit)
        linux_row.addWidget(linux_button)
        layout.addLayout(linux_row)

        windows_row = QHBoxLayout()
        windows_row.addWidget(QLabel("Windows local SAM or imported NTLM audit"))
        windows_live = QPushButton("Audit Live Windows SAM")
        windows_live.clicked.connect(self._start_windows_live_audit)
        windows_import = QPushButton("Audit Imported NTLM File")
        windows_import.clicked.connect(self._start_windows_import_audit)
        windows_row.addWidget(windows_live)
        windows_row.addWidget(windows_import)
        layout.addLayout(windows_row)

        cancel_button = QPushButton("Cancel Audit")
        cancel_button.clicked.connect(self._cancel_audit)
        layout.addWidget(cancel_button)

        self.audit_status = QLabel("Idle")
        layout.addWidget(self.audit_status)
        self.audit_progress = QProgressBar()
        layout.addWidget(self.audit_progress)

        self.audit_table = QTableWidget()
        self.audit_table.setColumnCount(7)
        self.audit_table.setHorizontalHeaderLabels([
            "Username",
            "UID",
            "Algorithm",
            "Status",
            "Risk",
            "Salt",
            "Source",
        ])
        layout.addWidget(self.audit_table)
        return page

    def _build_generator_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        row = QHBoxLayout()
        row.addWidget(QLabel("Generated password"))
        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)
        row.addWidget(self.generated_password)
        generate = QPushButton("Generate")
        generate.clicked.connect(self._generate_password)
        row.addWidget(generate)
        layout.addLayout(row)
        layout.addStretch()
        return page

    def _generate_password(self):
        self.generated_password.setText(generate_password(length=20))

    def _build_reports_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Export the last completed audit"))
        row = QHBoxLayout()
        json_button = QPushButton("Export JSON")
        csv_button = QPushButton("Export CSV")
        html_button = QPushButton("Export HTML")
        json_button.clicked.connect(lambda: self._export_report("json"))
        csv_button.clicked.connect(lambda: self._export_report("csv"))
        html_button.clicked.connect(lambda: self._export_report("html"))
        row.addWidget(json_button)
        row.addWidget(csv_button)
        row.addWidget(html_button)
        layout.addLayout(row)
        self.report_output = QTextEdit()
        self.report_output.setReadOnly(True)
        layout.addWidget(self.report_output)
        return page

    def _start_worker(self, callable_object, supports_cancel=False):
        if self._thread is not None:
            return
        self._cancel_event = mp.Event() if supports_cancel else None
        self._thread = QThread(self)
        self._worker = AuditWorker(callable_object, self._cancel_event)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.progress.connect(self._update_progress)
        self._worker.failed.connect(self._audit_failed)
        self._worker.finished.connect(self._audit_finished)
        self._worker.finished.connect(self._thread.quit)
        self._worker.failed.connect(self._thread.quit)
        self._thread.finished.connect(self._clear_worker)
        self._thread.start()

    def _clear_worker(self):
        self._thread = None
        self._worker = None
        self._cancel_event = None

    def _cancel_audit(self):
        if self._cancel_event is not None:
            self._cancel_event.set()
            self.audit_status.setText("Cancellation requested")

    def _update_progress(self, message, done, total):
        self.audit_status.setText(message)
        if total > 0:
            self.audit_progress.setMaximum(total)
            self.audit_progress.setValue(done)
        else:
            self.audit_progress.setMaximum(0)

    def _audit_finished(self, report):
        self.last_report = report
        self._populate_audit_table(report)
        self.audit_status.setText("Audit completed")
        self.report_output.setPlainText(
            f"Platform: {report.source_platform}\n"
            f"Hostname: {report.hostname}\n"
            f"Duration: {report.duration_seconds:.3f} seconds\n"
            f"Weak accounts: {report.accounts_weak}\n"
            f"Not assessed: {report.accounts_not_assessed}\n"
        )

    def _audit_failed(self, message):
        self.audit_status.setText(f"Error: {message}")

    def _populate_audit_table(self, report):
        report.compute_summary()
        self.audit_table.setRowCount(len(report.findings))
        for row, finding in enumerate(report.findings):
            values = [
                finding.username,
                str(finding.uid or ""),
                finding.algorithm,
                finding.status,
                finding.severity,
                finding.salt or "",
                finding.audit_source or finding.source,
            ]
            for column, value in enumerate(values):
                self.audit_table.setItem(row, column, QTableWidgetItem(value))

    def _start_linux_audit(self):
        def run_audit(progress_cb=None, cancel_event=None):
            return audit_linux_shadow(
                wordlist_path=self.wordlist_path,
                progress_cb=progress_cb,
                cancel_event=cancel_event,
            )

        self._start_worker(run_audit, supports_cancel=True)

    def _start_windows_live_audit(self):
        def run_audit(progress_cb=None, cancel_event=None):
            return audit_windows_sam_direct(
                wordlist_path=self.wordlist_path,
                progress_cb=progress_cb,
            )

        self._start_worker(run_audit)

    def _start_windows_import_audit(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select NTLM Hash File", "", "Hash files (*.txt *.dump);;All files (*)"
        )
        if not path:
            return

        def run_audit(progress_cb=None, cancel_event=None):
            return audit_windows_hashes(
                hash_file_path=path,
                wordlist_path=self.wordlist_path,
                progress_cb=progress_cb,
            )

        self._start_worker(run_audit)

    def _export_report(self, extension):
        if self.last_report is None:
            self.audit_status.setText("No completed audit to export")
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Save {extension.upper()} Report",
            f"passguard_audit.{extension}",
            f"{extension.upper()} files (*.{extension})",
        )
        if not path:
            return
        if extension == "json":
            to_json(self.last_report, path)
        elif extension == "csv":
            to_csv(self.last_report, path)
        else:
            to_html(self.last_report, path)
        self.report_output.append(f"Exported: {path}")


def launch_gui(wordlist_path: Optional[str] = None) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    window = PassGuardWindow(wordlist_path)
    window.show()
    return app.exec()
