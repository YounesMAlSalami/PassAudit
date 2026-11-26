"""Tkinter GUI for PassGuard. UI class retained from the supplied application."""
from __future__ import annotations
import math
import os
import sys
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk, filedialog
from tkinter.scrolledtext import ScrolledText
import tkinter as tk

from .config import AUDIT_HISTORY_DB, WORDLIST_PATH
from .wordlist import load_wordlist_candidates, load_wordlist, is_common_password, _load_candidates
from .password_utils import assess_password_strength, generate_strong_password, detect_linux_hash_algorithm, mask_hash
from .linux_auditor import audit_linux_shadow
from .windows_auditor import audit_windows_detailed_report
from .audit_history import AuditHistoryStore
from .reporting import AuditReport, create_audit_report, export_report

class PasswordAuditorApp:

    def __init__(
        self,
        root: tk.Tk,
        wordlist: set[str],
        wordlist_candidates: list[str]
    ) -> None:

        self.root = root
        self.wordlist = wordlist
        self.wordlist_candidates = wordlist_candidates
        self.password_visible = False
        self.audit_records = []
        self.audit_type = "None"
        self.current_report: AuditReport | None = None
        self.history_store = AuditHistoryStore(AUDIT_HISTORY_DB)
        self.wordlist_last_reload = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.colors = {
            "background": "#0A0D10",
            "surface": "#11161A",
            "surface_2": "#171D21",
            "surface_3": "#1D252A",
            "accent": "#45D3C6",
            "accent_hover": "#69E0D5",
            "text": "#F1F5F4",
            "muted": "#89979C",
            "green": "#55C892",
            "red": "#E66B73",
            "orange": "#D9A441",
            "border": "#263136",
            "input": "#0D1215",
            "selected": "#202B2F",
        }

        root.title("Password Auditor | Security Center")
        root.geometry("1180x780")
        root.minsize(940, 680)
        root.configure(bg=self.colors["background"])

        self._configure_styles()

        self.main_container = tk.Frame(
            root,
            bg=self.colors["background"]
        )

        self.main_container.pack(
            fill="both",
            expand=True
        )

        self.content = tk.Frame(
            self.main_container,
            bg=self.colors["background"]
        )

        self.content.pack(
            fill="both",
            expand=True
        )

        self._build_topbar()

        self.pages = {}

        self.pages["Dashboard"] = tk.Frame(
            self.content,
            bg=self.colors["background"]
        )

        self.pages["Account Audit"] = tk.Frame(
            self.content,
            bg=self.colors["background"]
        )
        self.pages["Password Generator"] = tk.Frame(
            self.content,
            bg=self.colors["background"]
        )
        self.pages["Reports"] = tk.Frame(
            self.content,
            bg=self.colors["background"]
        )

        self.build_dashboard()
        self.build_audit_page()
        self.build_generator_page()
        self.build_reports_page()

        self.show_page("Dashboard")
        self.refresh_report_history(load_latest=True)

    def _configure_styles(self):

        style = ttk.Style(self.root)

        try:
            style.theme_use("clam")

        except tk.TclError:
            pass

        style.configure(
            "Dark.TEntry",
            fieldbackground=self.colors["input"],
            foreground=self.colors["text"],
            insertcolor=self.colors["text"],
            padding=(12, 10),
            borderwidth=1,
            relief="flat"
        )

        style.configure(
            "Dark.Horizontal.TProgressbar",
            troughcolor=self.colors["surface_3"],
            background=self.colors["accent"],
            bordercolor=self.colors["surface_3"],
            lightcolor=self.colors["accent"],
            darkcolor=self.colors["accent"]
        )

    def _build_topbar(self):
        """Build a compact top navigation and system-status strip."""
        topbar = tk.Frame(
            self.content,
            bg=self.colors["surface"],
            height=66,
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        brand = tk.Frame(topbar, bg=self.colors["surface"])
        brand.pack(side="left", fill="y", padx=(24, 32))

        tk.Label(
            brand,
            text="P/A",
            bg=self.colors["accent"],
            fg="#071312",
            font=("Segoe UI", 13, "bold"),
            width=4,
            pady=7
        ).pack(side="left", pady=13)

        tk.Label(
            brand,
            text="PASSWORD AUDITOR",
            bg=self.colors["surface"],
            fg=self.colors["text"],
            font=("Segoe UI", 11, "bold")
        ).pack(side="left", padx=(10, 0), pady=13)

        nav = tk.Frame(topbar, bg=self.colors["surface"])
        nav.pack(side="left", fill="y")
        self.nav_buttons = {}

        for page_name in (
            "Dashboard", "Account Audit", "Password Generator", "Reports"
        ):
            button = tk.Button(
                nav,
                text=page_name.upper(),
                command=lambda name=page_name: self.show_page(name),
                bg=self.colors["surface"],
                fg=self.colors["muted"],
                activebackground=self.colors["selected"],
                activeforeground=self.colors["text"],
                font=("Segoe UI", 9, "bold"),
                relief="flat",
                bd=0,
                padx=18,
                pady=22,
                cursor="hand2"
            )
            button.pack(side="left", fill="y")
            self.nav_buttons[page_name] = button

        status = tk.Frame(topbar, bg=self.colors["surface"])
        status.pack(side="right", fill="y", padx=(12, 24))
        tk.Label(
            status,
            text="●",
            bg=self.colors["surface"],
            fg=self.colors["green"],
            font=("Segoe UI", 9)
        ).pack(side="left", padx=(0, 7), pady=22)
        tk.Label(
            status,
            text="LOCAL PROCESSING",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8, "bold")
        ).pack(side="left", pady=22)

    def show_page(self, page_name: str):

        for page in self.pages.values():
            page.pack_forget()

        self.pages[page_name].pack(
            fill="both",
            expand=True
        )

        for name, button in self.nav_buttons.items():

            if name == page_name:
                button.configure(
                    bg=self.colors["selected"],
                    fg=self.colors["accent"],
                    highlightbackground=self.colors["accent"],
                    highlightthickness=1
                )

            else:
                button.configure(
                    bg=self.colors["surface"],
                    fg=self.colors["muted"],
                    highlightthickness=0
                )

    def create_header(self, parent, title, subtitle):

        header = tk.Frame(
            parent,
            bg=self.colors["background"]
        )

        header.pack(
            fill="x",
            padx=34,
            pady=(26, 20)
        )

        tk.Label(
            header,
            text=title.upper(),
            bg=self.colors["background"],
            fg=self.colors["text"],
            font=("Segoe UI", 21, "bold")
        ).pack(anchor="w")

        tk.Label(
            header,
            text=subtitle,
            bg=self.colors["background"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            pady=(6, 0)
        )

    def create_card(self, parent, title, subtitle=None):

        card = tk.Frame(
            parent,
            bg=self.colors["surface"],
            highlightbackground=self.colors["border"],
            highlightthickness=1
        )

        tk.Label(
            card,
            text=title,
            bg=self.colors["surface"],
            fg=self.colors["text"],
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w",
            padx=18,
            pady=(16, 4)
        )

        if subtitle:

            tk.Label(
                card,
                text=subtitle,
                bg=self.colors["surface"],
                fg=self.colors["muted"],
                font=("Segoe UI", 8),
                wraplength=700,
                justify="left"
            ).pack(
                anchor="w",
                padx=18,
                pady=(0, 13)
            )

        return card

    def create_button(
        self,
        parent,
        text,
        command,
        primary=False
    ):

        background = (
            self.colors["accent"]
            if primary
            else self.colors["surface_3"]
        )

        foreground = (
            "#071521"
            if primary
            else self.colors["text"]
        )

        hover = (
            self.colors["accent_hover"]
            if primary
            else self.colors["border"]
        )

        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=background,
            fg=foreground,
            activebackground=hover,
            activeforeground=foreground,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            bd=0,
            padx=17,
            pady=10,
            cursor="hand2"
        )

        button.bind(
            "<Enter>",
            lambda event: button.configure(bg=hover)
        )

        button.bind(
            "<Leave>",
            lambda event: button.configure(bg=background)
        )

        return button

    def create_output(self, parent, height=10):

        output = ScrolledText(
            parent,
            height=height,
            wrap="word",
            state="disabled",
            font=("Cascadia Mono", 9),
            bg=self.colors["input"],
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            selectbackground=self.colors["accent"],
            selectforeground="#071521",
            relief="flat",
            bd=0,
            padx=12,
            pady=12
        )

        return output

    def build_dashboard(self):

        page = self.pages["Dashboard"]

        self.create_header(
            page,
            "Security Overview",
            "Local password intelligence and account assessment"
        )

        body = tk.Frame(
            page,
            bg=self.colors["background"]
        )
        body.pack(
            fill="x",
            padx=34
        )

        left = tk.Frame(body, bg=self.colors["background"])
        left.pack(side="left", fill="both", expand=True, padx=(0, 12))

        right = tk.Frame(body, bg=self.colors["background"], width=280)
        right.pack(side="left", fill="y")
        right.pack_propagate(False)

        check_card = self.create_card(
            left,
            "PASSWORD CHECK",
            "Compare a candidate against the loaded common-password corpus."
        )
        check_card.pack(fill="x")

        entry_area = tk.Frame(check_card, bg=self.colors["surface"])
        entry_area.pack(fill="x", padx=18, pady=(4, 12))

        self.password_entry = ttk.Entry(
            entry_area,
            style="Dark.TEntry",
            show="*",
            font=("Segoe UI", 12)
        )
        self.password_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=5
        )
        self.password_entry.bind("<Return>", self.check_password)

        self.visibility_button = self.create_button(
            entry_area,
            "Show",
            self.toggle_password_visibility
        )
        self.visibility_button.pack(side="left", padx=(8, 0), ipady=3)

        actions = tk.Frame(check_card, bg=self.colors["surface"])
        actions.pack(fill="x", padx=18, pady=(0, 14))

        self.create_button(
            actions,
            "Clear",
            self.clear_password
        ).pack(side="left")

        self.create_button(
            actions,
            "Run Check",
            self.check_password,
            primary=True
        ).pack(side="right")

        self.result_label = tk.Label(
            check_card,
            text="Awaiting password input.",
            bg=self.colors["surface_2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=520,
            padx=12,
            pady=12
        )
        self.result_label.pack(fill="x", padx=18, pady=(0, 18))

        technical = self.create_card(
            left,
            "TECHNICAL ANALYSIS",
            "Results are estimates and do not prove that a password is uncompromised."
        )
        technical.pack(fill="x", pady=(12, 0))

        self.technical_labels = {}
        for key, label in (
            ("wordlist", "Wordlist Status"),
            ("strength", "Password Strength"),
            ("score", "Strength Score"),
            ("length", "Password Length"),
            ("categories", "Character Categories"),
            ("pool", "Estimated Character Pool"),
            ("search", "Estimated Search Space"),
            ("recommendation", "Security Recommendations"),
        ):
            row = tk.Frame(technical, bg=self.colors["surface"])
            row.pack(fill="x", padx=18, pady=(0, 7))
            tk.Label(
                row,
                text=label,
                width=24,
                anchor="w",
                bg=self.colors["surface"],
                fg=self.colors["muted"],
                font=("Segoe UI", 8, "bold")
            ).pack(side="left")
            value = tk.Label(
                row,
                text="—",
                anchor="w",
                bg=self.colors["surface"],
                fg=self.colors["text"],
                font=("Consolas", 8),
                wraplength=430,
                justify="left"
            )
            value.pack(side="left", fill="x", expand=True)
            self.technical_labels[key] = value

        wordlist_card = self.create_card(
            right,
            "WORDLIST STATUS",
            "Local comparison corpus"
        )
        wordlist_card.pack(fill="x", pady=(0, 12))

        self.wordlist_status = tk.Label(
            wordlist_card,
            text="",
            bg=self.colors["surface"],
            fg=self.colors["accent"],
            font=("Consolas", 9, "bold"),
            justify="left",
            wraplength=230
        )
        self.wordlist_status.pack(
            anchor="w",
            padx=18,
            pady=(0, 12)
        )

        self.create_button(
            wordlist_card,
            "Reload Wordlist",
            self.reload_wordlist
        ).pack(
            anchor="w",
            padx=18,
            pady=(0, 16)
        )

        system_card = self.create_card(
            right,
            "SYSTEM STATUS",
            "Current operating system"
        )
        system_card.pack(fill="x", pady=(0, 12))

        system_name = (
            "Windows"
            if sys.platform == "win32"
            else "Linux / Ubuntu"
            if sys.platform.startswith("linux")
            else sys.platform
        )

        tk.Label(
            system_card,
            text=system_name,
            bg=self.colors["surface"],
            fg=self.colors["green"],
            font=("Segoe UI", 13, "bold")
        ).pack(
            anchor="w",
            padx=18,
            pady=(0, 18)
        )

        scope_card = self.create_card(
            right,
            "PROCESSING SCOPE",
            "No password or hash leaves this workstation."
        )
        scope_card.pack(fill="x")

        tk.Label(
            scope_card,
            text="● ENCRYPTED SESSION",
            bg=self.colors["surface"],
            fg=self.colors["green"],
            font=("Consolas", 8, "bold")
        ).pack(anchor="w", padx=18, pady=(0, 16))

        self.update_wordlist_status()

    def build_generator_page(self):
        page = self.pages["Password Generator"]
        self.create_header(
            page,
            "Password Generator",
            "Cryptographically secure local password creation"
        )

        body = tk.Frame(page, bg=self.colors["background"])
        body.pack(fill="both", expand=True, padx=34, pady=(0, 24))

        config = self.create_card(
            body,
            "GENERATOR SETTINGS",
            "Configure character categories and required password length."
        )
        config.pack(side="left", fill="y", padx=(0, 12), ipadx=8)

        length_row = tk.Frame(config, bg=self.colors["surface"])
        length_row.pack(fill="x", padx=18, pady=(4, 14))
        tk.Label(
            length_row,
            text="Password Length",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9, "bold")
        ).pack(side="left")

        self.generated_length = tk.StringVar(value="20")
        ttk.Entry(
            length_row,
            textvariable=self.generated_length,
            width=8,
            style="Dark.TEntry",
            font=("Consolas", 10)
        ).pack(side="right")

        self.generator_options = {}
        for name, label, default in (
            ("uppercase", "Uppercase letters", True),
            ("lowercase", "Lowercase letters", True),
            ("numbers", "Numbers", True),
            ("special", "Special characters", True),
        ):
            var = tk.BooleanVar(value=default)
            self.generator_options[name] = var
            tk.Checkbutton(
                config,
                text=label,
                variable=var,
                bg=self.colors["surface"],
                fg=self.colors["text"],
                activebackground=self.colors["surface"],
                activeforeground=self.colors["text"],
                selectcolor=self.colors["input"],
                font=("Segoe UI", 9),
                anchor="w"
            ).pack(fill="x", padx=18, pady=5)

        self.create_button(
            config,
            "Generate Password",
            self.generate_password,
            primary=True
        ).pack(fill="x", padx=18, pady=(18, 12))

        output = self.create_card(
            body,
            "GENERATED PASSWORD",
            "The value is masked by default and is not written to disk."
        )
        output.pack(side="left", fill="both", expand=True)

        self.generated_password_visible = False
        self.generated_password = ttk.Entry(
            output,
            style="Dark.TEntry",
            show="*",
            state="readonly",
            font=("Cascadia Mono", 12)
        )
        self.generated_password.pack(fill="x", padx=18, pady=(4, 12), ipady=5)

        generator_actions = tk.Frame(output, bg=self.colors["surface"])
        generator_actions.pack(fill="x", padx=18, pady=(0, 12))
        self.generator_show_button = self.create_button(
            generator_actions,
            "Show",
            self.toggle_generated_password
        )
        self.generator_show_button.pack(side="left")
        self.create_button(
            generator_actions,
            "Copy",
            self.copy_generated_password
        ).pack(side="left", padx=(8, 0))
        self.create_button(
            generator_actions,
            "Clear",
            self.clear_generated_password
        ).pack(side="right")

        self.generated_result = tk.Label(
            output,
            text="No password generated.",
            bg=self.colors["surface_2"],
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            justify="left",
            wraplength=520,
            padx=12,
            pady=10
        )
        self.generated_result.pack(fill="x", padx=18, pady=(0, 12))

        self.generated_technical = tk.Label(
            output,
            text="Strength: —  |  Score: —  |  Length: —  |  Diversity: —",
            bg=self.colors["surface"],
            fg=self.colors["text"],
            font=("Consolas", 8),
            anchor="w",
            justify="left",
            wraplength=520
        )
        self.generated_technical.pack(fill="x", padx=18, pady=(0, 12))

        tk.Label(
            output,
            text="Use a unique password for every account. Consider using a reputable password manager.",
            bg=self.colors["surface"],
            fg=self.colors["orange"],
            font=("Segoe UI", 8),
            anchor="w",
            justify="left",
            wraplength=520
        ).pack(fill="x", padx=18, pady=(0, 18))

    def build_audit_page(self):

        page = self.pages["Account Audit"]

        self.create_header(
            page,
            "Account Audit",
            "Credential exposure assessment for local operating-system accounts"
        )

        audit_card = self.create_card(
            page,
            "AUDIT WORKBENCH",
            (
                "Select a platform target. Linux requires read access to /etc/shadow; "
                "Windows requires elevated registry access."
            )
        )
        audit_card.pack(
            fill="both",
            expand=True,
            padx=34,
            pady=(0, 26)
        )

        actions = tk.Frame(
            audit_card,
            bg=self.colors["surface"]
        )
        actions.pack(
            fill="x",
            padx=18,
            pady=(2, 12)
        )

        self.create_button(
            actions,
            "LINUX  /  /etc/shadow",
            self.run_linux_audit,
            primary=True
        ).pack(side="left", pady=(0, 2))

        self.create_button(
            actions,
            "WINDOWS  /  SAM",
            self.run_windows_audit
        ).pack(
            side="left",
            padx=(10, 0),
            pady=(0, 2)
        )

        progress_frame = tk.Frame(
            audit_card,
            bg=self.colors["surface"]
        )
        progress_frame.pack(fill="x", padx=18, pady=(0, 10))

        tk.Label(
            progress_frame,
            text="EXECUTION",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8, "bold")
        ).pack(side="left")

        self.audit_progress = ttk.Progressbar(
            progress_frame,
            mode="indeterminate",
            style="Dark.Horizontal.TProgressbar",
            length=220
        )
        self.audit_progress.pack(side="left", padx=(12, 0))

        self.audit_result_output = self.create_output(
            audit_card,
            height=18
        )
        self.audit_result_output.pack(
            fill="both",
            expand=True,
            padx=18,
            pady=(0, 18)
        )

        table_frame = tk.Frame(audit_card, bg=self.colors["surface"])
        table_frame.pack(fill="x", padx=18, pady=(0, 10))

        columns = (
            "Account",
            "Hash Algorithm",
            "Hash Status",
            "Wordlist Status",
            "Password Strength",
            "Audit Result",
        )
        self.audit_table = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=7
        )
        for column in columns:
            self.audit_table.heading(column, text=column)
            self.audit_table.column(
                column,
                width=140 if column != "Audit Result" else 170,
                anchor="w"
            )
        self.audit_table.pack(side="left", fill="x", expand=True)

        table_scroll = ttk.Scrollbar(
            table_frame,
            orient="vertical",
            command=self.audit_table.yview
        )
        table_scroll.pack(side="right", fill="y")
        self.audit_table.configure(yscrollcommand=table_scroll.set)

        hash_details = tk.Frame(audit_card, bg=self.colors["surface"])
        hash_details.pack(fill="x", padx=18, pady=(0, 10))
        tk.Label(
            hash_details,
            text="HASH DETAILS",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w")
        self.hash_detail_label = tk.Label(
            hash_details,
            text="Select an account in the table to inspect masked hash details.",
            bg=self.colors["surface"],
            fg=self.colors["text"],
            font=("Consolas", 8),
            anchor="w",
            wraplength=760
        )
        self.hash_detail_label.pack(fill="x", pady=(5, 6))
        self.hash_visible = False
        self.hash_selected_account = None
        self.create_button(
            hash_details,
            "Show Hash",
            self.toggle_hash_visibility
        ).pack(anchor="w")
        self.audit_table.bind("<<TreeviewSelect>>", self.select_audit_account)

        export_frame = tk.Frame(audit_card, bg=self.colors["surface"])
        export_frame.pack(fill="x", padx=18, pady=(0, 12))
        tk.Label(
            export_frame,
            text="EXPORT REPORT",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8, "bold")
        ).pack(side="left", padx=(0, 12))
        for label, extension in (
            ("HTML", "html"),
            ("CSV", "csv"),
            ("JSON", "json"),
        ):
            self.create_button(
                export_frame,
                label,
                lambda ext=extension: self.export_audit_report(ext)
            ).pack(side="left", padx=(0, 8))

    def build_reports_page(self) -> None:
        page = self.pages["Reports"]
        self.create_header(
            page,
            "Reports",
            "Evidence-based summaries and exportable local audit history"
        )

        overview = self.create_card(page, "REPORT OVERVIEW")
        overview.pack(fill="x", padx=34, pady=(0, 12))
        metrics_grid = tk.Frame(overview, bg=self.colors["surface"])
        metrics_grid.pack(fill="x", padx=12, pady=(0, 12))
        metrics = (
            ("report_id", "Report ID"),
            ("audit_date", "Audit Date and Time"),
            ("operating_system", "Operating System"),
            ("audit_type", "Audit Type"),
            ("total_accounts", "Total Accounts"),
            ("accounts_audited", "Accounts Audited"),
            ("weak_passwords_found", "Weak Passwords Found"),
            ("passwords_not_found_in_wordlist", "Not Found in Wordlist"),
            ("unsupported_hashes", "Unsupported Hashes"),
            ("audit_errors", "Audit Errors"),
            ("audit_duration_seconds", "Audit Duration"),
        )
        self.report_metric_labels = {}
        for index, (key, title) in enumerate(metrics):
            metric = tk.Frame(metrics_grid, bg=self.colors["surface_2"])
            metric.grid(
                row=index // 4,
                column=index % 4,
                sticky="nsew",
                padx=5,
                pady=5,
            )
            tk.Label(
                metric,
                text=title.upper(),
                bg=self.colors["surface_2"],
                fg=self.colors["muted"],
                font=("Segoe UI", 7, "bold"),
                anchor="w",
            ).pack(fill="x", padx=9, pady=(8, 2))
            value = tk.Label(
                metric,
                text="—",
                bg=self.colors["surface_2"],
                fg=self.colors["text"],
                font=("Consolas", 9, "bold"),
                anchor="w",
                wraplength=220,
                justify="left",
            )
            value.pack(fill="x", padx=9, pady=(0, 8))
            self.report_metric_labels[key] = value
        for column in range(4):
            metrics_grid.grid_columnconfigure(column, weight=1)

        export_bar = tk.Frame(page, bg=self.colors["background"])
        export_bar.pack(fill="x", padx=34, pady=(0, 10))
        tk.Label(
            export_bar,
            text="EXPORT CURRENT REPORT",
            bg=self.colors["background"],
            fg=self.colors["muted"],
            font=("Segoe UI", 8, "bold"),
        ).pack(side="left", padx=(0, 12))
        for extension in ("html", "json", "csv"):
            self.create_button(
                export_bar,
                extension.upper(),
                lambda ext=extension: self.export_report_dialog(ext),
            ).pack(side="left", padx=(0, 8))

        results_card = self.create_card(
            page,
            "DETAILED AUDIT RESULTS",
            "Select an account to inspect parsed, partially masked hash information.",
        )
        results_card.pack(fill="both", expand=True, padx=34, pady=(0, 10))
        result_frame = tk.Frame(results_card, bg=self.colors["surface"])
        result_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))
        report_columns = (
            "Username",
            "Hash Availability",
            "Hash Algorithm",
            "Hash Format",
            "Hash Length",
            "Format Validation",
            "Hash Source",
            "Salt Information",
            "Hash Preview",
            "Hash Parsing Status",
            "Wordlist Match Status",
            "Password Strength",
            "Audit Result",
            "Technical Notes",
        )
        self.report_table = ttk.Treeview(
            result_frame,
            columns=report_columns,
            show="headings",
            height=5,
        )
        widths = (
            120, 115, 140, 165, 90, 135, 125,
            185, 140, 145, 150, 115, 110, 260,
        )
        for column, width in zip(report_columns, widths):
            self.report_table.heading(column, text=column)
            self.report_table.column(
                column,
                width=width,
                minwidth=80,
                anchor="w",
                stretch=False,
            )
        self.report_table.pack(side="top", fill="both", expand=True)
        self.report_table.bind(
            "<<TreeviewSelect>>", self.select_report_account
        )
        report_scroll_x = ttk.Scrollbar(
            result_frame, orient="horizontal", command=self.report_table.xview
        )
        report_scroll_x.pack(side="bottom", fill="x")
        self.report_table.configure(xscrollcommand=report_scroll_x.set)
        self.report_detail_label = tk.Label(
            results_card,
            text="No audit results are available. Run an audit to populate this report.",
            bg=self.colors["surface"],
            fg=self.colors["muted"],
            font=("Consolas", 8),
            anchor="w",
            justify="left",
            wraplength=1040,
        )
        self.report_detail_label.pack(fill="x", padx=14, pady=(0, 12))

        history_card = self.create_card(page, "AUDIT HISTORY")
        history_card.pack(fill="x", padx=34, pady=(0, 20))
        history_frame = tk.Frame(history_card, bg=self.colors["surface"])
        history_frame.pack(fill="x", padx=12, pady=(0, 8))
        history_columns = (
            "Audit Date",
            "Audit Type",
            "Operating System",
            "Total Accounts",
            "Audited",
            "Weak",
            "Not Found",
            "Unsupported",
            "Errors",
            "Duration (s)",
        )
        self.history_table = ttk.Treeview(
            history_frame,
            columns=history_columns,
            show="headings",
            height=4,
        )
        for column, width in zip(
            history_columns, (155, 150, 110, 105, 85, 75, 110, 75, 75, 100)
        ):
            self.history_table.heading(column, text=column)
            self.history_table.column(column, width=width, anchor="w")
        self.history_table.pack(side="left", fill="x", expand=True)
        history_scroll = ttk.Scrollbar(
            history_frame, orient="vertical", command=self.history_table.yview
        )
        history_scroll.pack(side="right", fill="y")
        self.history_table.configure(yscrollcommand=history_scroll.set)
        self.history_table.bind(
            "<Double-1>", lambda _event: self.open_selected_history()
        )

        history_actions = tk.Frame(history_card, bg=self.colors["surface"])
        history_actions.pack(fill="x", padx=12, pady=(0, 12))
        self.create_button(
            history_actions, "Open Selected", self.open_selected_history
        ).pack(side="left")
        self.create_button(
            history_actions,
            "Re-export Selected",
            self.reexport_selected_history,
        ).pack(side="left", padx=(8, 0))
        self.create_button(
            history_actions,
            "Delete Selected",
            self.delete_selected_history,
        ).pack(side="right")

    def _render_report(self, report: AuditReport | None) -> None:
        self.current_report = report
        for item in self.report_table.get_children():
            self.report_table.delete(item)
        if report is None:
            for label in self.report_metric_labels.values():
                label.configure(text="—")
            self.report_detail_label.configure(
                text="No audit results are available. Run an audit to populate this report."
            )
            return

        values = {
            "report_id": report.report_id,
            "audit_date": report.audit_date,
            "operating_system": report.operating_system,
            "audit_type": report.audit_type,
            "total_accounts": (
                report.total_accounts
                if report.total_accounts is not None
                else "Unknown"
            ),
            "accounts_audited": report.accounts_audited,
            "weak_passwords_found": report.weak_passwords_found,
            "passwords_not_found_in_wordlist": (
                report.passwords_not_found_in_wordlist
            ),
            "unsupported_hashes": report.unsupported_hashes,
            "audit_errors": report.audit_errors,
            "audit_duration_seconds": (
                f"{report.audit_duration_seconds:.2f} seconds"
            ),
        }
        for key, value in values.items():
            self.report_metric_labels[key].configure(text=str(value))

        for index, record in enumerate(report.account_results):
            salt = record.salt_availability
            if record.salt_length is not None:
                salt += f" ({record.salt_length} chars)"
            self.report_table.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    record.username,
                    record.hash_availability,
                    record.hash_algorithm,
                    record.hash_format,
                    record.hash_length if record.hash_length is not None else "Unknown",
                    record.hash_format_validation,
                    record.hash_source,
                    salt,
                    record.hash_preview or "Unavailable",
                    record.hash_parsing_status,
                    record.wordlist_match_status,
                    record.password_strength,
                    record.audit_result,
                    record.technical_notes,
                ),
            )
        if report.errors:
            self.report_detail_label.configure(
                text="Audit-level errors: " + " | ".join(report.errors)
            )
        elif not report.account_results:
            self.report_detail_label.configure(
                text="The audit produced no account results; no successful evaluation is implied."
            )
        else:
            self.report_detail_label.configure(
                text="Select an account to inspect hash details. Hash previews remain partially masked."
            )

    def select_report_account(self, _event: tk.Event | None = None) -> None:
        if not self.current_report:
            return
        selection = self.report_table.selection()
        if not selection:
            return
        try:
            record = self.current_report.account_results[int(selection[0])]
        except (ValueError, IndexError):
            return
        salt_length = (
            f"{record.salt_length} characters"
            if record.salt_length is not None
            else "Not available"
        )
        details = [
            f"Algorithm: {record.hash_algorithm}",
            f"Hash format: {record.hash_format}",
            f"Hash length: {record.hash_length if record.hash_length is not None else 'Unknown'}",
            f"Format validation: {record.hash_format_validation}",
            f"Source: {record.hash_source}",
            f"Salt information: {record.salt_availability}",
            f"Salt length: {salt_length}",
            f"Hash preview: {record.hash_preview or 'Unavailable'}",
            f"Parsing: {record.hash_parsing_status}",
        ]
        if record.unsupported_reason:
            details.append(f"Unsupported reason: {record.unsupported_reason}")
        self.report_detail_label.configure(text=" | ".join(details))

    def refresh_report_history(self, load_latest: bool = False) -> None:
        try:
            reports = self.history_store.list_reports()
        except (OSError, sqlite3.Error) as error:
            messagebox.showerror(
                "Audit history unavailable",
                f"Audit history could not be read:\n{error}",
                parent=self.root,
            )
            return
        for item in self.history_table.get_children():
            self.history_table.delete(item)
        for item in reports:
            total = item["total_accounts"]
            self.history_table.insert(
                "",
                "end",
                iid=str(item["report_id"]),
                values=(
                    item["audit_date"],
                    item["audit_type"],
                    item["operating_system"],
                    total if total is not None else "Unknown",
                    item["accounts_audited"],
                    item["weak_passwords_found"],
                    item["passwords_not_found_in_wordlist"],
                    item["unsupported_hashes"],
                    item["audit_errors"],
                    f"{float(item['audit_duration_seconds']):.2f}",
                ),
            )
        if load_latest and reports:
            try:
                latest = self.history_store.get_report(
                    str(reports[0]["report_id"])
                )
            except (OSError, sqlite3.Error, ValueError, KeyError) as error:
                messagebox.showerror(
                    "Unable to open latest report",
                    f"The latest report could not be opened:\n{error}",
                    parent=self.root,
                )
                return
            if latest:
                self._render_report(latest)
        elif load_latest:
            self._render_report(None)

    def open_selected_history(self) -> None:
        selection = self.history_table.selection()
        if not selection:
            messagebox.showinfo(
                "No audit selected",
                "Select a history entry to open its report.",
                parent=self.root,
            )
            return
        report_id = str(selection[0])
        try:
            report = self.history_store.get_report(report_id)
        except (OSError, sqlite3.Error, ValueError, KeyError) as error:
            messagebox.showerror(
                "Unable to open report",
                f"The selected report could not be opened:\n{error}",
                parent=self.root,
            )
            return
        if report is None:
            messagebox.showerror(
                "Report not found",
                "The selected history record no longer exists.",
                parent=self.root,
            )
            self.refresh_report_history()
            return
        self._render_report(report)

    def _selected_history_report(self) -> AuditReport | None:
        selection = self.history_table.selection()
        if not selection:
            messagebox.showinfo(
                "No audit selected",
                "Select a history entry first.",
                parent=self.root,
            )
            return None
        try:
            report = self.history_store.get_report(str(selection[0]))
        except (OSError, sqlite3.Error, ValueError, KeyError) as error:
            messagebox.showerror(
                "Unable to open report",
                f"The selected report could not be opened:\n{error}",
                parent=self.root,
            )
            return None
        if report is None:
            messagebox.showerror(
                "Report not found",
                "The selected history record no longer exists.",
                parent=self.root,
            )
        return report

    def delete_selected_history(self) -> None:
        selection = self.history_table.selection()
        if not selection:
            messagebox.showinfo(
                "No audit selected",
                "Select a history entry to delete.",
                parent=self.root,
            )
            return
        report_id = str(selection[0])
        if not messagebox.askyesno(
            "Delete audit history",
            "Permanently delete this audit history record?",
            parent=self.root,
        ):
            return
        try:
            deleted = self.history_store.delete_report(report_id)
        except (OSError, sqlite3.Error) as error:
            messagebox.showerror(
                "Unable to delete history",
                f"The history record could not be deleted:\n{error}",
                parent=self.root,
            )
            return
        if deleted and self.current_report and self.current_report.report_id == report_id:
            self._render_report(None)
        self.refresh_report_history()

    def _save_report_to_dialog(
        self,
        report: AuditReport,
        extension: str | None,
        title: str,
    ) -> None:
        formats = {
            "html": ("HTML Report", "*.html"),
            "json": ("JSON Report", "*.json"),
            "csv": ("CSV Report", "*.csv"),
        }
        if extension is not None and extension not in formats:
            messagebox.showerror(
                "Unsupported report format",
                f"Unsupported report format: {extension}",
                parent=self.root,
            )
            return
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filetypes = (
            [(formats[extension][0], formats[extension][1])]
            if extension
            else [formats[name] for name in ("html", "json", "csv")]
        )
        destination = filedialog.asksaveasfilename(
            parent=self.root,
            title=title,
            initialfile=f"passguard_audit_{stamp}.{extension or 'html'}",
            defaultextension=f".{extension}" if extension else ".html",
            filetypes=filetypes,
        )
        if not destination:
            return
        chosen_format = extension or Path(destination).suffix.lower().lstrip(".")
        if chosen_format not in formats:
            chosen_format = "html"
        try:
            saved_path = export_report(report, destination, chosen_format)
        except (OSError, UnicodeError, ValueError) as error:
            messagebox.showerror(
                "Export failed",
                f"The report could not be written:\n{error}",
                parent=self.root,
            )
            return
        try:
            self.history_store.add_export_path(report.report_id, saved_path)
        except (OSError, sqlite3.Error) as error:
            messagebox.showerror(
                "Report exported; history update failed",
                f"The report was saved to:\n{saved_path}\n\n"
                f"The export path could not be added to audit history:\n{error}",
                parent=self.root,
            )
            return
        messagebox.showinfo(
            "Report exported",
            f"Report saved to:\n{saved_path}",
            parent=self.root,
        )

    def export_report_dialog(self, extension: str) -> None:
        if self.current_report is None:
            messagebox.showwarning(
                "No audit results",
                "Run an account audit or open a history entry before exporting.",
                parent=self.root,
            )
            return
        self._save_report_to_dialog(
            self.current_report, extension, "Export Audit Report"
        )

    def reexport_selected_history(self) -> None:
        report = self._selected_history_report()
        if report:
            self._save_report_to_dialog(
                report, None, "Re-export Historical Audit Report"
            )

    def _publish_audit_report(
        self, report: AuditReport, output_text: str
    ) -> None:
        self._render_report(report)
        try:
            self.history_store.save_report(report)
        except (OSError, sqlite3.Error) as error:
            messagebox.showerror(
                "Audit history save failed",
                f"The report is available for this session, but could not be saved to history:\n{error}",
                parent=self.root,
            )
        self.refresh_report_history()
        self.set_audit_output(output_text)

    def set_audit_output(self, text: str) -> None:

        self.audit_result_output.configure(state="normal")

        self.audit_result_output.delete(
            "1.0",
            tk.END
        )

        self.audit_result_output.insert(
            "1.0",
            text
        )
        self.audit_result_output.configure(state="disabled")

        terminal_text = text.lower()
        is_running = (
            "auditing" in terminal_text
            or "exporting" in terminal_text
        )
        is_finished = (
            "audit results" in terminal_text
            or "failed" in terminal_text
            or "error:" in terminal_text
            or "available on" in terminal_text
            or "privileges (sudo)" in terminal_text
        )

        if is_running:
            if str(self.audit_progress["mode"]) == "indeterminate":
                try:
                    self.audit_progress.start(30)
                except tk.TclError:
                    pass
        elif is_finished:
            try:
                self.audit_progress.stop()
            except tk.TclError:
                pass

    def populate_audit_table(self) -> None:
        for item in self.audit_table.get_children():
                self.audit_table.delete(item)
        for record in self.audit_records:
                self.audit_table.insert(
                    "",
                    "end",
                    values=(
                        record["account"],
                        record["hash_algorithm"],
                        record["hash_status"],
                        record["wordlist_status"],
                        record["password_strength"],
                        record["audit_result"],
                    )
                )

    def select_audit_account(self, _event: tk.Event | None = None) -> None:
        selection = self.audit_table.selection()
        if not selection:
                return
        values = self.audit_table.item(selection[0], "values")
        if not values:
                return
        account = str(values[0])
        self.hash_selected_account = account
        self.hash_visible = False
        self.update_hash_detail_label()

    def update_hash_detail_label(self) -> None:
        record = next(
                (
                    item for item in self.audit_records
                    if item["account"] == self.hash_selected_account
                ),
                None,
        )
        if record is None:
                self.hash_detail_label.config(
                    text="Select an account in the table to inspect masked hash details."
                )
                return
        hash_value = record.get("hash_value")
        displayed_hash = (
                hash_value if self.hash_visible and hash_value
                else mask_hash(hash_value) if hash_value
                else "Unavailable"
        )
        self.hash_detail_label.config(
                text=(
                    f"Account: {record['account']} | "
                    f"Algorithm: {record['hash_algorithm']} | "
                    f"Hash Status: {record['hash_status']} | "
                    f"Hash: {displayed_hash}"
                )
        )

    def toggle_hash_visibility(self) -> None:
        if not self.hash_selected_account:
                messagebox.showinfo(
                    "No account selected",
                    "Select an account in the audit table first.",
                    parent=self.root
                )
                return
        if self.hash_visible:
            self.hash_visible = False
            self.update_hash_detail_label()
            return
        if sys.platform.startswith("linux") and os.geteuid() != 0:
            messagebox.showerror(
                "Insufficient privileges",
                "Full hash display is limited to an elevated local session.",
                parent=self.root,
            )
            return
        if sys.platform == "win32":
            try:
                import ctypes

                elevated = bool(ctypes.windll.shell32.IsUserAnAdmin())
            except (AttributeError, OSError):
                elevated = False
            if not elevated:
                messagebox.showerror(
                    "Insufficient privileges",
                    "Full hash display is limited to an elevated local session.",
                    parent=self.root,
                )
                return
        if not messagebox.askyesno(
            "Display sensitive hash",
            "Show the complete hash locally? It will not be added to reports or history.",
            parent=self.root,
        ):
            return
        self.hash_visible = True
        self.update_hash_detail_label()

    def export_audit_report(self, extension: str) -> None:
        self.export_report_dialog(extension)

    def run_windows_audit(self) -> None:

        if sys.platform != "win32":
            self.set_audit_output(
                "This audit is available on Windows only."
            )
            return

        audit_started_at = datetime.now().astimezone()
        timer_started_at = time.perf_counter()
        self.audit_records = []
        self.populate_audit_table()
        self.set_audit_output(
            "Exporting and auditing Windows accounts...\n"
            "Please wait for the audit to finish."
        )

        def worker():

            found = []
            errors = []
            try:
                found, summary = audit_windows_detailed_report(
                    WORDLIST_PATH
                )

                lines = [
                    "Windows Audit Results (SAM)",
                    "=" * 72,
                    ""
                ]

                if found:

                    lines.append(
                        "Account                         Result            Details"
                    )

                    lines.append("-" * 72)

                    for result in found:
                        lines.append(
                            f"{result.username:<30} {result.state:<18} {result.details}"
                        )

                else:
                    lines.append(summary)

                lines.extend([
                    "",
                    summary
                ])

                text = "\n".join(lines)

            except Exception as error:
                text = f"Windows audit failed:\n{error}"
                summary = "Windows audit failed."
                errors.append(
                    "Windows audit failed; technical details are omitted from the report."
                )

            if any(
                marker in summary.casefold()
                for marker in ("failed", "unavailable", "wordlist is empty", "unable to")
            ) and not errors:
                errors.append(
                    "Windows audit could not complete; technical details are omitted from the report."
                )

            self.audit_type = "Windows (SAM/NTLM)"
            self.audit_records = []
            for result in found:
                username = result.username
                state = result.state
                details = result.details
                if state == "Weak":
                    wordlist_status = "Found"
                    password_strength = "Weak"
                    audit_result = "Weak"
                elif state in ("Strong", "Not in wordlist"):
                    wordlist_status = "Not Found"
                    password_strength = "Unknown"
                    audit_result = "Not in wordlist"
                elif state == "Unsupported":
                    wordlist_status = "Unsupported"
                    password_strength = "Not evaluated"
                    audit_result = "Unsupported"
                else:
                    wordlist_status = "Error"
                    password_strength = "Not evaluated"
                    audit_result = "Error"
                self.audit_records.append({
                    "account": username,
                    "hash_algorithm": result.hash_algorithm,
                    "hash_status": (
                        "Available" if result.hash_value else "Unavailable"
                    ),
                    "hash_value": result.hash_value or None,
                    "hash_source": result.hash_source,
                    "wordlist_status": wordlist_status,
                    "password_strength": password_strength,
                    "audit_result": audit_result,
                    "unsupported_reason": details if state == "Unsupported" else "",
                })

            total_accounts = (
                len(found)
                if "extracted" in summary.casefold()
                else None
            )
            report = create_audit_report(
                self.audit_type,
                self.audit_records,
                total_accounts=total_accounts,
                started_at=audit_started_at,
                duration_seconds=time.perf_counter() - timer_started_at,
                errors=errors,
                operating_system="Windows",
            )
            self.root.after(
                0,
                lambda report=report, text=text: (
                    self.populate_audit_table(),
                    self._publish_audit_report(report, text),
                ),
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def run_linux_audit(self) -> None:

        if not sys.platform.startswith("linux"):
            self.set_audit_output(
                "This audit is available on Linux only."
            )
            return

        self.audit_records = []
        self.populate_audit_table()
        if os.geteuid() != 0:
            started_at = datetime.now().astimezone()
            report = create_audit_report(
                "Linux (/etc/shadow)",
                [],
                total_accounts=None,
                started_at=started_at,
                duration_seconds=0,
                errors=[
                    "Audit could not start because elevated privileges are required to read /etc/shadow."
                ],
                operating_system="Linux",
            )
            self._publish_audit_report(
                report,
                "Error: Administrator privileges (sudo) are required "
                "to read /etc/shadow.",
            )
            return

        candidate_count = len(
            _load_candidates(WORDLIST_PATH)
        )

        audit_started_at = datetime.now().astimezone()
        timer_started_at = time.perf_counter()

        def show_progress(
            current_account: int,
            total_accounts: int,
            username: str,
            checked: int,
            total_candidates: int,
        ) -> None:

            elapsed = time.perf_counter() - timer_started_at

            status = (
                "Auditing Linux password hashes...\n"
                f"Account {username} "
                f"({current_account} of {total_accounts})\n"
                f"{checked:,} of {total_candidates:,} candidates checked "
                f"• elapsed {elapsed:.0f} seconds."
            )

            self.root.after(
                0,
                lambda status=status: self.set_audit_output(status)
            )

        self.set_audit_output(
            "Auditing Linux password hashes...\n"
            f"Wordlist loaded: {candidate_count:,} candidates. "
            "This may take a while."
        )

        def worker():

            found = []
            errors = []
            try:
                found, summary = audit_linux_shadow(
                    WORDLIST_PATH,
                    show_progress
                )

                lines = [
                    "Linux Audit Results (/etc/shadow)",
                    "=" * 72,
                    ""
                ]

                if not found and (
                    "Failed" in summary or "Error" in summary
                ):
                    lines.append(summary)

                else:

                    if found:

                        lines.append(
                            "Account                         Result            Details"
                        )

                        lines.append("-" * 72)

                        for username, state, details in found:
                            lines.append(
                                f"{username:<30} {state:<18} {details}"
                            )

                    lines.extend([
                        "",
                        summary
                    ])

                text = "\n".join(lines)

            except Exception:
                import traceback

                text = (
                    "Unexpected error:\n"
                    f"{traceback.format_exc()}"
                )
                summary = "Linux audit failed."
                errors.append(
                    "Linux audit failed; technical details are omitted from the report."
                )

            if any(
                marker in summary.casefold()
                for marker in ("failed", "error", "wordlist is empty", "unable")
            ) and not errors:
                errors.append(
                    "Linux audit could not complete; technical details are omitted from the report."
                )

            shadow_map = {}
            if sys.platform.startswith("linux"):
                try:
                    with open("/etc/shadow", "r", encoding="utf-8", errors="ignore") as shadow_file:
                        for line in shadow_file:
                            parts = line.strip().split(":")
                            if len(parts) >= 2:
                                shadow_map[parts[0]] = parts[1]
                except (OSError, PermissionError):
                    shadow_map = {}

            self.audit_type = "Linux (/etc/shadow)"
            self.audit_records = []
            for username, state, details in found:
                full_hash = shadow_map.get(username, "")
                algorithm = detect_linux_hash_algorithm(full_hash) if full_hash else "Unknown"
                if state == "Weak":
                    wordlist_status = "Found"
                    password_strength = "Weak"
                    audit_result = "Weak"
                elif state == "Not in the list":
                    wordlist_status = "Not Found"
                    password_strength = "Unknown"
                    audit_result = "Not in wordlist"
                elif state == "Unsupported":
                    wordlist_status = "Unsupported"
                    password_strength = "Not evaluated"
                    audit_result = "Unsupported"
                else:
                    wordlist_status = "Error"
                    password_strength = "Not evaluated"
                    audit_result = "Error"

                hash_status = (
                    "Locked or unavailable"
                    if not full_hash or full_hash in ("!", "*", "!!", "", "x")
                    else "Available"
                )
                self.audit_records.append({
                    "account": username,
                    "hash_algorithm": algorithm,
                    "hash_status": hash_status,
                    "hash_value": full_hash or None,
                    "wordlist_status": wordlist_status,
                    "password_strength": password_strength,
                    "audit_result": audit_result,
                    "unsupported_reason": details if state == "Unsupported" else "",
                })

            try:
                with open("/etc/passwd", "r", encoding="utf-8", errors="strict") as passwd_file:
                    total_accounts = sum(
                        1 for line in passwd_file if len(line.rstrip("\n").split(":")) >= 7
                    )
            except (OSError, UnicodeError):
                total_accounts = None

            report = create_audit_report(
                self.audit_type,
                self.audit_records,
                total_accounts=total_accounts,
                started_at=audit_started_at,
                duration_seconds=time.perf_counter() - timer_started_at,
                errors=errors,
                operating_system="Linux",
            )
            self.root.after(
                0,
                lambda report=report, text=text: (
                    self.populate_audit_table(),
                    self._publish_audit_report(report, text),
                ),
            )

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    def toggle_password_visibility(self) -> None:

        self.password_visible = not self.password_visible

        self.password_entry.configure(
            show="" if self.password_visible else "*"
        )
        self.visibility_button.configure(
            text="Hide" if self.password_visible else "Show"
        )

        self.password_entry.focus_set()

    def check_password(
        self,
        _event: tk.Event | None = None
    ) -> None:

        password = self.password_entry.get()

        if not password.strip():
            self.result_label.config(
                text="Enter a password to check.",
                fg=self.colors["orange"]
            )
            return

        assessment = assess_password_strength(password)
        wordlist_status = "Error" if not self.wordlist else (
            "Found" if is_common_password(password, self.wordlist)
            else "Not Found"
        )

        if wordlist_status == "Found":
            summary = "WARNING: This password appears in the common-password wordlist."
            color = self.colors["red"]
        elif wordlist_status == "Error":
            summary = "Wordlist comparison is unavailable; strength is still assessed."
            color = self.colors["orange"]
        else:
            summary = "No wordlist match. Absence does not prove the password is strong."
            color = self.colors["green"]

        self.result_label.config(
            text=f"{summary}\nStrength: {assessment['classification']} ({assessment['score']}/100)",
            fg=color
        )
        self.technical_labels["wordlist"].config(text=wordlist_status)
        self.technical_labels["strength"].config(
            text=assessment["classification"]
        )
        self.technical_labels["score"].config(
            text=f"{assessment['score']}/100"
        )
        self.technical_labels["length"].config(
            text=str(assessment["length"])
        )
        self.technical_labels["categories"].config(
            text=", ".join(assessment["categories"]) or "None"
        )
        self.technical_labels["pool"].config(
            text=f"~{assessment['character_pool']} characters"
        )
        search_space = assessment["search_space"]
        if search_space:
            try:
                estimate = f"~10^{math.log10(search_space):.1f}"
            except (ValueError, OverflowError):
                estimate = "Too large to display"
        else:
            estimate = "0"
        self.technical_labels["search"].config(text=estimate)
        self.technical_labels["recommendation"].config(
            text=" ".join(assessment["recommendations"])
        )

        del password

    def clear_password(self) -> None:

        self.password_entry.delete(
            0,
            tk.END
        )

        self.result_label.config(text="")
        for label in self.technical_labels.values():
            label.config(text="—")
        self.password_entry.focus_set()

    def generate_password(self) -> None:
        try:
            length = int(self.generated_length.get())
        except ValueError:
            self.generated_result.config(
                text="Enter a valid numeric password length.",
                fg=self.colors["red"]
            )
            return

        password, error = generate_strong_password(
            length,
            self.generator_options["uppercase"].get(),
            self.generator_options["lowercase"].get(),
            self.generator_options["numbers"].get(),
            self.generator_options["special"].get(),
        )
        if error:
            self.generated_result.config(text=error, fg=self.colors["red"])
            return

        self.generated_password.configure(state="normal")
        self.generated_password.delete(0, tk.END)
        self.generated_password.insert(0, password)
        self.generated_password.configure(state="readonly")

        assessment = assess_password_strength(password)
        diversity = len(assessment["categories"])
        warning = ""
        if assessment["classification"] in ("Very Weak", "Weak"):
            warning = " Warning: generated configuration produced a weak result."
            color = self.colors["red"]
        else:
            color = self.colors["green"]

        self.generated_result.config(
            text=f"{assessment['classification']} password generated.{warning}",
            fg=color
        )
        self.generated_technical.config(
            text=(
                f"Strength: {assessment['classification']}  |  "
                f"Score: {assessment['score']}/100  |  "
                f"Length: {assessment['length']}  |  "
                f"Diversity: {diversity} categories"
            )
        )
        del password

    def toggle_generated_password(self) -> None:
        self.generated_password_visible = not self.generated_password_visible
        self.generated_password.configure(
            show="" if self.generated_password_visible else "*"
        )
        self.generator_show_button.configure(
            text="Hide" if self.generated_password_visible else "Show"
        )

    def copy_generated_password(self) -> None:
        if not self.generated_password.get():
            messagebox.showwarning(
                "Nothing to copy",
                "Generate a password before copying.",
                parent=self.root
            )
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.generated_password.get())
        self.generated_result.config(
            text="Password copied to the clipboard.",
            fg=self.colors["green"]
        )

    def clear_generated_password(self) -> None:
        self.generated_password.configure(state="normal")
        self.generated_password.delete(0, tk.END)
        self.generated_password.configure(state="readonly")
        self.generated_password_visible = False
        self.generated_password.configure(show="*")
        self.generator_show_button.configure(text="Show")
        self.generated_result.config(
            text="Generated password cleared.",
            fg=self.colors["muted"]
        )
        self.generated_technical.config(
            text="Strength: —  |  Score: —  |  Length: —  |  Diversity: —"
        )

    def update_wordlist_status(self) -> None:
        try:
            file_size = WORDLIST_PATH.stat().st_size
            size_text = f"{file_size:,} bytes"
        except OSError:
            size_text = "Unavailable"
        duplicates = len(self.wordlist_candidates) - len(self.wordlist)
        self.wordlist_status.config(
            text=(
                f"{WORDLIST_PATH.name}\n"
                f"Total: {len(self.wordlist_candidates):,}\n"
                f"Unique: {len(self.wordlist):,}\n"
                f"Duplicates: {duplicates:,}\n"
                f"Size: {size_text}\n"
                f"Reloaded: {self.wordlist_last_reload}"
            )
        )

    def reload_wordlist(self) -> None:

        try:
            updated_candidates = load_wordlist_candidates()

        except (OSError, UnicodeError) as error:

            messagebox.showerror(
                "Unable to load the wordlist",
                f"Check the file {WORDLIST_PATH.name}:\n{error}",
                parent=self.root
            )

            return

        self.wordlist_candidates = updated_candidates

        self.wordlist = {
            candidate.casefold()
            for candidate in updated_candidates
        }
        self.wordlist_last_reload = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self.update_wordlist_status()

        self.result_label.config(
            text="The wordlist was updated.",
            fg=self.colors["green"]
        )
