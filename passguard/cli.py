"""Interactive command-line interface for PassGuard."""
from __future__ import annotations
import csv
import getpass
import json
import os
import sys
import time
from pathlib import Path

from .config import WORDLIST_PATH
from .wordlist import load_wordlist_candidates, load_wordlist, is_common_password, _load_candidates
from .password_utils import assess_password_strength, generate_strong_password, detect_linux_hash_algorithm, mask_hash, mask_password
from .linux_auditor import audit_linux_shadow
from .windows_auditor import audit_windows_report

def print_cli_table(
    rows: list[tuple[str, str, str]],
    checked: int,
    weak: int
) -> None:

    print("\n┌─ Audit Results")

    print(
        "┌─────────────────────┬────────────┬─────────────────┬──────────┐"
    )

    print(
        "│ Account              │ Algorithm │ Result         │ Details │"
    )

    print(
        "├─────────────────────┼────────────┼─────────────────┼──────────┤"
    )

    for username, state, details in rows:
        print(
            f"│ {username:<19} │ NTLM       │ {state:<15} │ {details:<8} │"
        )

    print(
        "└─────────────────────┴────────────┴─────────────────┴──────────┘"
    )

    print("\n┌─ Summary")
    print(f"  Candidates checked       {checked}")
    print(f"  Account count           {len(rows)}")
    print(f"  Weak passwords            {weak}")


def cli_main() -> None:

    while True:

        print("\n" + "=" * 72)
        print("                        Password Audit Tool".center(72))
        print("=" * 72)

        print("  1  Audit Linux Passwords (/etc/shadow)")
        print("  2  Audit Windows Accounts (SAM)")
        print("  3  Check a Candidate Password")
        print("  4  Exit")

        try:
            choice = input("\nChoose [1-4]: ").strip()

        except (KeyboardInterrupt, EOFError):
            choice = "4"

        if choice == "1":

            if not sys.platform.startswith("linux"):
                print("This audit is available on Linux only.")
                continue

            candidate_count = len(
                _load_candidates(WORDLIST_PATH)
            )

            started_at = time.perf_counter()
            last_account = 0

            def show_progress(
                current_account: int,
                total_accounts: int,
                username: str,
                checked: int,
                total_candidates: int,
            ) -> None:

                nonlocal last_account

                if last_account and current_account != last_account:
                    print()

                elapsed = time.perf_counter() - started_at

                print(
                    f"\rAccount {username} "
                    f"({current_account}/{total_accounts}): "
                    f"{checked:,}/{total_candidates:,} candidates checked "
                    f"• {elapsed:.0f}s elapsed",
                    end="",
                    flush=True,
                )

                last_account = current_account

            try:
                found, summary = audit_linux_shadow(
                    WORDLIST_PATH,
                    show_progress
                )

                print()

            except KeyboardInterrupt:
                print(
                    "\nAudit cancelled. "
                    "No complete results are available."
                )
                continue

            if found:

                print(
                    "Account                         Result            Details"
                )

                print("-" * 72)

                for username, state, details in found:
                    print(
                        f"{username:<30} {state:<18} {details}"
                    )

            print(summary)

        elif choice == "2":

            if sys.platform != "win32":
                print("This audit is available on Windows only.")
                continue

            print("\n" + "=" * 72)
            print("Windows Account Audit (SAM)")
            print("=" * 72)

            found, summary = audit_windows_report(
                WORDLIST_PATH
            )

            if found:

                print(
                    "Account                         Result            Details"
                )

                print("-" * 72)

                for username, state, details in found:
                    print(
                        f"{username:<30} {state:<18} {details}"
                    )

            print(summary)

        elif choice == "3":

            import getpass

            print(
                "\nInteractive Check — type exit to return"
            )

            while True:

                try:
                    password = getpass.getpass("Password: ").strip()

                except (KeyboardInterrupt, EOFError):
                    break

                if password.lower() == "exit":
                    del password
                    break

                if is_common_password(
                    password,
                    load_wordlist(WORDLIST_PATH)
                ):

                    print(
                        "[! WARNING] This password appears "
                        "in the common-password list."
                    )

                else:

                    print(
                        "[✓ OK] This password is not in the wordlist."
                    )

                del password

        elif choice == "4":

            print("Goodbye.")
            break

        else:

            print("[! WARNING] Invalid selection.")
