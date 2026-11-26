"""Windows local SAM auditing helpers. Use only on systems you administer."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import WORDLIST_PATH
from .wordlist import _load_candidates
from .password_utils import is_valid_nt_hash, mask_password


@dataclass(frozen=True)
class WindowsAuditResult:
    username: str
    state: str
    details: str
    hash_value: str
    hash_algorithm: str
    hash_source: str = "SAM"


ProgressCallback = Callable[[int, int, str, int, int], None]


def _ntlm_hash(password: str) -> str:
    from Crypto.Hash import MD4

    return MD4.new(
        password.encode("utf-16-le")
    ).hexdigest().upper()


def _terminate_process(process: subprocess.Popen) -> None:
    """Stop a registry export process and reap it."""
    if process.poll() is not None:
        return

    try:
        process.terminate()
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
        except OSError:
            pass

        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _backup_sam_hives(
    temp_dir: str,
    stop_event: threading.Event | None = None,
    deadline: float | None = None,
) -> tuple[str | None, str | None]:
    """
    Export SAM and SYSTEM hives.

    The reg.exe subprocess is monitored so Stop and the duration limit can
    terminate an export that is still running.
    """
    if stop_event is None:
        stop_event = threading.Event()

    sam_path = os.path.join(temp_dir, "SAM")
    system_path = os.path.join(temp_dir, "SYSTEM")

    for hive, target in (
        (r"hklm\sam", sam_path),
        (r"hklm\system", system_path),
    ):
        if stop_event.is_set():
            return None, "Stopped by user"

        if deadline is not None and time.perf_counter() >= deadline:
            return None, "Maximum duration reached"

        try:
            process = subprocess.Popen(
                ["reg", "save", hive, target, "/y"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as error:
            return None, f"Unable to start registry export: {error}"

        while process.poll() is None:
            if stop_event.is_set():
                _terminate_process(process)
                return None, "Stopped by user"

            if deadline is not None and time.perf_counter() >= deadline:
                _terminate_process(process)
                return None, "Maximum duration reached during registry export"

            time.sleep(0.05)

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            message = (stderr or stdout or "").strip()
            return (
                None,
                message or "Failed to export the Windows registry hive",
            )

    return sam_path, system_path


def extract_windows_ntlm_hashes(
    sam_path: str,
    system_path: str,
) -> dict[str, str]:
    """Extract account NT hashes from exported SAM and SYSTEM hives."""

    hashes: dict[str, str] = {}

    try:
        from pypykatz.registry.offline_parser import OffineRegistry

        registry = OffineRegistry.from_files(
            system_path,
            sam_path,
        )

        sam_data = registry.to_dict().get("SAM", {})

        users = (
            sam_data.get("local_users", [])
            if isinstance(sam_data, dict)
            else []
        )

        for user in users:
            if not isinstance(user, dict):
                continue

            username = str(
                user.get("username", "")
            ).strip()

            nt_hash = user.get("nt_hash", b"")

            if isinstance(nt_hash, bytes):
                nt_hash = nt_hash.hex()

            nt_hash = str(nt_hash).upper()

            if username and nt_hash and nt_hash not in (
                "",
                "31D6CFE0D16AE931B73C59D7E0C089C0",
            ):
                hashes[username] = nt_hash

    except ImportError as error:
        raise RuntimeError(
            "The pypykatz library is unavailable"
        ) from error

    except Exception as error:
        raise RuntimeError(
            f"Unable to read SAM hashes: {error}"
        ) from error

    return hashes


def audit_windows_detailed_report(
    wordlist_path: str | Path = WORDLIST_PATH,
    progress_callback: ProgressCallback | None = None,
    *,
    max_candidates: int | None = None,
    max_duration_seconds: float | None = None,
    rate_limit: float | None = None,
    stop_event: threading.Event | None = None,
    stop_on_first_match: bool = False,
) -> tuple[list[WindowsAuditResult], str]:
    """
    Audit local Windows SAM hashes.

    max_candidates is a total candidate limit for this audit.
    max_duration_seconds is the maximum overall audit duration.
    rate_limit is candidates per second (None means unlimited).
    stop_event is set by the GUI to request cancellation.
    stop_on_first_match stops the full audit after the first match.
    """

    if sys.platform != "win32":
        return [], "This audit is available on Windows only."

    if stop_event is None:
        stop_event = threading.Event()

    if max_candidates is not None:
        max_candidates = max(1, int(max_candidates))

    if max_duration_seconds is not None:
        max_duration_seconds = max(0.1, float(max_duration_seconds))

    if rate_limit is not None:
        rate_limit = max(0.1, float(rate_limit))

    started_at = time.perf_counter()
    deadline = (
        started_at + max_duration_seconds
        if max_duration_seconds is not None
        else None
    )

    def stop_reason(checked: int) -> str | None:
        if stop_event.is_set():
            return "Stopped by user"

        if deadline is not None and time.perf_counter() >= deadline:
            return "Maximum duration reached"

        if (
            max_candidates is not None
            and checked >= max_candidates
        ):
            return "Maximum candidate limit reached"

        return None

    if stop_event.is_set():
        return [], "Audit stopped by user before starting."

    temp_dir = tempfile.mkdtemp(prefix="pwaudit_")

    try:
        sam_path, system_path = _backup_sam_hives(
            temp_dir,
            stop_event=stop_event,
            deadline=deadline,
        )

        if sam_path is None:
            message = system_path or "Unknown reason"

            if message.startswith("Stopped"):
                return [], f"Audit stopped: {message}."

            if message.startswith("Maximum duration"):
                return [], f"Audit stopped: {message}."

            return [], f"Registry backup failed: {message}"

        reason = stop_reason(0)
        if reason is not None:
            return [], f"Audit stopped: {reason}."

        try:
            user_hashes = extract_windows_ntlm_hashes(
                sam_path,
                system_path,
            )
        except RuntimeError as error:
            return [], str(error)

        reason = stop_reason(0)
        if reason is not None:
            rows = [
                WindowsAuditResult(
                    username,
                    "Not audited",
                    reason,
                    nt_hash,
                    "NT Hash (NTLM)"
                    if is_valid_nt_hash(nt_hash)
                    else "Unknown",
                )
                for username, nt_hash in user_hashes.items()
            ]
            return rows, f"Audit stopped: {reason}. SAM extraction completed; password candidates were not tested."

        results: dict[str, tuple[str, str]] = {}
        valid_hashes: dict[str, str] = {}

        for username, nt_hash in user_hashes.items():
            if is_valid_nt_hash(nt_hash):
                valid_hashes[username] = nt_hash
                results[username] = ("Not in wordlist", "No match")
            else:
                results[username] = (
                    "Error",
                    "Invalid NT hash format; account not evaluated",
                )

        candidates = _load_candidates(wordlist_path)

        if not candidates:
            for username in valid_hashes:
                results[username] = (
                    "Error",
                    "Wordlist is unavailable or empty; account not evaluated",
                )

            rows = [
                WindowsAuditResult(
                    username,
                    state,
                    details,
                    user_hashes[username],
                    "NT Hash (NTLM)"
                    if is_valid_nt_hash(user_hashes[username])
                    else "Unknown",
                )
                for username, (state, details) in results.items()
            ]

            return rows, (
                f"Extracted {len(results)} active accounts, but the wordlist "
                "is unavailable or empty. No accounts were evaluated."
            )

        checked = 0
        matches_found = 0
        audit_stop_reason = None

        total_to_check = (
            min(len(candidates), max_candidates)
            if max_candidates is not None
            else len(candidates)
        )

        next_candidate_at = time.perf_counter()
        interval = 1.0 / rate_limit if rate_limit else None
        last_progress_at = 0.0

        def report_progress(force: bool = False) -> None:
            nonlocal last_progress_at

            if progress_callback is None:
                return

            now = time.perf_counter()

            if force or now - last_progress_at >= 0.35:
                last_progress_at = now
                progress_callback(
                    len(user_hashes),
                    len(user_hashes),
                    "SAM accounts",
                    checked,
                    total_to_check,
                )

        if valid_hashes:
            for word in candidates:
                audit_stop_reason = stop_reason(checked)
                if audit_stop_reason is not None:
                    break

                # Rate limit is cancellation-aware.
                if interval is not None:
                    while True:
                        audit_stop_reason = stop_reason(checked)
                        if audit_stop_reason is not None:
                            break

                        remaining = next_candidate_at - time.perf_counter()
                        if remaining <= 0:
                            break

                        stop_event.wait(min(remaining, 0.1))

                    if audit_stop_reason is not None:
                        break

                checked += 1

                candidate_hash = _ntlm_hash(word)

                for username, nt_hash in list(valid_hashes.items()):
                    if candidate_hash == nt_hash:
                        results[username] = (
                            "Weak",
                            mask_password(word),
                        )
                        del valid_hashes[username]
                        matches_found += 1

                        if stop_on_first_match:
                            audit_stop_reason = "Stopped after first match"
                            break

                report_progress()

                if audit_stop_reason is not None:
                    break

                if not valid_hashes:
                    # Every valid account hash has been matched.
                    break

                if interval is not None:
                    next_candidate_at += interval

        # Do not report a limit as an interruption when the wordlist was
        # fully consumed or every valid account hash was already matched.
        if (
            audit_stop_reason is None
            and valid_hashes
            and checked < len(candidates)
        ):
            audit_stop_reason = stop_reason(checked)

        # A stopped or limited audit must not label untested accounts
        # as "Not in wordlist".
        if audit_stop_reason is not None:
            for username in valid_hashes:
                results[username] = (
                    "Not audited",
                    audit_stop_reason,
                )

        rows = [
            WindowsAuditResult(
                username,
                state,
                details,
                user_hashes[username],
                "NT Hash (NTLM)"
                if is_valid_nt_hash(user_hashes[username])
                else "Unknown",
            )
            for username, (state, details) in results.items()
        ]

        weak_count = sum(
            1 for row in rows if row.state == "Weak"
        )
        invalid_count = sum(
            not is_valid_nt_hash(row.hash_value)
            for row in rows
        )
        elapsed = time.perf_counter() - started_at

        if progress_callback is not None:
            report_progress(force=True)

        if audit_stop_reason is not None:
            summary = (
                f"Audit stopped: {audit_stop_reason}. "
                f"Extracted {len(rows)} active accounts, "
                f"checked {checked:,} candidates, "
                f"found {weak_count} weak passwords "
                f"in {elapsed:.1f} seconds."
            )
        else:
            summary = (
                f"Extracted {len(rows)} active accounts and "
                f"checked {checked:,} candidates. "
                f"Found {weak_count} weak passwords "
                f"in {elapsed:.1f} seconds."
            )

        if invalid_count:
            summary += (
                f" {invalid_count} invalid NT hash formats "
                "were not evaluated."
            )

        return rows, summary

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def audit_windows_report(
    wordlist_path: str | Path = WORDLIST_PATH,
    progress_callback: ProgressCallback | None = None,
    *,
    max_candidates: int | None = None,
    max_duration_seconds: float | None = None,
    rate_limit: float | None = None,
    stop_event: threading.Event | None = None,
    stop_on_first_match: bool = False,
) -> tuple[list[tuple[str, str, str]], str]:
    """Preserve the legacy three-column result interface used by the CLI."""

    results, summary = audit_windows_detailed_report(
        wordlist_path,
        progress_callback,
        max_candidates=max_candidates,
        max_duration_seconds=max_duration_seconds,
        rate_limit=rate_limit,
        stop_event=stop_event,
        stop_on_first_match=stop_on_first_match,
    )

    return [
        (result.username, result.state, result.details)
        for result in results
    ], summary
