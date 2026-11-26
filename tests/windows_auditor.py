"""Windows local SAM auditing helpers. Use only on systems you administer."""
from __future__ import annotations
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

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

def _ntlm_hash(password: str) -> str:
    from Crypto.Hash import MD4

    return MD4.new(
        password.encode("utf-16-le")
    ).hexdigest().upper()


def _backup_sam_hives(
    temp_dir: str
) -> tuple[str | None, str | None]:

    sam_path = os.path.join(temp_dir, "SAM")
    system_path = os.path.join(temp_dir, "SYSTEM")

    for hive, target in (
        ("hklm\\sam", sam_path),
        ("hklm\\system", system_path)
    ):
        result = subprocess.run(
            ["reg", "save", hive, target, "/y"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

        if result.returncode != 0:
            message = (
                result.stderr or result.stdout or ""
            ).strip()

            return (
                None,
                message or "Failed to export the Windows registry hive"
            )

    return sam_path, system_path


def extract_windows_ntlm_hashes(
    sam_path: str,
    system_path: str
) -> dict[str, str]:

    hashes: dict[str, str] = {}

    try:
        from pypykatz.registry.offline_parser import OffineRegistry

        registry = OffineRegistry.from_files(
            system_path,
            sam_path
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
    wordlist_path: str | Path = WORDLIST_PATH
) -> tuple[list[WindowsAuditResult], str]:

    if sys.platform != "win32":
        return [], "This audit is available on Windows only."

    temp_dir = tempfile.mkdtemp(prefix="pwaudit_")

    try:
        sam_path, system_path = _backup_sam_hives(temp_dir)

        if sam_path is None:
            return [], (
                f"Registry backup failed: "
                f"{system_path or 'Unknown reason'}"
            )

        try:
            user_hashes = extract_windows_ntlm_hashes(
                sam_path,
                system_path
            )

        except RuntimeError as error:
            return [], str(error)

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

        if valid_hashes:
            for word in candidates:
                checked += 1

                candidate_hash = _ntlm_hash(word)

                for username, nt_hash in list(valid_hashes.items()):

                    if candidate_hash == nt_hash:
                        results[username] = (
                            "Weak",
                            mask_password(word)
                        )

                        del valid_hashes[username]

                if not valid_hashes:
                    break

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
            1
            for row in rows
            if row.state == "Weak"
        )
        invalid_count = sum(
            not is_valid_nt_hash(row.hash_value)
            for row in rows
        )

        summary = (
            f"Extracted {len(results)} active accounts and "
            f"checked {checked} candidates. "
            f"Found {weak_count} weak passwords."
        )
        if invalid_count:
            summary += (
                f" {invalid_count} invalid NT hash formats were not evaluated."
            )

        return rows, summary

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def audit_windows_report(
    wordlist_path: str | Path = WORDLIST_PATH
) -> tuple[list[tuple[str, str, str]], str]:
    """Preserve the legacy three-column result interface used by the CLI."""
    results, summary = audit_windows_detailed_report(wordlist_path)
    return [
        (result.username, result.state, result.details)
        for result in results
    ], summary
