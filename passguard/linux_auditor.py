
"""Linux /etc/shadow audit helpers."""
from __future__ import annotations

import os
import time
import ctypes
import ctypes.util
import hmac
import threading

from pathlib import Path
from typing import Callable

from .config import WORDLIST_PATH
from .wordlist import load_wordlist_candidates
from .password_utils import mask_password


# Native crypt library cache
_native_crypt_library = None
_native_crypt = None


def _get_native_crypt():
    """Load the system crypt function once."""
    global _native_crypt_library, _native_crypt

    if _native_crypt is None:
        library_name = ctypes.util.find_library("crypt")

        if not library_name:
            library_name = "libcrypt.so.1"

        _native_crypt_library = ctypes.CDLL(library_name)
        _native_crypt = _native_crypt_library.crypt

        _native_crypt.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        _native_crypt.restype = ctypes.c_char_p

    return _native_crypt


def _verify_yescrypt_native(
    password: str | bytes,
    stored_hash: str | bytes,
) -> bool:
    """Verify a yescrypt hash using native system libcrypt."""

    native_crypt = _get_native_crypt()

    if isinstance(password, str):
        password = password.encode("utf-8")

    if isinstance(stored_hash, str):
        stored_hash = stored_hash.encode("ascii")

    result = native_crypt(password, stored_hash)

    if not result or result.startswith(b"*"):
        raise RuntimeError(
            "Native libcrypt failed to verify yescrypt hash"
        )

    return hmac.compare_digest(result, stored_hash)


def audit_linux_shadow(
    wordlist_path: str | Path = WORDLIST_PATH,
    progress_callback: Callable[
        [int, int, str, int, int], None
    ] | None = None,
    *,
    max_candidates: int | None = None,
    max_duration_seconds: float | None = None,
    rate_limit: float | None = None,
    stop_event: threading.Event | None = None,
    stop_on_first_match: bool = False,
) -> tuple[list[tuple[str, str, str]], str]:
    """
    Audit Linux password hashes.

    Limits:
        max_candidates:
            Maximum total candidates tested during this audit.

        max_duration_seconds:
            Maximum duration for the audit.

        rate_limit:
            Maximum candidate rate per second.

        stop_event:
            Event set by the GUI when the user presses Stop.

        stop_on_first_match:
            Stop the entire audit after the first password match.
    """

    shadow_path = "/etc/shadow"

    if stop_event is None:
        stop_event = threading.Event()

    # Validate optional limits
    if max_candidates is not None:
        max_candidates = max(1, int(max_candidates))

    if max_duration_seconds is not None:
        max_duration_seconds = max(
            0.1,
            float(max_duration_seconds),
        )

    if rate_limit is not None:
        rate_limit = max(0.1, float(rate_limit))

    # Check access to /etc/shadow
    if not os.access(shadow_path, os.R_OK):
        return [], (
            "Failed: /etc/shadow cannot be read. "
            "Run the tool with administrator privileges (sudo)."
        )

    # Load candidates
    wordlist = load_wordlist_candidates(wordlist_path)

    if not wordlist:
        return [], "The wordlist is empty."

    # Initialize Passlib for traditional hash schemes
    try:
        from passlib.context import CryptContext

        ctx = CryptContext(
            schemes=[
                "sha512_crypt",
                "sha256_crypt",
                "md5_crypt",
                "des_crypt",
            ]
        )

    except ImportError:
        ctx = None

    # Read accounts from /etc/shadow
    users = []

    with open(
        shadow_path,
        "r",
        encoding="utf-8",
        errors="ignore",
    ) as shadow_file:

        for line in shadow_file:
            parts = line.strip().split(":")

            if len(parts) < 2:
                continue

            username = parts[0]
            stored_hash = parts[1]

            # Skip locked accounts and accounts without usable hashes
            if (
                not stored_hash
                or stored_hash.startswith("!")
                or stored_hash.startswith("*")
                or stored_hash == "x"
            ):
                continue

            users.append((username, stored_hash))

    if not users:
        return [], "No accounts were found."

    found = []

    checked_words = 0
    unsupported = 0
    failed_accounts = 0

    started_at = time.perf_counter()
    last_progress_at = 0.0
    next_candidate_at = started_at

    stop_reason = None
    current_account_index = 0
    current_username = ""

    def elapsed_seconds() -> float:
        return time.perf_counter() - started_at

    def should_stop() -> str | None:
        """Return a stop reason if a limit has been reached."""

        if stop_event.is_set():
            return "Stopped by user"

        if (
            max_candidates is not None
            and checked_words >= max_candidates
        ):
            return "Maximum candidate limit reached"

        if (
            max_duration_seconds is not None
            and elapsed_seconds() >= max_duration_seconds
        ):
            return "Maximum duration reached"

        return None

    def send_progress(
        account_index: int,
        username: str,
        checked: int,
        total_candidates: int,
        force: bool = False,
    ) -> None:
        """Send progress updates at a controlled interval."""

        nonlocal last_progress_at

        if progress_callback is None:
            return

        now = time.perf_counter()

        if force or now - last_progress_at >= 0.35:
            last_progress_at = now

            progress_callback(
                account_index,
                len(users),
                username,
                checked,
                total_candidates,
            )

    def wait_for_rate_limit() -> bool:
        """
        Apply rate limiting without blocking cancellation.

        Returns False if the audit should stop.
        """

        nonlocal next_candidate_at

        if rate_limit is None:
            return should_stop() is None

        interval = 1.0 / rate_limit
        next_candidate_at += interval

        while True:
            reason = should_stop()

            if reason is not None:
                return False

            now = time.perf_counter()
            remaining = next_candidate_at - now

            if remaining <= 0:
                return True

            # Event.wait allows prompt cancellation during the delay.
            stop_event.wait(min(remaining, 0.1))

    # Audit each account
    for account_index, (username, full_hash) in enumerate(
        users,
        start=1,
    ):
        current_account_index = account_index
        current_username = username

        matched = None
        account_candidates_checked = 0
        verification_error = None

        send_progress(
            account_index,
            username,
            0,
            len(wordlist),
            force=True,
        )

        # Yescrypt hashes
        if full_hash.startswith("$y$"):

            for candidate_index, word in enumerate(
                wordlist,
                start=1,
            ):
                stop_reason = should_stop()

                if stop_reason is not None:
                    break

                if not wait_for_rate_limit():
                    stop_reason = should_stop() or "Audit stopped"
                    break

                checked_words += 1
                account_candidates_checked = candidate_index

                try:
                    if _verify_yescrypt_native(
                        word,
                        full_hash,
                    ):
                        matched = word
                        break

                except Exception as error:
                    verification_error = (
                        "Yescrypt verification failed: "
                        f"{error}"
                    )
                    break

                send_progress(
                    account_index,
                    username,
                    account_candidates_checked,
                    len(wordlist),
                )

        # Traditional Linux hash schemes
        else:

            if ctx is None:
                unsupported += 1

                found.append(
                    (
                        username,
                        "Unsupported",
                        "Passlib is unavailable",
                    )
                )

                send_progress(
                    account_index,
                    username,
                    0,
                    len(wordlist),
                    force=True,
                )

                continue

            for candidate_index, word in enumerate(
                wordlist,
                start=1,
            ):
                stop_reason = should_stop()

                if stop_reason is not None:
                    break

                if not wait_for_rate_limit():
                    stop_reason = should_stop() or "Audit stopped"
                    break

                checked_words += 1
                account_candidates_checked = candidate_index

                try:
                    if ctx.verify(
                        word,
                        full_hash,
                    ):
                        matched = word
                        break

                except Exception as error:
                    verification_error = (
                        "Password hash verification failed: "
                        f"{error}"
                    )
                    break

                send_progress(
                    account_index,
                    username,
                    account_candidates_checked,
                    len(wordlist),
                )

        # Record account result
        if verification_error is not None:

            failed_accounts += 1

            found.append(
                (
                    username,
                    "Error",
                    verification_error,
                )
            )

        elif matched is not None:

            found.append(
                (
                    username,
                    "Weak",
                    mask_password(matched),
                )
            )

            if stop_on_first_match:
                stop_reason = "Stopped after first match"

        elif stop_reason is not None:

            found.append(
                (
                    username,
                    "Stopped",
                    stop_reason,
                )
            )

        else:

            found.append(
                (
                    username,
                    "Not in the list",
                    "No match",
                )
            )

        send_progress(
            account_index,
            username,
            account_candidates_checked,
            len(wordlist),
            force=True,
        )

        # Stop the entire audit if requested or limited
        if stop_reason is not None:
            break

    # Mark accounts that were not audited
    if stop_reason is not None:
        completed_usernames = {
            username
            for username, _, _ in found
        }

        for username, _ in users:
            if username not in completed_usernames:
                found.append(
                    (
                        username,
                        "Not audited",
                        stop_reason,
                    )
                )

    elapsed = elapsed_seconds()

    successfully_processed = (
        len(users)
        - unsupported
        - failed_accounts
    )

    if stop_reason is not None:
        summary = (
            f"Audit stopped: {stop_reason}. "
            f"Processed {successfully_processed} accounts, "
            f"{unsupported} unsupported, "
            f"{failed_accounts} failed. "
            f"Tested {checked_words:,} candidates "
            f"in {elapsed:.1f} seconds."
        )

    else:
        summary = (
            f"Processed {successfully_processed} accounts, "
            f"{unsupported} unsupported, "
            f"{failed_accounts} failed. "
            f"Tested {checked_words:,} candidates "
            f"in {elapsed:.1f} seconds."
        )

    return found, summary
