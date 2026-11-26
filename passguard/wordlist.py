"""Wordlist loading and common-password membership helpers."""
from pathlib import Path
from .config import WORDLIST_PATH

def load_wordlist_candidates(
    path: str | Path = WORDLIST_PATH
) -> list[str]:
    """Load candidate spellings used for password-list membership checks."""
    wordlist_path = Path(path)

    with wordlist_path.open("r", encoding="utf-8-sig") as wordlist_file:
        return [
            line.strip()
            for line in wordlist_file
            if line.strip()
        ]


def load_wordlist(path: str | Path = WORDLIST_PATH) -> set[str]:
    """Load normalized candidates for fast, case-insensitive membership checks."""
    return {
        candidate.casefold()
        for candidate in load_wordlist_candidates(path)
    }


def is_common_password(password: str, wordlist: set[str]) -> bool:
    """Check a password without storing or logging the supplied value."""
    return password.strip().casefold() in wordlist
def _load_candidates(path: str | Path = WORDLIST_PATH):
    if not Path(path).is_file():
        return []

    return [
        word.strip()
        for word in load_wordlist_candidates(path)
        if word.strip()
    ]
