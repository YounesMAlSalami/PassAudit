"""Project paths and application configuration."""
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORDLIST_PATH = PROJECT_ROOT / "wordlists" / "wordlist.txt"
REPORTS_DIR = PROJECT_ROOT / "reports"
AUDIT_HISTORY_DB = REPORTS_DIR / "audit_history.sqlite3"
