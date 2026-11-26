"""PassGuard modular password auditing application."""
from .config import WORDLIST_PATH
from .wordlist import load_wordlist_candidates, load_wordlist, is_common_password
from .password_utils import (
    assess_password_strength, generate_strong_password, detect_linux_hash_algorithm,
    mask_hash, mask_password,
)
from .linux_auditor import audit_linux_shadow
from .windows_auditor import audit_windows_report, extract_windows_ntlm_hashes
from .gui import PasswordAuditorApp

__all__ = [
    "WORDLIST_PATH", "load_wordlist_candidates", "load_wordlist",
    "is_common_password", "assess_password_strength",
    "generate_strong_password", "detect_linux_hash_algorithm",
    "mask_hash", "mask_password", "audit_linux_shadow",
    "audit_windows_report", "extract_windows_ntlm_hashes",
    "PasswordAuditorApp",
]
