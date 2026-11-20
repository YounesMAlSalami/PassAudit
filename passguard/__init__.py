"""
PassGuard — أداة تدقيق وفحص سلامة كلمات المرور
=============================================

وحدة Python لتدقيق كلمات مرور الحسابات المحلية (Linux /etc/shadow و
Windows NTLM/SAM) ومقارنتها بقوائم الكلمات الشائعة، مع واجهة رسومية
موحّدة بثلاثة تبويبات:
  1. فاحص كلمات المرور (تحليل لحظي + إنتروبيا + وقت الكسر).
  2. تدقيق الحسابات (Linux تلقائي + Windows اختيار ملف).
  3. مولّد كلمات مرور قوية.

الاستخدام كحزمة:
    from passguard.gui import launch_gui
    launch_gui()
"""

__version__ = "3.1.0"
__author__ = "Blue Team — SOC Intern Project"

from .hash_utils import (
    compute_ntlm,
    md4_hex,
    parse_unix_hash_field,
    verify_unix_password,
    verify_unix_hash,
    can_verify_algo,
    get_hash_backend,
    BACKEND_INFO,
    mask_password,
    normalize_password,
)
from .wordlist_loader import (
    iter_wordlist,
    load_wordlist_set,
    wordlist_stats,
)
from .reporter import Finding, AuditReport, to_json, to_csv, to_html
from .linux_auditor import audit_linux_shadow
from .windows_auditor import (
    audit_windows_hashes, audit_windows_sam_direct,
    audit_windows_sam_from_files, parse_hash_file,
)
from .password_analyzer import (
    analyze_password,
    compute_entropy,
    compute_combinations,
    estimate_crack_time,
    entropy_to_level,
    hack_probability,
    LEVEL_LABELS_AR,
    LEVEL_COLORS,
    Pattern,
    detect_patterns,
    classify_guessability,
    classify_pattern_risk,
    classify_dictionary_exposure,
    compute_guess_resistance,
    is_zxcvbn_available,
    classify_interactive_password,
    GUESSABILITY_LABELS_AR,
    GUESSABILITY_COLORS,
    PATTERN_RISK_LABELS_AR,
    PATTERN_RISK_COLORS,
    DICTIONARY_EXPOSURE_LABELS_AR,
    DICTIONARY_EXPOSURE_COLORS,
)
from .password_generator import (
    generate_password,
    generate_passphrase,
    generate_passphrase_detailed,
    load_diceware_wordlist,
    passphrase_entropy_bits,
    PassphraseResult,
)
from .wordlist_manager import WordlistEntry, WordlistManager
from .password_policy_auditor import (
    PolicyFinding, PolicyReport,
    audit_linux_password_policy, audit_windows_password_policy,
)
from .risk_engine import (
    RiskFinding, RiskAssessment,
    assess_risk, assess_password_analysis,
    assess_audit_report, assess_policy_report,
    CATEGORIES, SEVERITIES, CONFIDENCES, WEAK_HASH_ALGOS,
)
from .audit_history import AuditHistory
from .sam_reader import (
    read_sam_hashes, read_sam_hashes_from_files,
    save_registry_hive, is_windows, is_admin,
    hashes_to_pwdump, RegistryHive,
)
def launch_gui(wordlist_path=None):
    """Lazy-load Tkinter GUI so core and CLI imports do not require Tkinter."""
    from .gui import launch_gui as _launch_gui
    return _launch_gui(wordlist_path=wordlist_path)

__all__ = [
    "compute_ntlm", "md4_hex", "parse_unix_hash_field",
    "verify_unix_password", "verify_unix_hash",
    "can_verify_algo", "get_hash_backend", "BACKEND_INFO",
    "mask_password", "normalize_password",
    "iter_wordlist", "load_wordlist_set", "wordlist_stats",
    "Finding", "AuditReport", "to_json", "to_csv", "to_html",
    "audit_linux_shadow", "audit_windows_hashes",
    "audit_windows_sam_direct", "audit_windows_sam_from_files",
    "parse_hash_file",
    "analyze_password", "compute_entropy", "compute_combinations",
    "estimate_crack_time", "entropy_to_level", "hack_probability",
    "LEVEL_LABELS_AR", "LEVEL_COLORS",
    "Pattern", "detect_patterns",
    "classify_guessability", "classify_pattern_risk",
    "classify_dictionary_exposure", "compute_guess_resistance",
    "is_zxcvbn_available",
    "classify_interactive_password",
    "GUESSABILITY_LABELS_AR", "GUESSABILITY_COLORS",
    "PATTERN_RISK_LABELS_AR", "PATTERN_RISK_COLORS",
    "DICTIONARY_EXPOSURE_LABELS_AR", "DICTIONARY_EXPOSURE_COLORS",
    "generate_password", "generate_passphrase",
    "generate_passphrase_detailed", "load_diceware_wordlist",
    "passphrase_entropy_bits", "PassphraseResult",
    "WordlistEntry", "WordlistManager",
    "PolicyFinding", "PolicyReport",
    "audit_linux_password_policy", "audit_windows_password_policy",
    "RiskFinding", "RiskAssessment",
    "assess_risk", "assess_password_analysis",
    "assess_audit_report", "assess_policy_report",
    "CATEGORIES", "SEVERITIES", "CONFIDENCES", "WEAK_HASH_ALGOS",
    "AuditHistory",
    "read_sam_hashes", "read_sam_hashes_from_files",
    "save_registry_hive", "is_windows", "is_admin",
    "hashes_to_pwdump", "RegistryHive",
    "launch_gui",
    "__version__",
]
