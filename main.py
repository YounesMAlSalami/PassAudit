#!/usr/bin/env python3
"""
PassGuard — نقطة الدخول الرئيسية
=================================

الاستخدام الافتراضي (تشغيل الواجهة الرسومية):
    python3 main.py
    python3 main.py --wordlist wordlists/wordlist.txt

أوامر CLI للمستخدمين المتقدّمين (تشغيل بدون واجهة رسومية):
    python3 main.py audit-linux   [--wordlist PATH] [--out DIR]
    python3 main.py audit-windows --hashes FILE [--wordlist PATH] [--out DIR]
    python3 main.py check         [--wordlist PATH]
    python3 main.py generate      [--length N] [--no-symbols]
    python3 main.py wordlist-stats [--wordlist PATH]

أمثلة:
    # الواجهة الرسومية (الافتراضية):
    python3 main.py

    # تدقيق Linux (يتطلب sudo):
    sudo python3 main.py audit-linux

    # تدقيق Windows (مع ملف تجزئات مُستخرَج):
    python3 main.py audit-windows --hashes hashes.txt

    # فحص كلمة مرور واحدة (CLI):
    python3 main.py check

    # توليد كلمة مرور قوية:
    python3 main.py generate --length 20
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import time
from typing import Optional

# السماح بالتشغيل كـ python main.py أو python -m passguard.main
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, os.path.dirname(_HERE))

from passguard import (  # noqa: E402
    audit_linux_shadow,
    audit_windows_hashes,
    audit_windows_sam_direct,
    audit_windows_sam_from_files,
    launch_gui,
    analyze_password,
    generate_password,
    generate_passphrase,
    to_csv,
    to_html,
    to_json,
    wordlist_stats,
    classify_interactive_password,
)


# ===========================================================================
# تحديد مسار ملف القائمة الافتراضي
# ===========================================================================

def _default_wordlist() -> str:
    """تحديد مسار ملف القائمة الافتراضي نسبياً لموقع السكربت."""
    candidates = [
        os.path.join(_HERE, "wordlists", "wordlist.txt"),
        os.path.join(os.getcwd(), "wordlists", "wordlist.txt"),
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return candidates[0]   # يُرجع المسار المتوقّع حتى لو لم يكن موجوداً


# ===========================================================================
# التشغيل الافتراضي: الواجهة الرسومية
# ===========================================================================

def cmd_gui(args: argparse.Namespace) -> int:
    """إطلاق الواجهة الرسومية الموحّدة."""
    wordlist = args.wordlist or _default_wordlist()
    print("[PassGuard] Launching the graphical interface...")
    print(f"[PassGuard] Wordlist: {wordlist}")
    try:
        launch_gui(wordlist_path=wordlist)
    except Exception as e:
        sys.stderr.write(f"\n[Error] Could not launch the interface: {e}\n")
        sys.stderr.write("Install GUI dependencies with: pip install -r requirements-gui.txt\n")
        return 3
    return 0


# ===========================================================================
# أوامر CLI المتقدّمة
# ===========================================================================

def cmd_audit_linux(args: argparse.Namespace) -> int:
    """تدقيق Linux من /etc/shadow تلقائياً."""
    out_dir = args.out or "reports"
    os.makedirs(out_dir, exist_ok=True)
    wordlist = args.wordlist or _default_wordlist()

    def progress(msg, d, t):
        if t:
            sys.stderr.write(f"\r[progress] {msg}  ({d}/{t})    ")
        else:
            sys.stderr.write(f"\r[progress] {msg}    ")
        sys.stderr.flush()

    try:
        # القراءة تلقائياً من /etc/shadow و /etc/passwd
        report = audit_linux_shadow(
            shadow_path="/etc/shadow",
            passwd_path="/etc/passwd",
            wordlist_path=wordlist,
            min_uid=args.min_uid,
            skip_system_accounts=not args.include_system,
            case_fold=args.case_fold,
            workers=args.workers,
            progress_cb=progress if not args.quiet else None,
        )
    except PermissionError as e:
        sys.stderr.write(f"\n[Permission error] {e}\n")
        sys.stderr.write("Run the tool as root: sudo python3 main.py audit-linux\n")
        return 2
    except FileNotFoundError as e:
        sys.stderr.write(f"\n[File error] {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"\n[Unexpected error] {e}\n")
        return 3

    sys.stderr.write("\n")
    base = os.path.join(out_dir, f"linux_audit_{int(time.time())}")
    json_p = to_json(report, base + ".json")
    csv_p = to_csv(report, base + ".csv")
    html_p = to_html(report, base + ".html")

    _print_summary(report, [json_p, csv_p, html_p])
    if report.accounts_weak > 0:
        return 1
    if report.accounts_not_assessed > 0:
        return 5
    return 0


def cmd_audit_windows(args: argparse.Namespace) -> int:
    """تدقيق ملف تجزئات NTLM."""
    out_dir = args.out or "reports"
    os.makedirs(out_dir, exist_ok=True)
    wordlist = args.wordlist or _default_wordlist()

    def progress(msg, d, t):
        if t:
            sys.stderr.write(f"\r[progress] {msg}  ({d}/{t})    ")
        else:
            sys.stderr.write(f"\r[progress] {msg}    ")
        sys.stderr.flush()

    try:
        report = audit_windows_hashes(
            hash_file_path=os.path.abspath(args.hashes),
            wordlist_path=wordlist,
            case_fold=args.case_fold,
            workers=args.workers,
            progress_cb=progress if not args.quiet else None,
        )
    except FileNotFoundError as e:
        sys.stderr.write(f"\n[File error] {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"\n[Unexpected error] {e}\n")
        return 3

    sys.stderr.write("\n")
    base = os.path.join(out_dir, f"windows_audit_{int(time.time())}")
    json_p = to_json(report, base + ".json")
    csv_p = to_csv(report, base + ".csv")
    html_p = to_html(report, base + ".html")

    _print_summary(report, [json_p, csv_p, html_p])
    return 1 if report.accounts_weak > 0 else 0


def cmd_audit_windows_sam(args: argparse.Namespace) -> int:
    """تدقيق SAM مباشرة (قراءة مباشرة أو من ملفات خلايا مُصدَّرة)."""
    out_dir = args.out or "reports"
    os.makedirs(out_dir, exist_ok=True)
    wordlist = args.wordlist or _default_wordlist()

    def progress(msg, d, t):
        if t:
            sys.stderr.write(f"\r[progress] {msg}  ({d}/{t})    ")
        else:
            sys.stderr.write(f"\r[progress] {msg}    ")
        sys.stderr.flush()

    try:
        if bool(args.sam) != bool(args.system):
            sys.stderr.write("[Invalid input] --sam and --system must be provided together.\n")
            return 4
        if args.sam and args.system:
            # من ملفات خلايا مُصدَّرة
            sys.stderr.write("[PassGuard] Auditing SAM from exported hive files...\n")
            report = audit_windows_sam_from_files(
                sam_path=os.path.abspath(args.sam),
                system_path=os.path.abspath(args.system),
                wordlist_path=wordlist,
                case_fold=args.case_fold,
                workers=args.workers,
                progress_cb=progress if not args.quiet else None,
            )
        else:
            # قراءة مباشرة من النظام الحيّ (Windows + admin)
            sys.stderr.write("[PassGuard] Reading SAM directly (RegSaveKeyEx)...\n")
            report = audit_windows_sam_direct(
                wordlist_path=wordlist,
                case_fold=args.case_fold,
                workers=args.workers,
                progress_cb=progress if not args.quiet else None,
            )
    except RuntimeError as e:
        sys.stderr.write(f"\n[Error] {e}\n")
        return 3
    except PermissionError as e:
        sys.stderr.write(f"\n[Permission error] {e}\n")
        return 2
    except FileNotFoundError as e:
        sys.stderr.write(f"\n[File error] {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"\n[Unexpected error] {e}\n")
        return 3

    sys.stderr.write("\n")
    base = os.path.join(out_dir, f"windows_sam_audit_{int(time.time())}")
    json_p = to_json(report, base + ".json")
    csv_p = to_csv(report, base + ".csv")
    html_p = to_html(report, base + ".html")

    _print_summary(report, [json_p, csv_p, html_p])
    if report.accounts_weak > 0:
        return 1
    if report.accounts_not_assessed > 0:
        return 5
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """فحص كلمة مرور واحدة عبر CLI (إدخال مُخفّى)."""
    from passguard.wordlist_loader import load_wordlist_set
    wordlist = args.wordlist or _default_wordlist()
    wl_set = None
    if os.path.exists(wordlist):
        wl_set = load_wordlist_set(wordlist, case_fold=not args.case_sensitive)

    pw = getpass.getpass("Enter the suggested password to check: ")
    in_wl = False
    if wl_set is not None:
        in_wl = pw.casefold() in wl_set if not args.case_sensitive else pw in wl_set

    analysis = analyze_password(pw, in_wordlist=in_wl)
    category = classify_interactive_password(
        analysis,
        wordlist_checked=wl_set is not None,
    )
    print(f"Result: {category}")
    _print_cli_analysis(analysis)

    # مسح كلمة المرور من الذاكرة
    del pw
    import gc
    gc.collect()

    if wl_set is None:
        return 5
    if in_wl or analysis.level in ("very_weak", "weak"):
        return 1
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    """توليد وطباعة كلمة مرور قوية."""
    try:
        if args.passphrase:
            pw = generate_passphrase(num_words=args.length // 3 or 4,
                                     separator=args.separator)
        else:
            pw = generate_password(
                length=args.length,
                use_upper=not args.no_upper,
                use_lower=not args.no_lower,
                use_digits=not args.no_digits,
                use_symbols=not args.no_symbols,
                avoid_ambiguous=args.avoid_ambiguous,
            )
        print(pw)
        # طباعة تحليل سريع للقوة
        analysis = analyze_password(pw, in_wordlist=False)
        sys.stderr.write(f"[Strength: {_LEVEL_LABELS_EN[analysis.level]} "
                         f"({analysis.score}/100), "
                         f"guessability: {_GUESSABILITY_LABELS_EN.get(analysis.guessability, 'N/A')}, "
                         f"entropy: {analysis.entropy_bits} bits, "
                         f"crack time: {_english_crack_time(analysis.crack_time_text)}]\n")
        return 0
    except Exception as e:
        sys.stderr.write(f"[Error] {e}\n")
        return 1


def cmd_wordlist_stats(args: argparse.Namespace) -> int:
    """عرض إحصائيات ملف القائمة."""
    wordlist = args.wordlist or _default_wordlist()
    if not os.path.exists(wordlist):
        sys.stderr.write(f"[Error] Wordlist file not found: {wordlist}\n")
        return 1
    stats = wordlist_stats(wordlist)
    print("Wordlist statistics:")
    for k, v in stats.items():
        print(f"  {k:18}: {v}")
    return 0


_LEVEL_LABELS_EN = {
    "very_weak": "Very weak",
    "weak": "Weak",
    "medium": "Moderate",
    "strong": "Strong",
    "very_strong": "Very strong",
    "excellent": "Excellent",
}

_GUESSABILITY_LABELS_EN = {
    "trivial": "Trivial (cracked instantly)",
    "low": "Low",
    "moderate": "Moderate",
    "high": "High (hard to guess)",
    "very_high": "Very high",
}

_PATTERN_RISK_LABELS_EN = {
    "none": "None",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_DICTIONARY_EXPOSURE_LABELS_EN = {
    "exposed": "Found in the wordlist",
    "not_exposed": "Not found",
    "not_checked": "Not checked",
}

_SUGGESTIONS_EN = {
    "⚠️ كلمة المرور مُدرجة في قائمة التسريبات — غيّرها فوراً.":
        "⚠️ This password appears in a breach list. Change it immediately.",
    "استخدم 12 حرفاً على الأقل (16+ مُفضّل).":
        "Use at least 12 characters (16+ is recommended).",
    "أضف أحرفاً كبيرة (A-Z).": "Add uppercase letters (A-Z).",
    "أضف أحرفاً صغيرة (a-z).": "Add lowercase letters (a-z).",
    "أضف أرقاماً (0-9).": "Add digits (0-9).",
    "أضف رموزاً (!@#$%^&*).": "Add symbols (!@#$%^&*).",
    "تجنّب تكرار نفس الحرف أكثر من مرّتين متتاليتين.":
        "Avoid repeating the same character more than twice in a row.",
    "تجنّب التسلسلات الرقمية المتتالية (1234, 9876).":
        "Avoid consecutive number sequences (1234, 9876).",
    "تجنّب التسلسلات الأبجدية (abcd, dcba).":
        "Avoid alphabetical sequences (abcd, dcba).",
    "تجنّب أنماط لوحة المفاتيح (qwerty, asdfgh, zxcvbn, 1234).":
        "Avoid keyboard patterns (qwerty, asdfgh, zxcvbn, 1234).",
    "تجنّب البدء بكلمات قاموسية شائعة.":
        "Avoid starting with common dictionary words.",
    "تجنّب إلحاق أرقام/رموز متوقّعة بنهاية كلمة قاموسية.":
        "Avoid appending predictable numbers or symbols to a dictionary word.",
    "تجنّب استخدام السنوات (تواريح الميلاد، أحداث).":
        "Avoid using years (birth years, events).",
    "تجنّب استخدام التواريخ في كلمات المرور.":
        "Avoid using dates in passwords.",
    "تجنّب تكرار نفس المقطع (abcabc, passpass).":
        "Avoid repeating the same substring (abcabc, passpass).",
    "استخدم بنية أقل توقّعاً (أحرف ورموز متداخلة).":
        "Use a less predictable structure (intermix letters and symbols).",
    "وزّع الرموز داخل الكلمة بدلاً من إلحاقها بالنهاية فقط.":
        "Place symbols within the password instead of only appending them.",
    "تجنّب التحويلات القاموسية المتوقّعة (Leet, Capitalize+digits).":
        "Avoid predictable dictionary variations (leet, capitalization + digits).",
    "كلمة مرور قوية. واصل اعتماد هذه السياسة في اختيار كلمات المرور.":
        "Strong password. Continue following this password-selection policy.",
}

_ANALYSIS_NOTES_EN = {
    "التحليل المتقدّم (zxcvbn) غير متاح — النتائج تعتمد على المحلّل "
    "الداخلي. ثبّت zxcvbn لتحسين دقّة قابلية التخمين.":
        "Advanced analysis (zxcvbn) is unavailable. Results use the built-in "
        "analyzer. Install zxcvbn for more accurate guessability estimates.",
    "كلمة المرور لها إنتروبيا نظرية عالية لكنّها مكشوفة في القائمة — "
    "الإنتروبيا النظرية لا تعني أماناً فعلياً.":
        "This password has high theoretical entropy but appears in the "
        "wordlist. Theoretical entropy does not guarantee real-world security.",
    "لم يُفحص التعرّض للقاموس — لا يمكن الجزم بعدم وجود كلمة المرور "
    "في قوائم التسريبات.":
        "Dictionary exposure was not checked, so this password cannot be "
        "confirmed absent from breach lists.",
}


def _english_crack_time(text: str) -> str:
    """Translate the analyzer's localized crack-time string for CLI output."""
    if text == "N/A":
        return text
    if text == "أقل من ثانية":
        return "Less than a second"
    if text == "ملايين السنين":
        return "Millions of years"
    match = re.fullmatch(
        r"([\d.]+)\s*(ثانية|دقيقة|ساعة|يوم|شهر|سنة|قرن|ألف سنة|مليون سنة)",
        text,
    )
    if not match:
        return "Unavailable"
    unit = {
        "ثانية": "seconds",
        "دقيقة": "minutes",
        "ساعة": "hours",
        "يوم": "days",
        "شهر": "months",
        "سنة": "years",
        "قرن": "centuries",
        "ألف سنة": "thousand years",
        "مليون سنة": "million years",
    }[match.group(2)]
    return f"{match.group(1)} {unit}"


def _english_pattern(pattern) -> tuple:
    """Return an English name and explanation for a detected password pattern."""
    pattern_id = pattern.pattern_id
    match = None
    if pattern_id == "repeated_char":
        match = re.search(
            r"الحرف '([^']+)' مكرّر (\d+) مرّات متتالية في الموضع (\d+)",
            pattern.explanation,
        )
        if match:
            char, count, position = match.groups()
            return "Repeated character", (
                f"Character '{char}' is repeated {count} times consecutively "
                f"at position {position}."
            )
    if pattern_id.startswith(("numeric_sequence_", "alpha_sequence_")):
        kind = "Numeric" if pattern_id.startswith("numeric") else "Alphabetical"
        direction = "ascending" if pattern_id.endswith("ascending") else "descending"
        match = re.search(r"'([^']+)'", pattern.explanation)
        sequence = match.group(1) if match else "sequence"
        return f"{kind} sequence ({direction})", (
            f"The {kind.lower()} sequence '{sequence}' is {direction} and predictable."
        )
    if pattern_id == "keyboard_sequence":
        match = re.search(r"'([^']+)'", pattern.explanation)
        fragment = match.group(1) if match else "keyboard pattern"
        return "Keyboard pattern", (
            f"'{fragment}' is a consecutive path on the keyboard."
        )
    if pattern_id in ("common_prefix", "common_suffix"):
        match = re.search(r"'([^']+)'", pattern.explanation)
        value = match.group(1) if match else "common"
        if pattern_id == "common_prefix":
            return "Common prefix", f"The password starts with the common prefix '{value}'."
        return "Common suffix", f"The password ends with the common suffix '{value}'."
    if pattern_id == "year":
        match = re.search(r"'([^']+)'", pattern.explanation)
        year = match.group(1) if match else "year"
        return "Year", f"The year '{year}' appears in the password and is easy to guess."
    if pattern_id == "date_pattern":
        match = re.search(r"'([^']+)'.*\(([^)]+)\)", pattern.explanation)
        if match:
            return "Date pattern", (
                f"'{match.group(1)}' resembles a date ({match.group(2)})."
            )
        return "Date pattern", "A date-like pattern was detected."
    if pattern_id == "repeated_substring":
        match = re.search(r"المقطع '([^']+)' مكرّر (\d+) مرّات", pattern.explanation)
        if match:
            return "Repeated substring", (
                f"Substring '{match.group(1)}' is repeated {match.group(2)} times consecutively."
            )
        return "Repeated substring", "A repeated substring was detected."
    pattern_text = {
        "structure_word_digits": (
            "Word followed by digits",
            "A dictionary word followed by digits is a very common pattern.",
        ),
        "structure_word_symbol": (
            "Word followed by a symbol",
            "A dictionary word followed by one symbol is a common variation (password!).",
        ),
        "structure_capital_word_digits": (
            "Capitalized word followed by digits",
            "A capitalized word followed by digits is a common dictionary variation.",
        ),
    }
    return pattern_text.get(
        pattern_id, ("Detected pattern", "A weak password pattern was detected.")
    )


def _english_suggestion(text: str) -> str:
    translated = _SUGGESTIONS_EN.get(text, text)
    if any("\u0600" <= char <= "\u06ff" for char in translated):
        return "Use a less predictable password."
    return translated


def _english_guess_resistance(analysis) -> str:
    if analysis.dictionary_exposure == "exposed":
        return "Password is exposed in a breach list. Change it immediately."
    if analysis.dictionary_exposure == "not_checked":
        prefix = "Dictionary exposure was not checked. "
    else:
        prefix = ""
    messages = {
        "trivial": "Trivial to guess; it can be cracked immediately.",
        "low": "Low guess resistance; vulnerable to expanded dictionary attacks.",
        "moderate": "Moderate guess resistance; a focused offline attack may crack it.",
        "high": "High guess resistance; difficult for dictionary attacks, but not guaranteed.",
        "very_high": "Very high guess resistance; robust against current attacks.",
    }
    return prefix + messages.get(analysis.guessability, "Not classified.")


def _print_summary(report, paths):
    """طباعة ملخّص التدقيق."""
    print()
    print("=" * 60)
    print(f"  Audit summary — {report.source_platform.upper()}")
    print("=" * 60)
    print(f"  Host:                   {report.hostname}")
    print(f"  Wordlist:               {os.path.basename(report.wordlist_path)} "
          f"({report.wordlist_count} words)")
    print(f"  Hash backend:           {report.hash_backend or 'N/A'}")
    print(f"  Accounts scanned:       {report.accounts_scanned}")
    print(f"  Weak passwords matched: {report.accounts_weak}")
    print(f"  Locked/disabled:        {report.accounts_locked}")
    print(f"  No wordlist match:      {report.accounts_no_match}")
    print(f"  Not assessed:           {report.accounts_not_assessed}")
    print(f"  Processing errors:      {report.error_accounts}")
    print(f"  Duration:               {report.duration_seconds:.2f}s")
    print()
    print("  Generated files:")
    for p in paths:
        print(f"    - {os.path.abspath(p)}")
    print("=" * 60)

    weak = [f for f in report.findings if f.status == "weak"]
    if weak:
        print(f"\n  ⚠️  Accounts with weak passwords ({len(weak)}):")
        for f in weak:
            print(f"    • {f.username:20}  [{f.algorithm}]  "
                  f"matched password: {f.matched_password_masked}")
    not_assessed = [f for f in report.findings if f.status == "not_assessed"]
    if not_assessed:
        print(f"\n  ⚠️  Accounts not assessed ({len(not_assessed)}):")
        for f in not_assessed:
            print(f"    • {f.username:20}  [{f.algorithm}]  {f.notes}")
    print()
    print("  Note: A password not matching the wordlist does not mean it is secure;")
    print("  it only means this wordlist did not identify it.")


def _print_cli_analysis(analysis) -> None:
    """طباعة تحليل كلمة المرور في CLI."""
    level = analysis.level
    label = _LEVEL_LABELS_EN[level]
    guess_label = _GUESSABILITY_LABELS_EN.get(analysis.guessability, "N/A")
    risk_label = _PATTERN_RISK_LABELS_EN.get(analysis.pattern_risk, "N/A")
    dict_label = _DICTIONARY_EXPOSURE_LABELS_EN.get(analysis.dictionary_exposure, "N/A")

    print()
    print("=" * 60)
    print(f"  Result: {label}  ({analysis.score}/100)")
    print(f"  Length: {analysis.password_length} characters")
    print(f"  Theoretical entropy: {analysis.entropy_bits} bits")
    print(f"  Estimated crack time: {_english_crack_time(analysis.crack_time_text)}")
    print(f"  Guessability: {guess_label}")
    print(f"  Pattern risk: {risk_label}")
    print(f"  Dictionary exposure: {dict_label}")
    print(f"  Guess resistance: {_english_guess_resistance(analysis)}")
    if analysis.in_wordlist:
        print("  ⚠️  This password appears in the common-password list. Change it.")
    elif analysis.dictionary_exposure == "not_checked":
        print("  ℹ️  Dictionary exposure was not checked; security cannot be confirmed.")
    else:
        print("  ✅ This password was not found in the common-password list.")
    if analysis.analysis_notes:
        print("  Analysis notes:")
        for n in analysis.analysis_notes:
            print(f"    ℹ️ {_ANALYSIS_NOTES_EN.get(n, 'An analysis note is available.')}")
    classes = []
    if analysis.has_lower:   classes.append("Lowercase")
    if analysis.has_upper:   classes.append("Uppercase")
    if analysis.has_digit:   classes.append("Digits")
    if analysis.has_symbol:  classes.append("Symbols")
    print(f"  Character classes: {', '.join(classes) if classes else 'None'}")
    if analysis.patterns:
        print(f"  Detected patterns ({len(analysis.patterns)}):")
        for p in analysis.patterns:
            name, explanation = _english_pattern(p)
            print(f"    • [{p.risk}] {name}: {explanation}")
    if analysis.suggestions:
        print("  Suggestions:")
        for s in analysis.suggestions:
            print(f"    - {_english_suggestion(s)}")
    print("=" * 60)
    print("Note: Theoretical entropy is not a measure of actual guessability.")
    print("The password was not saved to any file or log.")


# ===========================================================================
# بناء argparse
# ===========================================================================

def build_parser() -> argparse.ArgumentParser:
    # مُحلّل أب مشترك يوفّر --wordlist لكل الأوامر الفرعية وللواجهة الافتراضية
    parent = argparse.ArgumentParser(add_help=False)
    parent.add_argument("--wordlist", default=None,
                        help="Wordlist file path (default: wordlists/wordlist.txt).")

    p = argparse.ArgumentParser(
        prog="passguard",
        description="PassGuard — password auditing and strength-checking tool (Blue Team / SOC).",
        parents=[parent],
    )

    sub = p.add_subparsers(dest="command")

    # الافتراضي: gui (لا أوامر فرعية → نُشغّل الواجهة)

    # ---- audit-linux ----
    pl = sub.add_parser("audit-linux",
                        help="Audit /etc/shadow automatically (requires sudo).",
                        parents=[parent])
    pl.add_argument("--out", "-o", default="reports",
                    help="Output directory for reports.")
    pl.add_argument("--min-uid", type=int, default=1000,
                    help="UID threshold for excluding system accounts (default: 1000).")
    pl.add_argument("--include-system", action="store_true",
                    help="Do not exclude system accounts.")
    pl.add_argument("--case-fold", action="store_true",
                    help="Normalize case when comparing.")
    pl.add_argument("--workers", type=int, default=None,
                    help="Number of multiprocessing workers.")
    pl.add_argument("--quiet", action="store_true",
                    help="Suppress progress messages.")
    pl.set_defaults(func=cmd_audit_linux)

    # ---- audit-windows ----
    pw = sub.add_parser("audit-windows",
                        help="Audit an NTLM hash file (pwdump/secretsdump).",
                        parents=[parent])
    pw.add_argument("--hashes", required=True,
                    help="Hash file (pwdump, user:nt, or NT only).")
    pw.add_argument("--out", "-o", default="reports",
                    help="Output directory.")
    pw.add_argument("--case-fold", action="store_true",
                    help="Normalize case when comparing.")
    pw.add_argument("--workers", type=int, default=None,
                    help="Number of workers.")
    pw.add_argument("--quiet", action="store_true",
                    help="Suppress progress messages.")
    pw.set_defaults(func=cmd_audit_windows)

    # ---- audit-windows-sam (قراءة مباشرة من SAM) ----
    pws = sub.add_parser("audit-windows-sam",
                         help="Audit SAM directly (RegSaveKeyEx) or from exported hives.",
                         parents=[parent])
    pws.add_argument("--sam",
                     help="Exported SAM hive file (with --system).")
    pws.add_argument("--system",
                     help="Exported SYSTEM hive file (with --sam).")
    pws.add_argument("--out", "-o", default="reports",
                     help="Output directory.")
    pws.add_argument("--case-fold", action="store_true",
                     help="Normalize case when comparing.")
    pws.add_argument("--workers", type=int, default=None,
                     help="Number of workers.")
    pws.add_argument("--quiet", action="store_true",
                     help="Suppress progress messages.")
    pws.set_defaults(func=cmd_audit_windows_sam)

    # ---- check ----
    pc = sub.add_parser("check",
                        help="Interactively check a suggested password (hidden input).",
                        parents=[parent])
    pc.add_argument("--case-sensitive", action="store_true",
                    help="Make wordlist checks case-sensitive.")
    pc.set_defaults(func=cmd_check)

    # ---- generate ----
    pg = sub.add_parser("generate", help="Generate and print a strong password.",
                        parents=[parent])
    pg.add_argument("--length", type=int, default=16,
                    help="Length (default: 16).")
    pg.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters.")
    pg.add_argument("--no-lower", action="store_true", help="Exclude lowercase letters.")
    pg.add_argument("--no-digits", action="store_true", help="Exclude digits.")
    pg.add_argument("--no-symbols", action="store_true", help="Exclude symbols.")
    pg.add_argument("--avoid-ambiguous", action="store_true", default=True,
                    help="Exclude ambiguous characters (O/0, l/1).")
    pg.add_argument("--passphrase", action="store_true",
                    help="Generate a passphrase instead of a random password.")
    pg.add_argument("--separator", default="-",
                    help="Passphrase separator (default: '-').")
    pg.set_defaults(func=cmd_generate)

    # ---- wordlist-stats ----
    ps = sub.add_parser("wordlist-stats",
                        help="Show wordlist statistics.",
                        parents=[parent])
    ps.set_defaults(func=cmd_wordlist_stats)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # إذا لم يُحدَّد أمر فرعي → إطلاق الواجهة الرسومية (الافتراضي)
    if not getattr(args, "command", None):
        # بناء namespace بسيط لأمر gui
        if not hasattr(args, "wordlist"):
            args.wordlist = None
        return cmd_gui(args)

    try:
        return args.func(args)
    except KeyboardInterrupt:
        sys.stderr.write("\n[Cancelled] Stopped by user.\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
