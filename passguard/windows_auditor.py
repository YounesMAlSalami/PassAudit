"""
passguard.windows_auditor
=========================

وحدة تدقيق تجزئات NTLM المستخرجة من قاعدة بيانات SAM في Windows.

ملاحظة هامّة عن الاستخراج:
  قراءة SAM مباشرةً من نظام Windows قيد التشغيل غير ممكنة لأنّ الملف
  مُقفل من قبل LSM/SAMSERVICE. الإجراء المعتمد (المُصرّح به في فِرق
  التدقيق) هو استخراج التجزئات بأداة معتمدة مثل impacket's secretsdump:

      secretsdump.py -sam SAM -system SYSTEM LOCAL

  أو تصديرها بصيغة pwdump عبر أدوات مثل fgdump/pwdump8. الأداة هنا
  تأخذ ملف التجزئات المُستخرَج (أحد الصيغ المدعومة أدناه) وتُفحّصه
  ضدّ قائمة الكلمات. لا تحاول الأداة نفسها قراءة SAM حيّ، لأنّ ذلك
  يتطلّب امتيازات SYSTEM وأدوات مستقلة، وهذا فصل صحيح للمسؤوليات.

صيغ الإدخال المدعومة (يتم الكشف التلقائي):
  1. pwdump/secretsdump:  username:RID:LM:NT:::
  2. بسيطة:               username:NT
  3. NTLM فقط:            32-hex
  4. NTLM فقط مع LM:      LM:NT

الأداء:
  تجزئة NTLM غير مملّحة (unsalted)، لذا نُسبق حساب NTLM(word) لكل كلمة
  في القائمة مرة واحدة ونخزّنها في dict، ثم نبحث عن تجزئة كل مستخدم
  في هذا الـ dict بزمن O(1). هذا أسرع بكثير من إعادة الحساب لكل مستخدم.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import re
import socket
import time
from typing import Callable, Dict, List, Optional, Tuple

from .hash_utils import compute_ntlm, mask_password, get_hash_backend
from .reporter import AuditReport, Finding, DEFAULT_SEVERITY
from .wordlist_loader import iter_wordlist, wordlist_stats
from .sam_reader import (
    read_sam_hashes as _read_sam_hashes_direct,
    read_sam_hashes_from_files as _read_sam_hashes_from_files,
    is_windows as _is_windows,
    is_admin as _is_admin,
    hashes_to_pwdump as _hashes_to_pwdump,
)

# نمط تجزئة NT/LM: 32 حرف hex
_NT_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
# نمط حساب + تجزئة بسيطة
_USER_HASH_RE = re.compile(r"^([^:]+):([0-9a-fA-F]{32})$")
# نمط pwdump: username:RID:LM:NT:::
_PWDUMP_RE = re.compile(
    r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):.*$"
)
# تجزئة فارغة في NT (كلمة مرور فارغة) — تكتب دائماً بأحرف كبيرة
# لمطابقة convention pwdump/secretsdump ولأنّنا نُطبّق .upper() على كل تجزئة.
_EMPTY_LM = "AAD3B435B51404EEAAD3B435B51404EE"
_EMPTY_NT = "31D6CFE0D16AE931B73C59D7E0C089C0"


# ===========================================================================
# تحليل ملف التجزئات
# ===========================================================================

def parse_hash_file(path: str) -> List[Dict]:
    """
    تحليل ملف تجزئات NTLM.

    يعيد قائمة من dict:
        {"username": str|None, "lm": str|None, "nt": str, "format": str}

    الصيغ المكتشفة:
      - pwdump:    "username:RID:LM:NT:::"
      - user:nt:   "username:NT"
      - bare-nt:   "NT" فقط (username=None)
      - lm:nt:     "LM:NT"
    """
    entries: List[Dict] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # pwdump
            m = _PWDUMP_RE.match(line)
            if m:
                username, _rid, lm, nt = m.group(1), m.group(2), m.group(3), m.group(4)
                entries.append({"username": username, "lm": lm.upper(),
                                "nt": nt.upper(), "format": "pwdump"})
                continue

            # LM:NT (كلاهما 32-hex) — يجب التحقق قبل user:nt لأنّ المستخدم
            # قد يكون نصاً بطول 32 حرفاً من hex (نادر لكن ممكن).
            parts = line.split(":")
            if len(parts) == 2 and _NT_HASH_RE.match(parts[0]) and _NT_HASH_RE.match(parts[1]):
                entries.append({"username": None, "lm": parts[0].upper(),
                                "nt": parts[1].upper(), "format": "lm:nt"})
                continue

            # username:NT
            m = _USER_HASH_RE.match(line)
            if m:
                entries.append({"username": m.group(1), "lm": None,
                                "nt": m.group(2).upper(), "format": "user:nt"})
                continue

            # NT فقط
            if _NT_HASH_RE.match(line):
                entries.append({"username": None, "lm": None,
                                "nt": line.upper(), "format": "bare-nt"})
                continue

            # سطر غير معروف — نتخطّاه لكن نسجّله
            entries.append({"username": None, "lm": None, "nt": None,
                            "format": "unparsed", "raw": line})
    return entries


# ===========================================================================
# بناء جدول NTLM(word) → word
# ===========================================================================

def _build_ntlm_table_worker(wordlist_path: str,
                              case_fold: bool,
                              strip: bool) -> Dict[str, str]:
    """
    بناء dict {ntlm_hash: word} من قائمة الكلمات.
    هذه عملية O(wordlist) تُنفّذ مرة واحدة قبل المقارنة.
    """
    table: Dict[str, str] = {}
    for word in iter_wordlist(wordlist_path, case_fold=case_fold, strip=strip):
        ntlm = compute_ntlm(word)
        # إن تعارضت تجزئة (نادرة جداً) نُبقي أول ظهور
        if ntlm not in table:
            table[ntlm] = word
    return table


# عامل مجزّأ لـ multiprocessing عند بناء الجدول على قوائم ضخمة
def _table_chunk_worker(args: tuple) -> Dict[str, str]:
    wordlist_path, start, end, case_fold, strip = args
    table: Dict[str, str] = {}
    # نقرأ بـ seek ولكن iter_wordlist لا يدعم الإزاحة مباشرة؛ لذا نستخدم
    # عدّاد الأسطر ونأخذ الشريحة [start, end)
    idx = 0
    for word in iter_wordlist(wordlist_path, case_fold=case_fold, strip=strip):
        if idx >= end:
            break
        if idx >= start:
            ntlm = compute_ntlm(word)
            if ntlm not in table:
                table[ntlm] = word
        idx += 1
    return table


def build_ntlm_table(wordlist_path: str,
                     case_fold: bool = False,
                     strip: bool = True,
                     workers: Optional[int] = None) -> Dict[str, str]:
    """
    بناء جدول بحث NTLM(word) → word مع دعم التوازي للقوائم الكبيرة.

    للقوائم الصغيرة-المتوسطة (< ~500 ألف كلمة) يُنفّذ تسلسلياً (أبسط
    وأسرع بسبب تجنّب الـ IPC). للأكبر، يُقسّم العمل على العمّال.
    """
    n_workers = workers or max(1, mp.cpu_count())
    # تقدير عدد الكلمات من حجم الملف (تقريبي: ~10 بايت/كلمة)
    size = os.path.getsize(wordlist_path)
    est_count = max(1, size // 10)

    # عتبة التوازي: ~500 ألف كلمة
    if est_count < 500_000 or n_workers <= 1:
        return _build_ntlm_table_worker(wordlist_path, case_fold, strip)

    # توازي مجزّأ
    chunk_size = max(1, est_count // n_workers)
    tasks = []
    for i in range(n_workers):
        start = i * chunk_size
        end = (i + 1) * chunk_size if i < n_workers - 1 else est_count + 10_000_000
        tasks.append((wordlist_path, start, end, case_fold, strip))

    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    merged: Dict[str, str] = {}
    with ctx.Pool(processes=n_workers) as pool:
        for partial in pool.imap_unordered(_table_chunk_worker, tasks):
            # نُدمج دون الكتابة فوق الموجود
            for k, v in partial.items():
                if k not in merged:
                    merged[k] = v
    return merged


# ===========================================================================
# التدقيق الرئيسي
# ===========================================================================

def audit_windows_hashes(
    hash_file_path: str,
    wordlist_path: str = "wordlists/wordlist.txt",
    case_fold: bool = False,
    strip: bool = True,
    workers: Optional[int] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> AuditReport:
    """
    تدقيق ملف تجزئات NTLM ضدّ قائمة كلمات مرور شائعة.

    المعاملات:
        hash_file_path:  مسار ملف التجزئات (pwdump أو user:nt أو bare).
        wordlist_path:   مسار ملف القائمة.
        case_fold:       تطبيع الحالة.
        strip:           إزالة المسافات.
        workers:         عدد العمّال.
        progress_cb:     دالة استدعاء للتقدّم (msg, done, total).

    يعيد AuditReport.
    """
    start = time.time()

    # --- تحقّق الإدخال ---
    if not hash_file_path or not os.path.exists(hash_file_path):
        raise FileNotFoundError(f"ملف التجزئات غير موجود: {hash_file_path}")
    if os.path.getsize(hash_file_path) == 0:
        raise ValueError(f"ملف التجزئات فارغ: {hash_file_path}")
    if not wordlist_path or not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"ملف القائمة غير موجود: {wordlist_path}")

    try:
        wstats = wordlist_stats(wordlist_path)
        wl_count = wstats["word_count"]
    except Exception:
        wl_count = 0

    if progress_cb:
        progress_cb(f"بناء جدول NTLM لـ {wl_count} كلمة من القائمة...", 0, 0)

    # بناء جدول NTLM(word) → word (مرة واحدة)
    table = build_ntlm_table(wordlist_path, case_fold=case_fold,
                             strip=strip, workers=workers)
    if progress_cb:
        progress_cb(f"اكتمل بناء الجدول: {len(table)} تجزئة فريدة.", 0, 0)

    # تحليل ملف التجزئات
    entries = parse_hash_file(hash_file_path)
    if not entries:
        raise ValueError(f"لم يُعثر على تجزئات صالحة في الملف: {hash_file_path}")
    if progress_cb:
        progress_cb(f"تدقيق {len(entries)} تجزئة...", 0, len(entries))

    report = AuditReport()
    report.source_platform = "windows"
    report.hostname = socket.gethostname()
    report.wordlist_path = os.path.abspath(wordlist_path)
    report.wordlist_count = wl_count
    report.hash_backend = get_hash_backend()
    # بيانات وصفية عن أنواع الصيغ المكتشفة
    format_counts: Dict[str, int] = {}
    for e in entries:
        fmt = e.get("format", "unknown")
        format_counts[fmt] = format_counts.get(fmt, 0) + 1
    report.metadata["hash_file"] = os.path.abspath(hash_file_path)
    report.metadata["format_distribution"] = format_counts
    report.metadata["table_size"] = len(table)

    done = 0
    for e in entries:
        done += 1
        if e.get("format") == "unparsed":
            report.add(Finding(
                username="(unparsed-line)",
                source="windows-ntlm",
                algorithm="—",
                status="unknown",
                matched_password_masked=None,
                hash_preview=None,
                severity="info",
                notes=f"سطر غير مفهوم: {e.get('raw', '')[:60]}",
            ))
            continue

        nt = e["nt"]
        if nt is None:
            report.add(Finding(
                username=e.get("username") or "(unknown)",
                source="windows-ntlm",
                algorithm="—",
                status="unknown",
                matched_password_masked=None,
                hash_preview=None,
                severity="info",
                notes="تعذّر استخراج تجزئة NT.",
            ))
            continue

        username = e.get("username") or "(unknown)"
        hash_preview = f"NT | {nt[:8]}…"

        # تجزئة NT فارغة (لا كلمة مرور)
        if nt.upper() == _EMPTY_NT:
            report.add(Finding(
                username=username,
                source="windows-ntlm",
                algorithm="NTLM",
                status="empty",
                matched_password_masked=None,
                hash_preview=hash_preview,
                severity="high",
                notes="الحساب بدون كلمة مرور (تجزئة NT الفارغة).",
            ))
        elif nt.upper() in table:
            word = table[nt.upper()]
            report.add(Finding(
                username=username,
                source="windows-ntlm",
                algorithm="NTLM",
                status="weak",
                matched_password_masked=mask_password(word),
                hash_preview=hash_preview,
                severity="critical",
                notes="كلمة المرور مطابقة لإدخال في القائمة الشائعة.",
            ))
        else:
            # لم تُطابق — هذا لا يعني الأمان، فقط أنّ القائمة المُستخدمة لم تكشفها
            report.add(Finding(
                username=username,
                source="windows-ntlm",
                algorithm="NTLM",
                status="no_match",
                matched_password_masked=None,
                hash_preview=hash_preview,
                severity="low",
                notes="لم تُطابق أي كلمة في القائمة المُستخدمة — هذا لا يعني الأمان.",
            ))

        if progress_cb and done % 50 == 0:
            progress_cb(f"تم تدقيق {done}/{len(entries)} تجزئة.", done, len(entries))

    report.duration_seconds = time.time() - start
    if progress_cb:
        progress_cb("اكتمل التدقيق.", done, len(entries))

    return report


def audit_windows_sam_from_files(
    sam_path: str,
    system_path: str,
    wordlist_path: str,
    case_fold: bool = False,
    strip: bool = True,
    workers: Optional[int] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> AuditReport:
    """تدقيق تجزئات SAM من ملفات خلايا مُصدَّرة (SAM.save + SYSTEM.save).

    يتطلّب أن تكون خليتا SAM وSYSTEM مُصدَّرتين مسبقاً (عبر ``reg save`` أو
    ``save_registry_hive``). تعمل هذه الدالة على أيّ منصة.

    المعاملات:
        sam_path:     مسار ملف خلية SAM المُصدَّر.
        system_path:  مسار ملف خلية SYSTEM المُصدَّر.
        wordlist_path: مسار ملف القائمة.

    يعيد AuditReport.
    """
    start = time.time()
    if progress_cb:
        progress_cb("قراءة تجزئات SAM من ملفات الخلايا المُصدَّرة...", 0, 0)

    hashes = _read_sam_hashes_from_files(sam_path, system_path)
    if progress_cb:
        progress_cb(f"استُخرجت {len(hashes)} تجزئة من SAM.", 0, len(hashes))

    # تحويل إلى صيغة pwdump مؤقتة وإعادة استخدام parse_hash_file
    pwdump_text = _hashes_to_pwdump(hashes)
    tmp_path = sam_path + ".pwdump.tmp"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        fh.write(pwdump_text)
    try:
        report = audit_windows_hashes(
            hash_file_path=tmp_path,
            wordlist_path=wordlist_path,
            case_fold=case_fold, strip=strip,
            workers=workers, progress_cb=progress_cb)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
    report.metadata["sam_source"] = "exported-hives"
    report.metadata["sam_path"] = os.path.abspath(sam_path)
    report.metadata["system_path"] = os.path.abspath(system_path)
    report.metadata["direct_read"] = False
    return report


def audit_windows_sam_direct(
    wordlist_path: str,
    case_fold: bool = False,
    strip: bool = True,
    workers: Optional[int] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
) -> AuditReport:
    """تدقيق SAM مباشرة من نظام Windows الحيّ (يتطلّب Windows + admin).

    سير العمل:
      1. التحقّق من Windows + صلاحيات admin.
      2. تمكين SE_BACKUP_PRIVILEGE.
      3. تصدير خليتي SAM وSYSTEM عبر RegSaveKeyEx (مكتبة advapi32 القياسية).
      4. استخراج تجزئات NTLM من الخلايا المُصدَّرة (RC4 + DES فكّ تشفير).
      5. تدقيق التجزئات ضدّ القائمة.

    يعيد AuditReport. يرفع RuntimeError على غير-Windows، PermissionError بدون admin.
    """
    if not _is_windows():
        raise RuntimeError(
            "القراءة المباشرة من SAM تتطلّب Windows. "
            "استخدم audit_windows_sam_from_files() مع ملفات خلايا مُصدَّرة.")
    if not _is_admin():
        raise PermissionError(
            "القراءة المباشرة من SAM تتطلّب صلاحيات Administrator. "
            "أعد تشغيل الأداة كـ Administrator.")

    if progress_cb:
        progress_cb("تصدير خليتي SAM وSYSTEM (RegSaveKeyEx)...", 0, 0)

    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="passguard-sam-audit-")
    try:
        os.chmod(tmp, 0o700)
    except (AttributeError, OSError):
        pass
    if os.name == "nt":
        from .sam_reader import _restrict_windows_temp_directory
        _restrict_windows_temp_directory(tmp)
    sam_path = os.path.join(tmp, "SAM.save")
    system_path = os.path.join(tmp, "SYSTEM.save")

    try:
        from .sam_reader import save_registry_hive
        save_registry_hive("SAM", sam_path)
        save_registry_hive("SYSTEM", system_path)
        report = audit_windows_sam_from_files(
            sam_path, system_path, wordlist_path,
            case_fold=case_fold, strip=strip,
            workers=workers, progress_cb=progress_cb)
        report.metadata["direct_read"] = True
        report.metadata["sam_source"] = "live-system-regsavekeyex"
        return report
    finally:
        try:
            shutil.rmtree(tmp)
        except OSError:
            pass


__all__ = ["audit_windows_hashes", "audit_windows_sam_direct",
           "audit_windows_sam_from_files", "parse_hash_file", "build_ntlm_table"]
