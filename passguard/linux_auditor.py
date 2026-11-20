"""
passguard.linux_auditor
=======================

وحدة تدقيق كلمات مرور أنظمة Linux عبر قراءة /etc/shadow.

سير العمل:
  1. قراءة /etc/shadow (يتطلب صلاحيات root: sudo).
  2. قراءة /etc/passwd لاستبعاد حسابات النظام (UID < min_uid).
  3. لكل حساب نشط (status="active")، نأخذ حقل التجزئة الكامل
     ($id$salt$hash) ونطبّق backend التجزئة (passlib/crypt) لكل كلمة في
     القائمة. التطابق يعني أنّ كلمة المرور الخاصة بالمستخدم هي تلك الكلمة.
  4. التوازي: كل مستخدم له ملح مستقل، لذا نُوزّع المستخدمين على دفعات
     (batches) على عمّال multiprocessing.Pool. كل عامل يقرأ القائمة مرة
     واحدة ويفحص كل مستخدمي دفعته ضدّها — هذا يقلّل قراءة الملف من
     N_users إلى N_batches.

تحسينات Phase 3:
  - إعادة استخدام القائمة: كل عامل يقرأ ملف القائمة مرة واحدة لكل دفعة
    (لا لكل مستخدم).
  - عزل الأخطاء: فشل مستخدم واحد لا يُنهي التدقيق كله.
  - إلغاء: دعم cancel_event (multiprocessing.Event) لإيقاف التدقيق.
  - تصنيف النتائج الواضح: weak/no_match/locked/disabled/empty/unknown/
    error/not_assessed.
  - backend التجزئة: استخدام verify_unix_hash لتمييز "unsupported" عن
    "no_match".
  - لا إجبار القائمة في الذاكرة: قراءة تدفّقية سطراً بسطر.

الأمان:
  - لا تُخزّن كلمات المرور الأصلية. المطابقات تُمرّر مُخفّاة.
  - يستخدم hmac.compare_digest (داخل verify_unix_hash) لمقارنة ثابتة الزمن.
  - الحسابات المقفلة/الفارغة تُسجّل بحالة مناسبة دون محاولة كسرها.

ملاحظة عن الصلاحيات:
  /etc/shadow عادةً بملكية root:shadow وبتصريح 640. لذا يجب تشغيل
  الأداة بصلاحيات root (sudo).
"""

from __future__ import annotations

import multiprocessing as mp
import os
import socket
import time
from typing import Callable, Dict, List, Optional

from .hash_utils import (
    parse_unix_hash_field,
    verify_unix_hash,
    can_verify_algo,
    get_hash_backend,
    mask_password,
    hash_summary_for_report,
)
from .reporter import AuditReport, Finding, DEFAULT_SEVERITY
from .wordlist_loader import iter_wordlist, wordlist_stats


# ===========================================================================
# قراءة /etc/passwd لاستبعاد حسابات النظام
# ===========================================================================

def _read_passwd_uids(passwd_path: str = "/etc/passwd") -> Dict[str, int]:
    """قراءة /etc/passwd وإرجاع {username: uid}."""
    uids: Dict[str, int] = {}
    try:
        with open(passwd_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 3:
                    try:
                        uids[parts[0]] = int(parts[2])
                    except ValueError:
                        continue
    except OSError:
        pass
    return uids


def _read_shadow(shadow_path: str = "/etc/shadow") -> List[tuple]:
    """قراءة /etc/shadow وإرجاع قائمة (username, hash_field, last_changed)."""
    entries: List[tuple] = []
    try:
        with open(shadow_path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 2 and parts[0]:
                    username = parts[0]
                    hash_field = parts[1]
                    last_changed = parts[2] if len(parts) > 2 else ""
                    entries.append((username, hash_field, last_changed))
    except PermissionError:
        raise PermissionError(
            f"صلاحية غير كافية لقراءة {shadow_path}. شغّل الأداة بصلاحيات root: "
            f"sudo python -m passguard.main audit-linux ..."
        )
    except OSError as e:
        raise OSError(f"تعذّر قراءة {shadow_path}: {e}")
    return entries


# ===========================================================================
# عامل توازي: فحص دفعة مستخدمين ضدّ القائمة (قراءة واحدة)
# ===========================================================================

def _audit_user_batch(args: tuple) -> List[dict]:
    """
    عامل multiprocessing: يفحص دفعة من المستخدمين ضدّ القائمة.

    المعطيات: (users_batch, wordlist_path, case_fold, strip, cancel_flag)
        users_batch: قائمة (username, hash_field)
        wordlist_path: مسار ملف القائمة
        case_fold: تطبيع الحالة
        strip: إزالة المسافات
        cancel_flag: multiprocessing.Value أو None للتحقّق من الإلغاء

    يقرأ ملف القائمة مرة واحدة (تدفّقياً) ويفحص كل كلمة ضدّ كل مستخدمي
    الدفعة. هذا يقلّل قراءة الملف من N_users إلى N_batches.

    الإرجاع: قائمة نتائج (dict لكل مستخدم).
    عزل الأخطاء: فشل مستخدم واحد لا يُنهي الدفعة.
    """
    users_batch, wordlist_path, case_fold, strip, cancel_flag = args

    # تهيئة نتائج كل مستخدم بحالة افتراضية
    # نستخدم قاموساً لمتابعة الحالة لكل مستخدم
    results: List[dict] = []
    pending: List[tuple] = []   # (index_in_results, username, hash_field)

    for username, hash_field in users_batch:
        result = _classify_account_initial(username, hash_field)
        results.append(result)
        # فقط الحسابات النشطة تحتاج فحص القائمة
        if result["status"] == "active_pending":
            pending.append((len(results) - 1, username, hash_field))

    # إن لم تكن هناك حسابات نشطة، نُعيد النتائج فوراً
    if not pending:
        return results

    # فحص القائمة: نقرأ الملف مرة واحدة ونتحقّق من كل كلمة ضدّ كل المستخدمين
    # المعلّقين. بمجرّد العثور على تطابق لمستخدم، نُزيله من pending.
    try:
        for word in iter_wordlist(wordlist_path, case_fold=case_fold, strip=strip):
            # التحقّق من الإلغاء
            if cancel_flag is not None:
                try:
                    if cancel_flag.value:
                        break
                except Exception:
                    pass
            # نسخة من pending للتعديل أثناء التكرار
            still_pending: List[tuple] = []
            for idx, username, hash_field in pending:
                try:
                    matched, status = verify_unix_hash(word, hash_field)
                except Exception:
                    # خطأ في التحقق — نُسجّله لكنّنا نُكمل
                    matched, status = False, "error"
                if matched:
                    results[idx] = {
                        "username": username,
                        "status": "weak",
                        "algorithm": results[idx]["algorithm"],
                        "matched": mask_password(word),
                        "hash_preview": results[idx]["hash_preview"],
                        "severity": "critical",
                        "notes": "كلمة المرور مطابقة لإدخال في القائمة الشائعة.",
                        "salt": results[idx].get("salt"),
                        "rounds": results[idx].get("rounds"),
                        "verification_backend": get_hash_backend(),
                    }
                elif status == "unsupported":
                    # خوارزمية غير مدعومة — نُعلّم كـ not_assessed ونُزيل من pending
                    results[idx] = {
                        "username": username,
                        "status": "not_assessed",
                        "algorithm": results[idx]["algorithm"],
                        "matched": None,
                        "hash_preview": results[idx]["hash_preview"],
                        "severity": "medium",
                        "notes": "خوارزمية التجزئة غير مدعومة من backend النشط — تعذّر التحقق.",
                        "salt": results[idx].get("salt"),
                        "rounds": results[idx].get("rounds"),
                        "verification_backend": get_hash_backend(),
                    }
                elif status == "error":
                    results[idx] = {
                        "username": username,
                        "status": "error",
                        "algorithm": results[idx]["algorithm"],
                        "matched": None,
                        "hash_preview": results[idx]["hash_preview"],
                        "severity": "medium",
                        "notes": "حدث خطأ أثناء التحقق من التجزئة.",
                        "salt": results[idx].get("salt"),
                        "rounds": results[idx].get("rounds"),
                        "verification_backend": get_hash_backend(),
                    }
                else:
                    # no_match حتى الآن — نُبقيه في pending لمتابعة الفحص
                    still_pending.append((idx, username, hash_field))
            pending = still_pending
            # إن لم يبقَ مستخدمون معلّقون، نتوقّف مبكراً
            if not pending:
                break
    except OSError as e:
        # خطأ في قراءة ملف القائمة — نُعلّم كل المعلّقين كـ error
        for idx, username, _ in pending:
            results[idx] = {
                "username": username,
                "status": "error",
                "algorithm": results[idx]["algorithm"],
                "matched": None,
                "hash_preview": results[idx]["hash_preview"],
                "severity": "medium",
                "notes": f"خطأ في قراءة ملف القائمة: {e}",
                "salt": results[idx].get("salt"),
                "rounds": results[idx].get("rounds"),
                "verification_backend": get_hash_backend(),
            }
        return results

    # المستخدمون المتبقّون في pending لم يطابقوا أي كلمة → no_match
    # (هذا لا يعني أنّهم آمنون، فقط أنّ القائمة لم تكشفهم)
    for idx, username, _ in pending:
        results[idx] = {
            "username": username,
            "status": "no_match",
            "algorithm": results[idx]["algorithm"],
            "matched": None,
            "hash_preview": results[idx]["hash_preview"],
            "severity": "low",
            "notes": "لم تُطابق أي كلمة في القائمة المُستخدمة — هذا لا يعني الأمان.",
            "salt": results[idx].get("salt"),
            "rounds": results[idx].get("rounds"),
            "verification_backend": get_hash_backend(),
        }

    return results


def _classify_account_initial(username: str, hash_field: str) -> dict:
    """التصنيف الأوّلي للحساب قبل فحص القائمة."""
    parsed = parse_unix_hash_field(hash_field)
    if parsed is None:
        return {"username": username, "status": "empty", "algorithm": "",
                "matched": None, "hash_preview": "",
                "severity": "info", "notes": "حقل فارغ",
                "salt": None, "rounds": None,
                "verification_backend": get_hash_backend()}

    status = parsed["status"]
    algo_name = parsed["algo_name"] or "Unknown"
    algo_id = parsed.get("algo_id")
    hash_preview = hash_summary_for_report(algo_name, hash_field)
    salt = parsed.get("salt")
    rounds = parsed.get("rounds")

    if status == "active":
        # نتأكّد أنّ backend يستطيع التحقق من هذه الخوارزمية قبل فحص القائمة
        if not can_verify_algo(algo_id):
            return {
                "username": username, "status": "not_assessed",
                "algorithm": algo_name,
                "matched": None, "hash_preview": hash_preview,
                "severity": "medium",
                "notes": f"خوارزمية {algo_name} غير مدعومة من backend النشط ({get_hash_backend()}).",
                "salt": salt, "rounds": rounds,
                "verification_backend": get_hash_backend(),
            }
        # نُعيد حالة وسيطة تُشير لاحتياج فحص القائمة
        return {
            "username": username, "status": "active_pending",
            "algorithm": algo_name,
            "matched": None, "hash_preview": hash_preview,
            "severity": "low", "notes": "",
            "salt": salt, "rounds": rounds,
            "verification_backend": get_hash_backend(),
        }
    elif status == "locked":
        return {
            "username": username, "status": "locked",
            "algorithm": algo_name,
            "matched": None, "hash_preview": hash_preview,
            "severity": "info",
            "notes": "الحساب مقفل أو كلمة المرور معطّلة (!/*).",
            "salt": salt, "rounds": rounds,
            "verification_backend": get_hash_backend(),
        }
    elif status == "empty":
        return {
            "username": username, "status": "empty",
            "algorithm": algo_name,
            "matched": None, "hash_preview": hash_preview,
            "severity": "high",
            "notes": "لا توجد كلمة مرور مضبوطة للحساب.",
            "salt": salt, "rounds": rounds,
            "verification_backend": get_hash_backend(),
        }
    elif status == "disabled":
        return {
            "username": username, "status": "disabled",
            "algorithm": algo_name,
            "matched": None, "hash_preview": hash_preview,
            "severity": "info",
            "notes": "الحساب معطّل (*).",
            "salt": salt, "rounds": rounds,
            "verification_backend": get_hash_backend(),
        }
    else:
        return {
            "username": username, "status": "unknown",
            "algorithm": algo_name,
            "matched": None, "hash_preview": hash_preview,
            "severity": "medium",
            "notes": "صيغة تجزئة غير معروفة.",
            "salt": salt, "rounds": rounds,
            "verification_backend": get_hash_backend(),
        }


# ===========================================================================
# واجهة التدقيق الرئيسية
# ===========================================================================

def audit_linux_shadow(
    shadow_path: str = "/etc/shadow",
    passwd_path: str = "/etc/passwd",
    wordlist_path: str = "wordlists/wordlist.txt",
    min_uid: int = 1000,
    skip_system_accounts: bool = True,
    case_fold: bool = False,
    strip: bool = True,
    workers: Optional[int] = None,
    progress_cb: Optional[Callable[[str, int, int], None]] = None,
    cancel_event: Optional["mp.Event"] = None,
    batch_size: int = 4,
) -> AuditReport:
    """
    تدقيق كلمات مرور حسابات Linux المحلية.

    المعاملات:
        shadow_path:            مسار /etc/shadow.
        passwd_path:            مسار /etc/passwd (لاستخراج UID).
        wordlist_path:          مسار ملف القائمة.
        min_uid:                الحد الأدنى لـ UID للحسابات غير النظامية.
        skip_system_accounts:   استثناء حسابات النظام (UID < min_uid).
        case_fold:              تطبيع الحالة.
        strip:                  إزالة المسافات.
        workers:                عدد عمّال multiprocessing.
        progress_cb:            دالة (msg, done, total) للتقدّم.
        cancel_event:           mp.Event للإلغاء (اختياري).
        batch_size:             عدد المستخدمين في كل دفعة عامل (يقلّل قراءة
                                القائمة: N_batches = ceil(N_users/batch_size)).

    يعيد AuditReport.

    عزل الأخطاء: فشل مستخدم واحد لا يُنهي التدقيق.
    الإلغاء: إن وُضع cancel_event، يتوقّف التدقيق بأمان.
    """
    start = time.time()

    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"ملف القائمة غير موجود: {wordlist_path}")

    # إحصاءات القائمة
    try:
        wstats = wordlist_stats(wordlist_path)
        wl_count = wstats["word_count"]
    except Exception:
        wl_count = 0

    # قراءة الظل
    shadow_entries = _read_shadow(shadow_path)

    # قراءة UIDs
    uids = _read_passwd_uids(passwd_path) if skip_system_accounts else {}

    # تصفية الحسابات
    active_users: List[tuple] = []
    skipped_system = 0
    for username, hash_field, _last in shadow_entries:
        if skip_system_accounts and username != "root":
            uid = uids.get(username)
            if uid is not None and uid < min_uid:
                skipped_system += 1
                continue
        active_users.append((username, hash_field))

    # تقسيم المستخدمين إلى دفعات
    n_users = len(active_users)
    if n_users == 0:
        if progress_cb:
            progress_cb("لا توجد حسابات للفحص.", 0, 0)
        report = AuditReport()
        report.source_platform = "linux"
        report.hostname = socket.gethostname()
        report.wordlist_path = os.path.abspath(wordlist_path)
        report.wordlist_count = wl_count
        report.duration_seconds = time.time() - start
        report.hash_backend = get_hash_backend()
        if skipped_system:
            report.add(Finding(
                username="(system-accounts)", source="linux-shadow",
                algorithm="—", status="skipped",
                severity="info",
                notes=f"تم استثناء {skipped_system} حساب نظام (UID < {min_uid}).",
            ))
        return report

    batches: List[List[tuple]] = []
    for i in range(0, n_users, batch_size):
        batches.append(active_users[i: i + batch_size])

    if progress_cb:
        progress_cb(f"بدء تدقيق {n_users} حساباً ضدّ قائمة من {wl_count} كلمة "
                    f"({len(batches)} دفعة، {workers or 'auto'} عمّال).",
                    0, n_users)

    # علم إلغاء مشترك
    cancel_flag = None
    if cancel_event is not None:
        # نستخدم Value بدلاً من Event لأنّ Event قد لا ينتقل عبر fork بسلاسة
        # في بعض البيئات؛ لكنّ Event يعمل عادةً. نستخدم Event مباشرة.
        cancel_flag = cancel_event

    # بناء المهام
    tasks = [(batch, wordlist_path, case_fold, strip, cancel_flag)
             for batch in batches]

    n_workers = workers or max(1, mp.cpu_count())
    n_workers = min(n_workers, len(batches))

    results: List[dict] = []
    cancelled = False

    ctx = mp.get_context("fork") if "fork" in mp.get_all_start_methods() else mp.get_context()
    try:
        with ctx.Pool(processes=n_workers) as pool:
            done_users = 0
            for batch_results in pool.imap_unordered(_audit_user_batch, tasks,
                                                       chunksize=1):
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                results.extend(batch_results)
                done_users += len(batch_results)
                if progress_cb:
                    progress_cb(f"تم فحص {done_users}/{n_users} حساباً.",
                                done_users, n_users)
    except Exception as e:
        # خطأ في Pool — نُسجّله لكن نُكمل بنتائج الجزء المُكتمل
        if progress_cb:
            progress_cb(f"خطأ في تجمّع العمّال: {e}", 0, 0)

    # بناء التقرير
    report = AuditReport()
    report.source_platform = "linux"
    report.hostname = socket.gethostname()
    report.wordlist_path = os.path.abspath(wordlist_path)
    report.wordlist_count = wl_count
    report.duration_seconds = time.time() - start
    report.hash_backend = get_hash_backend()
    report.metadata["cancelled"] = cancelled
    report.metadata["batches"] = len(batches)
    report.metadata["batch_size"] = batch_size

    for r in results:
        report.add(Finding(
            username=r["username"],
            source="linux-shadow",
            algorithm=r["algorithm"],
            status=r["status"],
            matched_password_masked=r["matched"],
            hash_preview=r["hash_preview"],
            severity=r["severity"],
            notes=r["notes"],
            uid=uids.get(r["username"]),
            salt=r.get("salt"),
            rounds=r.get("rounds"),
            verification_backend=r.get("verification_backend") or get_hash_backend(),
            audit_source=shadow_path,
        ))

    # الحسابات النظامية المستثناة
    if skipped_system:
        report.findings.append(Finding(
            username="(system-accounts)",
            source="linux-shadow",
            algorithm="—",
            status="skipped",
            matched_password_masked=None,
            hash_preview=None,
            severity="info",
            notes=f"تم استثناء {skipped_system} حساب نظام (UID < {min_uid}).",
        ))

    if progress_cb:
        if cancelled:
            progress_cb("تم إلغاء التدقيق.", len(results), n_users)
        else:
            progress_cb("اكتمل التدقيق.", n_users, n_users)

    return report


# الحفاظ على الـ worker القديم للاستدعاءات المباشرة (للتوافق الخلفي)
def _audit_one_user(args: tuple) -> dict:
    """
    [مُهمل — للتوافق الخلفي] فحص مستخدم واحد.
    مُحافَظ عليها لتفادي كسر الاستدعاءات المباشرة، لكنّ audit_linux_shadow
    يستخدم الآن _audit_user_batch (أكثر كفاءة).
    """
    username, hash_field, wordlist_path, case_fold, strip = args
    batch_results = _audit_user_batch(
        [(username, hash_field)], wordlist_path, case_fold, strip, None)
    return batch_results[0] if batch_results else {
        "username": username, "status": "error", "algorithm": "",
        "matched": None, "hash_preview": "", "severity": "medium",
        "notes": "لم تُنتج الدفعة نتيجة.",
    }


__all__ = ["audit_linux_shadow"]
