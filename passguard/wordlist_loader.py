"""
passguard.wordlist_loader
=========================

تحميل قوائم كلمات المرور الشائعة بكفاءة، مع دعم الملفات الكبيرة جداً.

نوفّر مسارين:
  1. load_wordlist_set(path): يُرجع set للبحث الفوري O(1) — يُستخدم في
     النافذة التفاعلية (Interactive Checker) لأن سرعة الفحص مطلوبة فوراً.
  2. iter_wordlist(path): مولّد (generator) يقرأ سطراً سطراً دون تحميل
     الملف بالكامل في الذاكرة — يُستخدم في وحدات التدقيق (Auditors)
     عند المقارنة مع التجزئات.

الاعتبارات:
  - القراءة بخيار encoding='utf-8' مع fallback إلى latin-1 لأن بعض
    قوائم التسريبات تحتوي على بايتات غير صالحة UTF-8.
  - يتجاهل الأسطر الفارغة والتعليقات (#).
  - خيار تطبيع الحالة (case folding) لجعل الفحص غير حساس للحالة عند
    الحاجة.
"""

from __future__ import annotations

import os
from typing import Iterator, Optional, Set, Tuple


def _open_wordlist(path: str):
    """فتح ملف القائمة بترميز متسامح."""
    try:
        return open(path, "r", encoding="utf-8", errors="replace")
    except OSError as e:
        raise FileNotFoundError(f"تعذّر فتح ملف القائمة: {path} ({e})")


def iter_wordlist(path: str,
                  case_fold: bool = False,
                  strip: bool = True) -> Iterator[str]:
    """
    مولّد يُنتج كلمات القائمة سطراً بسطر دون تحميل الملف كاملاً.

    المعاملات:
        path:       مسار ملف القائمة.
        case_fold:  إن كان True يُطبّق .casefold() على كل كلمة (لجعل
                    البحث غير حساس للحالة).
        strip:      إزالة المسافات الزائدة ومحارف نهاية السطر.

    يستثني الأسطر الفارغة والأسطر التي تبدأ بـ # (تعليقات).
    """
    with _open_wordlist(path) as fh:
        for raw in fh:
            line = raw.rstrip("\r\n")
            if strip:
                line = line.strip()
            if not line or line.startswith("#"):
                continue
            if case_fold:
                line = line.casefold()
            yield line


def load_wordlist_set(path: str,
                      case_fold: bool = False,
                      strip: bool = True,
                      max_bytes: Optional[int] = None) -> Set[str]:
    """
    تحميل ملف القائمة بالكامل في set للبحث الفوري.

    المعاملات:
        path:       مسار ملف القائمة.
        case_fold:  تطبيع الحالة.
        strip:      إزالة المسافات.
        max_bytes:  حد أقصى لحجم الملف بالبايت (حماية من التحميل العرضي
                    لملفات ضخمة جداً في وضع التحميل الكامل). None يعني
                    بلا حد.

    يعيد set من الكلمات.
    """
    if max_bytes is not None:
        size = os.path.getsize(path)
        if size > max_bytes:
            raise ValueError(
                f"حجم ملف القائمة {size} بايت يتجاوز الحد المسموح {max_bytes}. "
                f"استخدم iter_wordlist() بدلاً من ذلك."
            )
    result: Set[str] = set()
    for w in iter_wordlist(path, case_fold=case_fold, strip=strip):
        result.add(w)
    return result


def wordlist_stats(path: str) -> dict:
    """
    إحصائيات سريعة عن ملف القائمة: عدد الكلمات، حجم الملف بالبايت،
    متوسط طول الكلمة، أطول وأقصر كلمة.
    """
    count = 0
    total_len = 0
    longest = 0
    shortest = 10_000_000
    size_bytes = os.path.getsize(path)
    for w in iter_wordlist(path):
        count += 1
        n = len(w)
        total_len += n
        if n > longest:
            longest = n
        if n < shortest:
            shortest = n
    return {
        "path": path,
        "size_bytes": size_bytes,
        "word_count": count,
        "avg_length": round(total_len / count, 2) if count else 0,
        "min_length": shortest if count else 0,
        "max_length": longest if count else 0,
    }


__all__ = ["iter_wordlist", "load_wordlist_set", "wordlist_stats"]
