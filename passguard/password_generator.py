"""
passguard.password_generator
============================

مولّد كلمات مرور قوية وعشوائية باستخدام `secrets` (مولّد الأرقام العشوائية
الزائف المُختبَر والآمن تشفيرياً)، ومولّد عبارات مرور (passphrases) بأسلوب
Diceware مع دعم قوائم كلمات خارجية وحساب إنتروبيا فعلي.

الميزات:
  - generate_password(): كلمة مرور عشوائية بطول وأصناف قابلة للتحكّم.
    تستخدم secrets.choice + Fisher-Yates shuffle الآمن.
  - generate_passphrase(): عبارة مرور من كلمات عشوائية. تدعم:
      * قائمة Diceware خارجية (wordlist_path) — يُوصى بها للإنتاج.
      * قائمة مدمجة صغيرة (~70 كلمة) — للعرض فقط، ليست Diceware إنتاجية.
      * منع تكرار الكلمات (allow_duplicates=False).
      * حساب الإنتروبيا من العدد الفعلي للكلمات الفريدة في القائمة.
  - generate_passphrase_detailed(): توليد مع تحليل مفصّل (إنتروبيا، تحذيرات).

قواعد أمنية:
  - secrets.choice() دائماً (آمن تشفيرياً، لا random).
  - لا إدعاء بأنّ القائمة المدمجة الصغيرة توفّر أمان Diceware إنتاجي.
  - تحذير صريح عند استخدام القائمة المدمجة.

توافق خلفي:
  - generate_password(...) signature محفوظ تماماً.
  - generate_passphrase(num_words, separator, ...) محفوظ مع إضافة معاملات
    اختيارية جديدة لها قيم افتراضية (لا تكسر الـ call sites القديمة).
"""

from __future__ import annotations

import math
import secrets
import string
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .password_analyzer import analyze_password


# ===========================================================================
# كلمات مرور عشوائية (generate_password — محفوظة بدون تغيير)
# ===========================================================================

# الأحرف الملتبسة بصرياً
AMBIGUOUS = set("Il1O0o`'\"|{}[]()/\\")

# مجاميع الأحرف الافتراضية
SET_LOWER = string.ascii_lowercase
SET_UPPER = string.ascii_uppercase
SET_DIGIT = string.digits
SET_SYMBOL = "!@#$%^&*-_=+?.,:;"


def _filter_ambiguous(chars: str) -> str:
    """استبعاد الأحرف الملتبسة."""
    return "".join(c for c in chars if c not in AMBIGUOUS)


def generate_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    """
    توليد كلمة مرور عشوائية قوية.

    المعاملات:
        length:           الطول (4-128).
        use_upper:        تضمين أحرف كبيرة.
        use_lower:        تضمين أحرف صغيرة.
        use_digits:       تضمين أرقام.
        use_symbols:      تضمين رموز.
        avoid_ambiguous:  استبعاد الأحرف الملتبسة بصرياً.

    يعيد كلمة مرور كنص. تطبيق `secrets` يضمن عشوائية آمنة تشفيرياً.

    يرفع ValueError إذا لم يُختر أي صنف، أو إذا كان الطول خارج النطاق.
    """
    if length < 4:
        raise ValueError("الطول يجب أن يكون 4 على الأقل.")
    if length > 128:
        raise ValueError("الطول يجب أن يكون 128 على الأكثر.")
    if not any([use_upper, use_lower, use_digits, use_symbols]):
        raise ValueError("يجب اختيار صنف أحرف واحد على الأقل.")

    # بناء مجاميع الأحرف المُختارة
    pools: list[str] = []
    if use_lower:
        s = SET_LOWER
        pools.append(_filter_ambiguous(s) if avoid_ambiguous else s)
    if use_upper:
        s = SET_UPPER
        pools.append(_filter_ambiguous(s) if avoid_ambiguous else s)
    if use_digits:
        s = SET_DIGIT
        pools.append(_filter_ambiguous(s) if avoid_ambiguous else s)
    if use_symbols:
        s = SET_SYMBOL
        pools.append(_filter_ambiguous(s) if avoid_ambiguous else s)

    # المجموعة الكاملة للاختيار العشوائي
    all_chars = "".join(pools)
    if not all_chars:
        raise ValueError("لا أحرف متاحة للتصعيد.")

    # نضمن وجود حرف واحد على الأقل من كل صنف مُختار
    password_chars: list[str] = []
    for pool in pools:
        password_chars.append(secrets.choice(pool))

    # إكمال بقية الطول بالاختيار العشوائي من المجموعة الكاملة
    remaining = length - len(password_chars)
    if remaining > 0:
        password_chars.extend(secrets.choice(all_chars) for _ in range(remaining))

    # خلط القائمة بأمان (Fisher-Yates مع secrets)
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)


# ===========================================================================
# عبارات المرور (passphrases) — Diceware-compatible
# ===========================================================================

# قائمة كلمات مدمجة صغيرة (~70 كلمة فريدة) للعرض والاختبار السريع.
# ⚠️ ليست Diceware إنتاجية: إنتروبيا ~6.1 bits/كلمة فقط (log2(70)).
# للإنتاج استخدم قائمة EFF الرسمية (7776 كلمة → 12.9 bits/كلمة) عبر
# wordlist_path. القائمة المدمجة تكفي فقط للتجربة والتعلّم.
_BUNDLED_PASSPHRASE_WORDS: List[str] = [
    "apple", "river", "stone", "cloud", "tiger", "ocean", "moon", "fire",
    "green", "blue", "swift", "calm", "brave", "smart", "lucky", "proud",
    "mount", "valley", "forest", "desert", "island", "meadow",
    "thunder", "light", "shadow", "frost", "storm", "breeze", "summit",
    "canyon", "plateau", "harbor", "village", "castle", "bridge", "tower",
    "garden", "orchard", "pasture", "glacier", "volcano", "delta",
    "comet", "planet", "galaxy", "nebula", "quasar", "meteor", "orbit",
    "phoenix", "griffin", "dragon", "falcon", "raven", "eagle", "hawk",
    "wolf", "bear", "lion", "fox", "deer", "hare", "owl", "otter",
    "amber", "crimson", "indigo", "silver", "golden", "violet",
]


@dataclass
class PassphraseResult:
    """نتيجة توليد عبارة مرور مع تحليل مفصّل."""
    passphrase: str
    num_words: int
    separator: str
    wordlist_source: str            # "bundled" أو مسار الملف
    wordlist_unique_count: int      # عدد الكلمات الفريدة في القائمة
    allow_duplicates: bool
    entropy_bits: float             # إنتروبيا فعلي = num_words × log2(unique_count)
    selected_words: List[str] = field(default_factory=list)
    warning: str = ""               # تحذير إن كانت القائمة صغيرة


def load_diceware_wordlist(path: str,
                            case_fold: bool = False,
                            min_word_len: int = 2,
                            max_word_len: int = 12) -> Tuple[List[str], int]:
    """
    تحميل قائمة Diceware من ملف نصي (كلمة واحدة لكل سطر).

    المعاملات:
        path:           مسار ملف القائمة.
        case_fold:      تطبيع الحالة.
        min_word_len:   تجاهل الكلمات الأقصر من هذا الطول.
        max_word_len:   تجاهل الكلمات الأطول.

    يعيد (unique_words_list, unique_count).
    تُزال التكرارات لضمان توزيع احتماليّ منتظم.
    يرفع FileNotFoundError إن لم يوجد الملف.
    """
    if not path or not __import__("os").path.exists(path):
        raise FileNotFoundError(f"ملف قائمة Diceware غير موجود: {path}")
    seen: set = set()
    words: List[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            w = raw.strip()
            if case_fold:
                w = w.casefold()
            if not w or w.startswith("#"):
                continue
            if not (min_word_len <= len(w) <= max_word_len):
                continue
            # تجاهل الكلمات بحروف غير أبجدية (للحفاظ على قابلية الحفظ)
            if not w.isalpha():
                continue
            if w not in seen:
                seen.add(w)
                words.append(w)
    return words, len(words)


def passphrase_entropy_bits(num_words: int,
                              wordlist_unique_count: int,
                              allow_duplicates: bool) -> float:
    """
    حساب إنتروبيا عبارة المرور من العدد الفعلي للكلمات الفريدة.

    إن سُمح التكرار (allow_duplicates=True):
        H = num_words × log2(N)   حيث N = unique_count
    إن لم يُسمح التكرار (allow_duplicates=False):
        H = sum(log2(N - i)) for i in range(num_words)   (تسلسل هابط)

    هذا حساب فعلي يعتمد على القائمة المُستخدمة، وليس تقديراً عاماً.
    """
    if wordlist_unique_count <= 0 or num_words <= 0:
        return 0.0
    if allow_duplicates:
        return num_words * math.log2(wordlist_unique_count)
    # بدون تكرار: اختيار بدون إعادة
    if num_words > wordlist_unique_count:
        # لا يمكن منع التكرار إن كان num_words > N — نسقط للمسار المتاح
        return num_words * math.log2(wordlist_unique_count)
    total = 0.0
    for i in range(num_words):
        total += math.log2(wordlist_unique_count - i)
    return total


def _select_words(words: List[str], num_words: int,
                   allow_duplicates: bool) -> List[str]:
    """اختيار num_words كلمات عشوائية من words باستخدام secrets.choice."""
    if not words:
        raise ValueError("قائمة الكلمات فارغة.")
    n = len(words)
    selected: List[str] = []
    if allow_duplicates:
        for _ in range(num_words):
            selected.append(secrets.choice(words))
    else:
        # بدون إعادة: نسخة قابلة للتعديل ونختار ونحذف
        pool = list(words)
        for _ in range(num_words):
            if not pool:
                # إن نفدت الكلمات (num_words > N) نُعيد التعبئة
                pool = list(words)
            idx = secrets.randbelow(len(pool))
            selected.append(pool.pop(idx))
    return selected


def generate_passphrase(
    num_words: int = 4,
    separator: str = "-",
    min_word_len: int = 4,
    max_word_len: int = 8,
    wordlist_path: Optional[str] = None,
    allow_duplicates: bool = False,
    case_fold: bool = False,
) -> str:
    """
    توليد عبارة مرور (passphrase) من كلمات عشوائية بأسلوب Diceware.

    المعاملات:
        num_words:        عدد الكلمات (افتراضي 4).
        separator:        الفاصل بين الكلمات (افتراضي '-').
        min_word_len:     الحدّ الأدنى لطول الكلمة (للترشيح).
        max_word_len:     الحدّ الأقصى لطول الكلمة (للترشيح).
        wordlist_path:    مسار قائمة Diceware خارجية. إن None تُستخدم
                          القائمة المدمجة الصغيرة (~70 كلمة) — ⚠️ ليست
                          Diceware إنتاجية. للإنتاج استخدم قائمة EFF 7776.
        allow_duplicates: إن False (الافتراضي) لا تتكرر كلمة في العبارة.
        case_fold:        تطبيع الحالة عند تحميل قائمة خارجية.

    يعيد عبارة المرور كنص.

    توافق خلفي: المعاملات الجديدة (wordlist_path, allow_duplicates, case_fold)
    اختيارية بقيم افتراضية لا تغيّر سلوك الـ call sites القديمة (التي تستخدم
    القائمة المدمجة). لتحسين الأمان، مرّر wordlist_path لقائمة EFF.
    """
    if num_words < 1:
        raise ValueError("عدد الكلمات يجب أن يكون 1 على الأقل.")
    if not separator:
        separator = "-"

    if wordlist_path:
        words, unique_count = load_diceware_wordlist(
            wordlist_path, case_fold=case_fold,
            min_word_len=min_word_len, max_word_len=max_word_len)
        if unique_count == 0:
            raise ValueError(f"قائمة Diceware فارغة بعد الترشيح: {wordlist_path}")
    else:
        # القائمة المدمجة — نطبّق ترشيح الطول
        words = [w for w in _BUNDLED_PASSPHRASE_WORDS
                 if min_word_len <= len(w) <= max_word_len]
        if not words:
            words = list(_BUNDLED_PASSPHRASE_WORDS)
        unique_count = len(words)

    selected = _select_words(words, num_words, allow_duplicates)
    return separator.join(selected)


def generate_passphrase_detailed(
    num_words: int = 4,
    separator: str = "-",
    min_word_len: int = 4,
    max_word_len: int = 8,
    wordlist_path: Optional[str] = None,
    allow_duplicates: bool = False,
    case_fold: bool = False,
) -> PassphraseResult:
    """
    توليد عبارة مرور مع تحليل مفصّل (إنتروبيا، مصدر القائمة، تحذيرات).

    المعاملات نفس generate_passphrase. يعيد PassphraseResult.
    """
    if num_words < 1:
        raise ValueError("عدد الكلمات يجب أن يكون 1 على الأقل.")
    if not separator:
        separator = "-"

    warning = ""
    if wordlist_path:
        words, unique_count = load_diceware_wordlist(
            wordlist_path, case_fold=case_fold,
            min_word_len=min_word_len, max_word_len=max_word_len)
        if unique_count == 0:
            raise ValueError(f"قائمة Diceware فارغة بعد الترشيح: {wordlist_path}")
        source = wordlist_path
        # تحذير إن كانت القائمة أصغر من 1000 كلمة
        if unique_count < 1000:
            warning = (f"القائمة تحتوي {unique_count} كلمة فقط — إنتروبيا منخفضة. "
                       f"استخدم قائمة EFF 7776 كلمة للإنتاج.")
    else:
        words = [w for w in _BUNDLED_PASSPHRASE_WORDS
                 if min_word_len <= len(w) <= max_word_len]
        if not words:
            words = list(_BUNDLED_PASSPHRASE_WORDS)
        unique_count = len(words)
        source = "bundled"
        warning = ("استخدام القائمة المدمجة الصغيرة (~70 كلمة) — ليست Diceware "
                   "إنتاجية. مرّر wordlist_path لقائمة EFF 7776 كلمة.")

    selected = _select_words(words, num_words, allow_duplicates)
    passphrase = separator.join(selected)
    entropy = passphrase_entropy_bits(num_words, unique_count, allow_duplicates)

    return PassphraseResult(
        passphrase=passphrase,
        num_words=num_words,
        separator=separator,
        wordlist_source=source,
        wordlist_unique_count=unique_count,
        allow_duplicates=allow_duplicates,
        entropy_bits=round(entropy, 2),
        selected_words=selected,
        warning=warning,
    )


__all__ = [
    "generate_password",
    "generate_passphrase",
    "generate_passphrase_detailed",
    "load_diceware_wordlist",
    "passphrase_entropy_bits",
    "PassphraseResult",
    "AMBIGUOUS",
    "SET_LOWER",
    "SET_UPPER",
    "SET_DIGIT",
    "SET_SYMBOL",
]
