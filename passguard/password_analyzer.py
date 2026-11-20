"""
passguard.password_analyzer
===========================

تحليل متقدّم لقوة كلمات المرور مع التمييز الصريح بين:

  1. **الإنتروبيا النظرية** (Theoretical Entropy): حدّ أعلى رياضي لفضاء
     المفاتيح = L × log2(N). لا تُقدَّم كأنّها تخمين فعلي.
  2. **قابلية التخمين** (Guessability): تصنيف وصفي يعتمد على الإنتروبيا +
     الأنماط المكتشفة + التعرّض للقاموس + (اختيارياً) zxcvbn.
  3. **خطر الأنماط** (Pattern Risk): تصنيف للأنماط الضعيفة المكتشفة.
  4. **التعرّض للقاموس** (Dictionary Exposure): مكشوفة / غير مكشوفة / لم يُفحص.
  5. **مقاومة التخمين التقديرية** (Guess Resistance): ملخّص بشري مقروء.

الأسس الرياضية (حقيقية، مُختبَرة):
  - حجم فضاء الأحرف (charset size):
      N = |مجموعة الأحرف المُستخدَمة فعلياً في كلمة المرور|
  - الإنتروبيا النظرية (Shannon، الحالة الأسوأ):
      H = L × log2(N)   وحدة: bits.
  - عدد التركيبات الممكنة:
      C = N^L
  - وقت الكسر التقديري (هجوم offline على تجزئة سريعة مثل NTLM):
      guesses_per_second = 10^10  (معدّل نموذجي لـ GPU ضدّ NTLM)
      seconds = C / 2 / guesses_per_second
      نُنسق النتيجة إلى ثوانٍ/دقائق/ساعات/أيام/سنوات/قرون.

ملاحظات أمنية مهمّة:
  - الإنتروبيا النظرية ليست مقياساً لقابلية التخمين الفعلية. كلمة "P@ssw0rd"
    لها إنتروبيا نظرية عالية نسبياً لكنّها ضعيفة عملياً لوجودها في القوائم.
  - hack_probability() السابقة كانت heuristic مُضلِّلة (نسبة مئوية عشوائية).
    حُفظت الدالة والحق لغرض التوافق الخلفي فقط، لكنّها لم تُعرَض بعد الآن في
    الواجهة أو التقارير. استخدم المقاييس الجديدة (guessability، pattern_risk،
    dictionary_exposure، guess_resistance).
  - إن لم تتوفّر zxcvbn، تستمرّ الأداة بتحليلها الخاص وتُشير صراحةً إلى
    غياب التحليل المتقدّم.

ملاحظة عن وقت الكسر: تقدير تحفّظي للحالة الأسوأ (هجوم offline على NTLM غير
مملّح). تجزئات Unix crypt الحديثة (bcrypt/argon2/yescrypt) أبطأ بملايين
المرّات، فيكون الوقت الفعلي أطول بكثير.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ===========================================================================
# الأصول الثابتة (المحفوظة من الإصدار السابق للتوافق الخلفي)
# ===========================================================================

# أحجام فضاءات الأحرف
CHARSET_LOWER = 26      # a-z
CHARSET_UPPER = 26      # A-Z
CHARSET_DIGIT = 10      # 0-9
CHARSET_SYMBOL = 33     # !@#$%^&*()... رموز قابلة للطباعة على لوحة المفاتيح

# معدّل تخمين offline نموذجي ضدّ تجزئة NTLM (GPU حديث)
GUESSES_PER_SECOND = 10 ** 10


def _charset_size(has_lower: bool, has_upper: bool,
                  has_digit: bool, has_symbol: bool) -> int:
    """حجم فضاء الأحرف الفعلي بناءً على الأصناف الموجودة."""
    n = 0
    if has_lower:
        n += CHARSET_LOWER
    if has_upper:
        n += CHARSET_UPPER
    if has_digit:
        n += CHARSET_DIGIT
    if has_symbol:
        n += CHARSET_SYMBOL
    return max(n, 1)


def compute_entropy(password: str) -> float:
    """الإنتروبيا النظرية بالـ bits = L × log2(N)."""
    if not password:
        return 0.0
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    n = _charset_size(has_lower, has_upper, has_digit, has_symbol)
    return len(password) * math.log2(n)


def compute_combinations(password: str) -> int:
    """عدد التركيبات الممكنة = N^L."""
    if not password:
        return 0
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    n = _charset_size(has_lower, has_upper, has_digit, has_symbol)
    return n ** len(password)


def format_crack_time(seconds: float) -> str:
    """تنسيق زمن الكسر إلى نص عربي مقروء."""
    if seconds < 0:
        return "N/A"
    if seconds < 1:
        return "أقل من ثانية"
    if seconds < 60:
        return f"{seconds:.0f} ثانية"
    if seconds < 3600:
        return f"{seconds / 60:.1f} دقيقة"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} ساعة"
    if seconds < 86400 * 30:
        return f"{seconds / 86400:.1f} يوم"
    if seconds < 86400 * 365:
        return f"{seconds / (86400 * 30):.1f} شهر"
    if seconds < 86400 * 365 * 100:
        years = seconds / (86400 * 365)
        if years < 1000:
            return f"{years:.1f} سنة"
        return f"{years:.0f} سنة"
    if seconds < 86400 * 365 * 1000:
        return f"{seconds / (86400 * 365 * 100):.1f} قرن"
    if seconds < 86400 * 365 * 1_000_000:
        return f"{seconds / (86400 * 365 * 1000):.0f} ألف سنة"
    if seconds < 86400 * 365 * 1_000_000_000:
        return f"{seconds / (86400 * 365 * 1_000_000):.0f} مليون سنة"
    return "ملايين السنين"


def estimate_crack_time(password: str,
                        guesses_per_second: int = GUESSES_PER_SECOND) -> str:
    """تقدير وقت الكسر كنص منسّق (افتراض هجوم offline على NTLM)."""
    if not password:
        return "N/A"
    combinations = compute_combinations(password)
    seconds = combinations / 2 / guesses_per_second
    return format_crack_time(seconds)


def estimate_crack_time_seconds(password: str,
                                guesses_per_second: int = GUESSES_PER_SECOND) -> float:
    """تقدير وقت الكسر بالثواني (رقم خام)."""
    if not password:
        return 0.0
    combinations = compute_combinations(password)
    return combinations / 2 / guesses_per_second


def entropy_to_level(entropy_bits: float) -> str:
    """تحويل الإنتروبيا النظرية إلى مستوى نصّي (مُحافَظ عليه للتوافق)."""
    if entropy_bits < 28:
        return "very_weak"
    if entropy_bits < 36:
        return "weak"
    if entropy_bits < 60:
        return "medium"
    if entropy_bits < 80:
        return "strong"
    if entropy_bits < 128:
        return "very_strong"
    return "excellent"


# ===========================================================================
# hack_probability() — مُحافَظ عليه للتوافق الخلفي فقط (مُهمل، لا يُعرَض)
# ===========================================================================
# ملاحظة: هذه الدالة كانت تُنتج نسبة مئوية عشوائية غير مدعومة بأساس علمي
# صارم. حُفظت لتفادي كسر الـ call sites القديمة، لكنّها لم تُعرَض بعد الآن
# في الواجهة أو التقارير. استخدم guessability / pattern_risk /
# dictionary_exposure / guess_resistance بدلاً منها.

def hack_probability(entropy_bits: float, in_wordlist: bool) -> int:
    """
    [مُهمل — للتوافق الخلفي فقط] تقدير احتمال الاختراق كنسبة مئوية.

    لا تستخدم هذه الدالة في واجهات جديدة. النسبة المئوية هنا heuristic
    غير موثوق. استخدم المقاييس الوصفية الجديدة بدلاً منها.
    """
    if in_wordlist:
        return 100
    if entropy_bits < 28:
        return 100
    if entropy_bits < 36:
        return 85
    if entropy_bits < 46:
        return 60
    if entropy_bits < 60:
        return 30
    if entropy_bits < 80:
        return 10
    if entropy_bits < 128:
        return 3
    return 1


# تسميات المستويات بالعربية (مُحافَظ عليها)
LEVEL_LABELS_AR = {
    "very_weak":   "ضعيفة جداً",
    "weak":        "ضعيفة",
    "medium":      "متوسطة",
    "strong":      "قوية",
    "very_strong": "قوية جداً",
    "excellent":   "ممتازة",
}

# ألوان المستويات (hex) — مُحافَظ عليها
LEVEL_COLORS = {
    "very_weak":   "#dc2626",
    "weak":        "#ea580c",
    "medium":      "#f59e0b",
    "strong":      "#22c55e",
    "very_strong": "#16a34a",
    "excellent":   "#15803d",
}


# ===========================================================================
# zxcvbn — تحليل قابلية التخمين (اختياري)
# ===========================================================================

try:
    from zxcvbn import zxcvbn as _zxcvbn_func  # type: ignore
    _HAS_ZXCVBN = True
except Exception:  # pragma: no cover — غياب zxcvbn شائع
    _zxcvbn_func = None
    _HAS_ZXCVBN = False


def is_zxcvbn_available() -> bool:
    """هل zxcvbn متاح للاستخدام؟"""
    return _HAS_ZXCVBN


def _run_zxcvbn(password: str) -> Optional[dict]:
    """تشغيل zxcvbn إن توفّر. يعيد dict مُختصر أو None."""
    if not _HAS_ZXCVBN or not password:
        return None
    try:
        result = _zxcvbn_func(password)
        feedback = result.get("feedback", {}) or {}
        suggestions = list(feedback.get("suggestions", []) or [])
        warning = feedback.get("warning", "")
        if warning:
            suggestions.insert(0, warning)
        return {
            "score": int(result.get("score", 0)),         # 0-4
            "guesses": int(result.get("guesses", 0)),
            "feedback": suggestions,
        }
    except Exception:
        return None


# ===========================================================================
# كشف الأنماط (Pattern Detection)
# ===========================================================================

@dataclass
class Pattern:
    """نمط ضعف مكتشف في كلمة المرور."""
    pattern_id: str          # معرّف آلي (repeated_char, numeric_sequence, ...)
    name: str                # اسم بصري (عربي)
    risk: str                # low / medium / high / critical
    explanation: str         # ما الذي اكتُشف
    remediation: str         # توصية الإصلاح
    location: str = ""       # مكان النمط في كلمة المرور (اختياري)


# ---- بيانات الأنماط ----

# صفوف لوحة المفاتيح القياسية (QWERTY) للكشف عن مسارات الأصابع
_KEYBOARD_ROWS_LOWER = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
]
# صف الأرقام + ما يقابله من رموز shifted
_KEYBOARD_DIGITS = "1234567890"
_KEYBOARD_SHIFTED = "!@#$%^&*()"

# البادئات الشائعة في كلمات المرور الضعيفة
COMMON_PREFIXES = {
    "pass", "password", "passwd", "pwd", "admin", "administrator",
    "root", "user", "guest", "test", "demo", "welcome", "hello",
    "letmein", "monkey", "dragon", "master", "super", "secret",
    "login", "signin", "qwer", "asdf", "zxcv", "abc", "qwerty",
}

# اللواحق الشائعة
COMMON_SUFFIXES = {
    "123", "1234", "12345", "123456", "1234567", "12345678",
    "!", "!!", "@", "#", "$", "1!", "12!", "123!",
    "2024", "2023", "2022", "2021", "2020", "2019",
    "01", "02", "99", "007", "420", "69", "666", "777",
    "abc", "xyz",
}


def _is_consecutive_ascending(chars: str, alphabet: str) -> bool:
    """هل السلسلة chars عبارة عن تتابع تصاعدي في alphabet؟"""
    if len(chars) < 3:
        return False
    idx = alphabet.find(chars[0])
    if idx < 0 or idx + len(chars) > len(alphabet):
        return False
    return alphabet[idx: idx + len(chars)] == chars


def _is_consecutive_descending(chars: str, alphabet: str) -> bool:
    """هل السلسلة chars عبارة عن تتابع تنازلي في alphabet؟"""
    return _is_consecutive_ascending(chars[::-1], alphabet)


def detect_repeated_chars(password: str) -> List[Pattern]:
    """كشف تكرار نفس الحرف 3+ مرّات متتالية (aaa, 111, ...)."""
    patterns: List[Pattern] = []
    for m in re.finditer(r"(.)\1{2,}", password):
        char = m.group(1)
        run = m.group(0)
        patterns.append(Pattern(
            pattern_id="repeated_char",
            name="تكرار حرف",
            risk="medium",
            explanation=f"الحرف '{char}' مكرّر {len(run)} مرّات متتالية في الموضع {m.start()}.",
            remediation="تجنّب تكرار نفس الحرف أكثر من مرّتين متتاليتين.",
            location=f"[{m.start()}:{m.end()}]",
        ))
    return patterns


def detect_numeric_sequences(password: str) -> List[Pattern]:
    """كشف تسلسلات رقمية تصاعدية/تنازلية (123, 987, ...) بطول 3+.

    نستخدم نافذة منزلقة بطول 3+ لاكتشاف التسلسلات حتى داخل مقاطع أرقام
    أطول (مثل '1234' في 'x1234y' أو '456' في '123456').
    """
    patterns: List[Pattern] = []
    digits_alphabet = "0123456789"
    # نجد كل مقاطع الأرقام بطول ≥ 3
    for m in re.finditer(r"\d{3,}", password):
        run = m.group(0)
        run_start = m.start()
        # لكل موضع داخل المقطع، نبحث عن أطول تسلسل تصاعدي/تنازلي يبدأ منه
        i = 0
        reported: List[tuple] = []
        while i < len(run) - 2:
            # أطول تسلسل تصاعدي يبدأ عند i
            asc_len = 0
            for j in range(i, len(run) - 1):
                if (digits_alphabet.find(run[j]) >= 0 and
                        digits_alphabet.find(run[j + 1]) >= 0 and
                        digits_alphabet.find(run[j + 1]) ==
                        digits_alphabet.find(run[j]) + 1):
                    asc_len += 1
                else:
                    break
            # أطول تسلسل تنازلي يبدأ عند i
            desc_len = 0
            for j in range(i, len(run) - 1):
                if (digits_alphabet.find(run[j]) >= 0 and
                        digits_alphabet.find(run[j + 1]) >= 0 and
                        digits_alphabet.find(run[j + 1]) ==
                        digits_alphabet.find(run[j]) - 1):
                    desc_len += 1
                else:
                    break
            # نأخذ الأطول (تصاعدي أو تنازلي)
            best_len = max(asc_len, desc_len)
            best_kind = "ascending" if asc_len >= desc_len else "descending"
            if best_len >= 2:   # طول ≥ 3 (2 انتقال = 3 أحرف)
                seq = run[i: i + best_len + 1]
                span = (run_start + i, run_start + i + best_len + 1)
                # نتخطّى إن كان داخل تسلسل سابق
                if not any(s[0] <= span[0] and span[1] <= s[1] for s in reported):
                    pid = (f"numeric_sequence_{best_kind}")
                    patterns.append(Pattern(
                        pattern_id=pid,
                        name=f"تسلسل رقمي {'تصاعدي' if best_kind == 'ascending' else 'تنازلي'}",
                        risk="high",
                        explanation=f"التسلسل الرقمي '{seq}' {'تصاعدي' if best_kind == 'ascending' else 'تنازلي'} ومتوقّع.",
                        remediation="تجنّب التسلسلات الرقمية المتتالية (1234, 9876).",
                        location=f"[{span[0]}:{span[1]}]",
                    ))
                    reported.append(span)
                i += best_len + 1
            else:
                i += 1
    return patterns


def detect_alpha_sequences(password: str) -> List[Pattern]:
    """كشف تسلسلات أبجدية تصاعدية/تنازلية (abcd, dcba, ...) بطول 3+.

    نستخدم نافذة منزلقة لاكتشاف التسلسلات حتى داخل مقاطع أحرف أطول
    (مثل 'abcd' في 'xyzabcd123').
    """
    patterns: List[Pattern] = []
    lower_alpha = "abcdefghijklmnopqrstuvwxyz"
    # نجد كل مقاطع الأحرف بطول ≥ 3
    for m in re.finditer(r"[a-zA-Z]{3,}", password):
        run = m.group(0)
        run_lower = run.lower()
        run_start = m.start()
        i = 0
        reported: List[tuple] = []
        while i < len(run) - 2:
            asc_len = 0
            for j in range(i, len(run) - 1):
                if (lower_alpha.find(run_lower[j]) >= 0 and
                        lower_alpha.find(run_lower[j + 1]) >= 0 and
                        lower_alpha.find(run_lower[j + 1]) ==
                        lower_alpha.find(run_lower[j]) + 1):
                    asc_len += 1
                else:
                    break
            desc_len = 0
            for j in range(i, len(run) - 1):
                if (lower_alpha.find(run_lower[j]) >= 0 and
                        lower_alpha.find(run_lower[j + 1]) >= 0 and
                        lower_alpha.find(run_lower[j + 1]) ==
                        lower_alpha.find(run_lower[j]) - 1):
                    desc_len += 1
                else:
                    break
            best_len = max(asc_len, desc_len)
            best_kind = "ascending" if asc_len >= desc_len else "descending"
            if best_len >= 2:
                seq = run[i: i + best_len + 1]
                span = (run_start + i, run_start + i + best_len + 1)
                if not any(s[0] <= span[0] and span[1] <= s[1] for s in reported):
                    pid = f"alpha_sequence_{best_kind}"
                    patterns.append(Pattern(
                        pattern_id=pid,
                        name=f"تسلسل أبجدي {'تصاعدي' if best_kind == 'ascending' else 'تنازلي'}",
                        risk="high",
                        explanation=f"التسلسل الأبجدي '{seq}' {'تصاعدي' if best_kind == 'ascending' else 'تنازلي'} ومتوقّع.",
                        remediation="تجنّب التسلسلات الأبجدية (abcd, dcba).",
                        location=f"[{span[0]}:{span[1]}]",
                    ))
                    reported.append(span)
                i += best_len + 1
            else:
                i += 1
    return patterns


def detect_keyboard_sequences(password: str) -> List[Pattern]:
    """كشف مسارات لوحة المفاتيح (qwerty, asdfgh, 1234, ...) بطول 4+.

    نكتشف فقط أطول مسار متّصل لكل موضع بداية في كلمة المرور، لتفادي
    الإبلاغ عن أجزاء متداخلة (qwer / qwert / qwerty لنفس المسار).
    """
    patterns: List[Pattern] = []
    pw_lower = password.lower()
    min_len = 4
    rows = _KEYBOARD_ROWS_LOWER + [_KEYBOARD_DIGITS]
    # لكل صف، نبني خريطة موضع→طويل مسار ممكن
    i = 0
    n = len(pw_lower)
    reported_spans: List[tuple] = []
    while i < n:
        best_len = 0
        best_frag = ""
        best_row = ""
        for row in rows:
            # كم حرفاً متتالياً من موضع i يطابق تتابعاً في row؟
            # نبحث عن أطول تتابع في row يبدأ عند pw[i]
            # نجرّب كل طول من الأطول فالأقصر
            max_possible = min(len(row), n - i)
            for length in range(max_possible, min_len - 1, -1):
                # هل pw[i:i+length] هو تتابع في row (تصاعدي أو تنازلي)؟
                for row_start in range(len(row) - length + 1):
                    candidate = row[row_start: row_start + length]
                    if pw_lower[i: i + length] == candidate:
                        if length > best_len:
                            best_len = length
                            best_frag = candidate
                            best_row = row
                        break
                else:
                    continue
                break   # وجدنا أطول تتابع لهذا الطول
        if best_len >= min_len:
            # نتأكّد عدم التداخل مع نمط سابق
            span = (i, i + best_len)
            if not any(s[0] <= i < s[1] or s[0] < i + best_len <= s[1]
                       for s in reported_spans):
                patterns.append(Pattern(
                    pattern_id="keyboard_sequence",
                    name="مسار لوحة مفاتيح",
                    risk="high",
                    explanation=f"النمط '{best_frag}' مسار متّصل على لوحة المفاتيح.",
                    remediation="تجنّب أنماط لوحة المفاتيح (qwerty, asdfgh, zxcvbn, 1234).",
                    location=f"[{i}:{i + best_len}]",
                ))
                reported_spans.append(span)
            i += best_len
        else:
            i += 1
    return patterns


def detect_common_prefixes(password: str) -> List[Pattern]:
    """كشف البادئات الشائعة (password, admin, welcome, ...)."""
    patterns: List[Pattern] = []
    pw_lower = password.lower()
    for prefix in sorted(COMMON_PREFIXES, key=len, reverse=True):
        if pw_lower.startswith(prefix) and len(prefix) >= 3:
            patterns.append(Pattern(
                pattern_id="common_prefix",
                name="بادئة شائعة",
                risk="high",
                explanation=f"كلمة المرور تبدأ بالبادئة الشائعة '{prefix}'.",
                remediation="تجنّب البدء بكلمات قاموسية شائعة.",
                location=f"[0:{len(prefix)}]",
            ))
            break   # نُبلغ عن أطول بادئة فقط
    return patterns


def detect_common_suffixes(password: str) -> List[Pattern]:
    """كشف اللواحق الشائعة (123, !, 2024, ...)."""
    patterns: List[Pattern] = []
    pw_lower = password.lower()
    for suffix in sorted(COMMON_SUFFIXES, key=len, reverse=True):
        if pw_lower.endswith(suffix) and len(suffix) >= 2:
            patterns.append(Pattern(
                pattern_id="common_suffix",
                name="لاحقة شائعة",
                risk="medium",
                explanation=f"كلمة المرور تنتهي باللاحقة الشائعة '{suffix}'.",
                remediation="تجنّب إلحاق أرقام/رموز متوقّعة بنهاية كلمة قاموسية.",
                location=f"[{len(password) - len(suffix)}:{len(password)}]",
            ))
            break
    return patterns


def detect_years(password: str) -> List[Pattern]:
    """كشف أنماط السنوات (1900-2039)."""
    patterns: List[Pattern] = []
    for m in re.finditer(r"(?:19\d{2}|20[0-3]\d)", password):
        year = m.group(0)
        patterns.append(Pattern(
            pattern_id="year",
            name="سنة",
            risk="medium",
            explanation=f"السنة '{year}' موجودة في كلمة المرور (تُخمَّس بسهولة).",
            remediation="تجنّب استخدام السنوات (تواريح الميلاد، أحداث).",
            location=f"[{m.start()}:{m.end()}]",
        ))
    return patterns


def detect_dates(password: str) -> List[Pattern]:
    """كشف أنماط التواريخ (MMDDYYYY, DDMMYYYY, YYYYMMDD, MMDDYY, ...).

    نتحقّق من صحّة مكوّنات التاريخ (شهر 01-12، يوم 01-31) لتفادي الإيجابيات
    الخاطئة على تسلسلات أرقام صرفة. نُبلِغ عن أطول نمط تاريخ لكل موضع فقط.
    """
    patterns: List[Pattern] = []
    # (regex, label, group order: which group is year/month/day)
    # نرتّب من الأطول فالأقصر لإعطاء الأولوية للأنماط الأكثر تحديداً
    date_patterns = [
        (r"(?<!\d)(\d{4})(\d{2})(\d{2})(?!\d)", "YYYYMMDD", "ymd"),
        (r"(?<!\d)(\d{2})(\d{2})(\d{4})(?!\d)", "DDMMYYYY/MMDDYYYY", "dmy"),
        (r"(?<!\d)(\d{2})(\d{2})(\d{2})(?!\d)", "DDMMYY/MMDDYY", "dmy"),
    ]
    reported_spans: List[tuple] = []
    for regex, label, order in date_patterns:
        for m in re.finditer(regex, password):
            span = (m.start(), m.end())
            # نتخطّى إن كان داخل نمط تاريخ أطول أبلغنا عنه
            if any(s[0] <= span[0] and span[1] <= s[1] for s in reported_spans):
                continue
            groups = m.groups()
            if order == "ymd":
                year, month, day = groups
            else:
                d1, d2, d3 = groups
                # d1=day or month, d2=month or day, d3=year(2 or 4)
                # نتحقّق: أحد d1/d2 يجب أن يكون شهراً صالحاً (01-12)
                # والآخر يوماً صالحاً (01-31)
                try:
                    v1, v2 = int(d1), int(d2)
                except ValueError:
                    continue
                if 1 <= v1 <= 12 and 1 <= v2 <= 31:
                    month, day = d1, d2
                elif 1 <= v2 <= 12 and 1 <= v1 <= 31:
                    month, day = d2, d1
                else:
                    continue   # لا يُشبه تاريخاً صالحاً
                year = d3
            # تحقّق نهائي: شهر 01-12، يوم 01-31
            try:
                mi, di = int(month), int(day)
            except ValueError:
                continue
            if not (1 <= mi <= 12 and 1 <= di <= 31):
                continue
            patterns.append(Pattern(
                pattern_id="date_pattern",
                name="نمط تاريخ",
                risk="medium",
                explanation=f"النمط '{m.group(0)}' يشبه تاريخاً ({label}).",
                remediation="تجنّب استخدام التواريخ في كلمات المرور.",
                location=f"[{m.start()}:{m.end()}]",
            ))
            reported_spans.append(span)
    return patterns


def detect_repeated_substrings(password: str) -> List[Pattern]:
    """كشف المقاطع المكرّرة (abcabc, 1212, passpass, ...).

    نُبلِغ فقط عن أطول مقطع مكرّر لكل موضع بداية، لتفادي الإبلاغ عن
    مقاطع متداخلة (abc / abcabc لنفس التكرار).
    """
    patterns: List[Pattern] = []
    n = len(password)
    reported_spans: List[tuple] = []
    # نبدأ بأطوال أكبر أولاً (أولوية للمقاطع الطويلة)
    for seg_len in range(n // 2, 1, -1):
        for start in range(n - seg_len * 2 + 1):
            seg = password[start: start + seg_len]
            # هل يتكرّر مباشرة مرّتين أو أكثر؟
            repeats = 1
            pos = start + seg_len
            while password[pos: pos + seg_len] == seg:
                repeats += 1
                pos += seg_len
            if repeats >= 2:
                span = (start, pos)
                # نتخطّى إن كان هذا المقطع داخل مقطع أطول أبلغنا عنه سابقاً
                if any(s[0] <= start and pos <= s[1] for s in reported_spans):
                    continue
                if any(not (pos <= s[0] or start >= s[1])
                       for s in reported_spans):
                    continue
                patterns.append(Pattern(
                    pattern_id="repeated_substring",
                    name="مقطع مكرّر",
                    risk="medium",
                    explanation=f"المقطع '{seg}' مكرّر {repeats} مرّات متتالية.",
                    remediation="تجنّب تكرار نفس المقطع (abcabc, passpass).",
                    location=f"[{start}:{pos}]",
                ))
                reported_spans.append(span)
    return patterns


def detect_common_structures(password: str) -> List[Pattern]:
    """كشف الهياكل الشائعة لكلمات المرور الضعيفة."""
    patterns: List[Pattern] = []
    # هيكل: كلمة + أرقام في النهاية
    m = re.match(r"^([a-zA-Z]{3,})(\d{1,4})$", password)
    if m:
        word_part = m.group(1).lower()
        if word_part in COMMON_PREFIXES or len(m.group(2)) <= 2:
            patterns.append(Pattern(
                pattern_id="structure_word_digits",
                name="هيكل كلمة+أرقام",
                risk="medium",
                explanation="كلمة قاموسية متبوعة بأرقام — هيكل شائع جداً في القوائم.",
                remediation="استخدم بنية أقل توقّعاً (أحرف ورموز متداخلة).",
            ))
    # هيكل: كلمة + رمز في النهاية
    m = re.match(r"^([a-zA-Z]{3,})([!@#$%^&*]{1,2})$", password)
    if m:
        patterns.append(Pattern(
            pattern_id="structure_word_symbol",
            name="هيكل كلمة+رمز",
            risk="low",
            explanation="كلمة قاموسية متبوعة برمز واحد — تحويل شائع (password!).",
            remediation="وزّع الرموز داخل الكلمة بدلاً من إلحاقها بالنهاية فقط.",
        ))
    # هيكل: كلمة بحرف أول كبير + أرقام (Password123)
    if re.match(r"^[A-Z][a-z]{2,}\d{1,4}$", password):
        patterns.append(Pattern(
            pattern_id="structure_capital_word_digits",
            name="هيكل كلمة كبيرة+أرقام",
            risk="medium",
            explanation="كلمة بحرف أول كبير متبوعة بأرقام — تحويل قاموسي شائع.",
            remediation="تجنّب التحويلات القاموسية المتوقّعة (Leet, Capitalize+digits).",
        ))
    return patterns


def detect_patterns(password: str) -> List[Pattern]:
    """تجميع كل أنماط الضعف المكتشفة في كلمة المرور."""
    if not password:
        return []
    all_patterns: List[Pattern] = []
    all_patterns.extend(detect_repeated_chars(password))
    all_patterns.extend(detect_numeric_sequences(password))
    all_patterns.extend(detect_alpha_sequences(password))
    all_patterns.extend(detect_keyboard_sequences(password))
    all_patterns.extend(detect_common_prefixes(password))
    all_patterns.extend(detect_common_suffixes(password))
    all_patterns.extend(detect_years(password))
    all_patterns.extend(detect_dates(password))
    all_patterns.extend(detect_repeated_substrings(password))
    all_patterns.extend(detect_common_structures(password))
    return all_patterns


# ===========================================================================
# تصنيف المقاييس الجديدة
# ===========================================================================

# مستويات خطر الأنماط
_PATTERN_RISK_ORDER = ["none", "low", "medium", "high", "critical"]


def _risk_rank(risk: str) -> int:
    try:
        return _PATTERN_RISK_ORDER.index(risk)
    except ValueError:
        return 0


def classify_pattern_risk(patterns: List[Pattern]) -> str:
    """تصنيف خطر الأنماط المكتشفة إلى مستوى واحد."""
    if not patterns:
        return "none"
    max_risk = max(p.risk for p in patterns)
    # إن وُجد نمطان عالي الخطورة أو أكثر → حرج
    high_count = sum(1 for p in patterns if _risk_rank(p.risk) >= _risk_rank("high"))
    if high_count >= 2 or max_risk == "critical":
        return "critical"
    return max_risk


# مستويات قابلية التخمين
GUESSABILITY_LEVELS = ["trivial", "low", "moderate", "high", "very_high"]

GUESSABILITY_LABELS_AR = {
    "trivial":    "تافته (تُخمَّس فوراً)",
    "low":        "منخفضة",
    "moderate":   "متوسطة",
    "high":       "عالية (صعبة التخمين)",
    "very_high":  "عالية جداً",
}

PATTERN_RISK_LABELS_AR = {
    "none":     "لا أنماط",
    "low":      "منخفض",
    "medium":   "متوسط",
    "high":     "عالي",
    "critical": "حرج",
}

DICTIONARY_EXPOSURE_LABELS_AR = {
    "exposed":     "مكشوفة في القائمة",
    "not_exposed": "غير مكشوفة",
    "not_checked": "لم يُفحص",
}


def classify_guessability(entropy_bits: float,
                          patterns: List[Pattern],
                          in_wordlist: bool,
                          zxcvbn_score: Optional[int] = None) -> str:
    """
    تصنيف قابلية التخمين إلى مستوى وصفي.

    يعتمد على: التعرّض للقاموس، الإنتروبيا النظرية، الأنماط، ونتيجة zxcvbn
    إن توفّرت. هذا تصنيف وصفي وليس نسبة مئوية عشوائية.
    """
    # التعرّض للقاموس = تافته دائماً
    if in_wordlist:
        return "trivial"
    # zxcvbn (إن توفّر) هو المصدر الأكثر موثوقية
    if zxcvbn_score is not None:
        # score 0-4 → trivial/low/moderate/high/very_high
        mapping = ["trivial", "low", "moderate", "high", "very_high"]
        zx_level = mapping[min(zxcvbn_score, 4)]
        # لكن إن كانت هناك أنماط حرجة، نخفض مستوى واحد
        pattern_risk = classify_pattern_risk(patterns)
        if pattern_risk == "critical" and zx_level not in ("trivial", "low"):
            return "low"
        return zx_level
    # بدون zxcvbn: نعتمد على الإنتروبيا + الأنماط
    pattern_risk = classify_pattern_risk(patterns)
    if entropy_bits < 28 or pattern_risk == "critical":
        return "trivial"
    if entropy_bits < 45 or pattern_risk == "high":
        return "low"
    if entropy_bits < 60 or pattern_risk == "medium":
        return "moderate"
    if entropy_bits < 80:
        return "high"
    return "very_high"


def classify_dictionary_exposure(in_wordlist: bool,
                                  wordlist_checked: bool) -> str:
    """تصنيف التعرّض للقاموس."""
    if not wordlist_checked:
        return "not_checked"
    return "exposed" if in_wordlist else "not_exposed"


def compute_guess_resistance(entropy_bits: float,
                             guessability: str,
                             pattern_risk: str,
                             dictionary_exposure: str,
                             zxcvbn_guesses: Optional[int] = None) -> str:
    """
    توليد نص بشري مقروء يصف مقاومة كلمة المرور للتخمين.

    هذا ملخّص تفسيري، وليس نسبة مئوية. يجمع كل المقاييس في جملة واضحة.
    """
    if dictionary_exposure == "exposed":
        return "كلمة المرور مكشوفة في قائمة التسريبات — تُخمَّس فوراً. غيّرها."
    if dictionary_exposure == "not_checked":
        prefix = "لم يُفحص التعرّض للقاموس. "
    else:
        prefix = ""
    if guessability == "trivial":
        return prefix + "قابلية التخمين تافته — تُكسَر فوراً بأبسط هجوم."
    if guessability == "low":
        return prefix + "قابلية تخمين منخفضة — ضعيفة ضدّ هجمات القاموس الموسّعة."
    if guessability == "moderate":
        return prefix + "قابلية تخمين متوسطة — قد تُكسَر بهجوم offline مركّز."
    if guessability == "high":
        return prefix + "قابلية تخمين عالية — صعبة على هجمات القاموس لكنّها ليست مضمونة."
    if guessability == "very_high":
        return prefix + "قابلية تخمين عالية جداً — مقاومة جيدة للهجمات الحالية."
    return prefix + "غير مصنّفة."


# ألوان المقاييس الجديدة (للواجهة)
GUESSABILITY_COLORS = {
    "trivial":   "#dc2626",
    "low":       "#ea580c",
    "moderate":  "#f59e0b",
    "high":      "#22c55e",
    "very_high": "#15803d",
}

PATTERN_RISK_COLORS = {
    "none":     "#22c55e",
    "low":      "#84cc16",
    "medium":   "#f59e0b",
    "high":     "#ea580c",
    "critical": "#dc2626",
}

DICTIONARY_EXPOSURE_COLORS = {
    "exposed":     "#dc2626",
    "not_exposed": "#22c55e",
    "not_checked": "#94a3b8",
}


# ===========================================================================
# نموذج نتيجة التحليل (موسّع مع الحفاظ على الحقول القديمة)
# ===========================================================================

@dataclass
class PasswordAnalysis:
    """نتيجة تحليل كلمة مرور (موسّعة، متوافقة مع الإصدار السابق)."""
    # --- حقول محفوظة (للتوافق الخلفي) ---
    password_length: int
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    charset_size: int
    entropy_bits: float                        # إنتروبيا نظرية (ليست تخميناً فعلياً)
    combinations: int
    crack_time_text: str
    crack_time_seconds: float
    hack_prob: int                             # [مُهمل] للتوافق الخلفي فقط
    in_wordlist: bool
    has_repeats: bool
    has_sequences: bool
    has_keyboard_pattern: bool
    has_year: bool
    level: str                                 # very_weak/weak/medium/strong/very_strong/excellent
    score: int                                 # 0-100
    checklist: dict
    suggestions: List[str]
    # --- حقول جديدة (لها قيم افتراضية للتوافق الخلفي) ---
    patterns: List[Pattern] = field(default_factory=list)
    guessability: str = "moderate"
    pattern_risk: str = "none"
    dictionary_exposure: str = "not_checked"
    guess_resistance: str = ""
    wordlist_checked: bool = False
    zxcvbn_available: bool = False
    zxcvbn_score: Optional[int] = None
    zxcvbn_guesses: Optional[int] = None
    zxcvbn_feedback: Optional[List[str]] = None
    analysis_notes: List[str] = field(default_factory=list)


# ===========================================================================
# واجهة التحليل الرئيسية (موسّعة)
# ===========================================================================

def classify_interactive_password(analysis: PasswordAnalysis,
                                  wordlist_checked: bool) -> str:
    """Return a stable English status category for the interactive checker."""
    if not wordlist_checked:
        return "ANALYSIS_INCOMPLETE"
    if analysis.dictionary_exposure == "exposed":
        return "COMMON_PASSWORD"
    if analysis.level in ("very_weak", "weak"):
        return "WEAK"
    if analysis.level in ("medium",):
        return "STRONGER_PASSWORD_RECOMMENDED"
    return "NOT_IN_WORDLIST"


def analyze_password(password: str,
                     in_wordlist: bool = False,
                     wordlist_checked: bool = True) -> PasswordAnalysis:
    """
    تحليل شامل لكلمة مرور.

    المعاملات:
        password:         كلمة المرور كنص.
        in_wordlist:      هل هي موجودة في القائمة الشائعة؟ (يُحسبها المُستدعي).
        wordlist_checked: هل فُحصت ضدّ قائمة فعلاً؟ (إن False → dictionary_exposure
                          يكون "not_checked").

    يعيد PasswordAnalysis بكل المقاييس (القديمة للتوافق + الجديدة).

    ملاحظة: الإنتروبيا النظرية (entropy_bits) ليست مقياساً لقابلية التخمين
    الفعلية. استخدم guessability / pattern_risk / dictionary_exposure /
    guess_resistance للمقاييس الموثوقة.
    """
    pw = password or ""
    length = len(pw)
    has_lower = bool(re.search(r"[a-z]", pw))
    has_upper = bool(re.search(r"[A-Z]", pw))
    has_digit = bool(re.search(r"\d", pw))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pw))

    n = _charset_size(has_lower, has_upper, has_digit, has_symbol)
    entropy = compute_entropy(pw)
    combinations = compute_combinations(pw)
    crack_sec = estimate_crack_time_seconds(pw)
    crack_text = estimate_crack_time(pw)
    # hack_prob محفوظ للتوافق الخلفي فقط (مُهمل)
    hack_prob = hack_probability(entropy, in_wordlist)
    level = entropy_to_level(entropy)
    # إن كانت في القائمة الشائعة، المستوى "very_weak" مهما كانت الإنتروبيا
    if in_wordlist:
        level = "very_weak"

    # كشف الأنماط الموسّع
    patterns = detect_patterns(pw)
    has_repeats = any(p.pattern_id == "repeated_char" for p in patterns)
    has_sequences = any(p.pattern_id.startswith("numeric_sequence") or
                        p.pattern_id.startswith("alpha_sequence")
                        for p in patterns)
    has_keyboard = any(p.pattern_id == "keyboard_sequence" for p in patterns)
    has_year = any(p.pattern_id == "year" for p in patterns)

    # قائمة التحقّق (محفوظة)
    checklist = {
        "length_12": length >= 12,
        "length_16": length >= 16,
        "lower": has_lower,
        "upper": has_upper,
        "digit": has_digit,
        "symbol": has_symbol,
        "not_in_wordlist": not in_wordlist,
        "no_repeats": not has_repeats,
        "no_sequences": not has_sequences,
        "no_keyboard": not has_keyboard,
        "no_year": not has_year,
        "no_patterns": len(patterns) == 0,
    }

    # الدرجة الكلية (0-100) — محفوظة مع تحسين طفيف
    score = 0
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 12
    elif length > 0:
        score += 3
    classes = sum([has_lower, has_upper, has_digit, has_symbol])
    score += classes * 7
    if classes >= 3:
        score += 2
    if entropy >= 80:
        score += 25
    elif entropy >= 60:
        score += 18
    elif entropy >= 45:
        score += 10
    elif entropy >= 28:
        score += 4
    # غياب الأنماط الضعيفة (10) — فقط إن كانت كلمة المرور بطول كافٍ (≥ 8)
    # لأنّ كلمة قصيرة جداً ضعيفة حتى لو خلت من الأنماط المعروفة
    if length >= 8 and not patterns:
        score += 10
    elif length >= 8:
        # عقوبة تناسبية مع عدد الأنماط وخطورتها
        penalty = sum(_risk_rank(p.risk) for p in patterns)
        score -= penalty * 2
    # إن كانت أقصر من 8، لا مكافأة ولا عقوبة على الأنماط
    if in_wordlist:
        score = min(score, 5)
    score = max(0, min(100, score))

    # zxcvbn (اختياري)
    zx_result = _run_zxcvbn(pw)
    zxcvbn_available = _HAS_ZXCVBN
    zxcvbn_score = zx_result["score"] if zx_result else None
    zxcvbn_guesses = zx_result["guesses"] if zx_result else None
    zxcvbn_feedback = zx_result["feedback"] if zx_result else None

    # المقاييس الجديدة
    pattern_risk = classify_pattern_risk(patterns)
    guessability = classify_guessability(entropy, patterns, in_wordlist,
                                         zxcvbn_score)
    dictionary_exposure = classify_dictionary_exposure(in_wordlist,
                                                       wordlist_checked)
    guess_resistance = compute_guess_resistance(entropy, guessability,
                                                pattern_risk,
                                                dictionary_exposure,
                                                zxcvbn_guesses)

    # ملاحظات تحليلية
    analysis_notes: List[str] = []
    if not zxcvbn_available:
        analysis_notes.append(
            "التحليل المتقدّم (zxcvbn) غير متاح — النتائج تعتمد على المحلّل "
            "الداخلي. ثبّت zxcvbn لتحسين دقّة قابلية التخمين."
        )
    if entropy >= 80 and in_wordlist:
        analysis_notes.append(
            "كلمة المرور لها إنتروبيا نظرية عالية لكنّها مكشوفة في القائمة — "
            "الإنتروبيا النظرية لا تعني أماناً فعلياً."
        )
    if not wordlist_checked:
        analysis_notes.append(
            "لم يُفحص التعرّض للقاموس — لا يمكن الجزم بعدم وجود كلمة المرور "
            "في قوائم التسريبات."
        )

    # اقتراحات (محفوظة + مُعزَّزة بزxcvbn feedback)
    suggestions: List[str] = []
    if in_wordlist:
        suggestions.append("⚠️ كلمة المرور مُدرجة في قائمة التسريبات — غيّرها فوراً.")
    if length < 12:
        suggestions.append("استخدم 12 حرفاً على الأقل (16+ مُفضّل).")
    if not has_upper:
        suggestions.append("أضف أحرفاً كبيرة (A-Z).")
    if not has_lower:
        suggestions.append("أضف أحرفاً صغيرة (a-z).")
    if not has_digit:
        suggestions.append("أضف أرقاماً (0-9).")
    if not has_symbol:
        suggestions.append("أضف رموزاً (!@#$%^&*).")
    # اقتراحات من الأنماط المكتشفة
    for p in patterns:
        if p.remediation not in suggestions:
            suggestions.append(p.remediation)
    # اقتراحات zxcvbn (إن توفّرت ولم تكن مكرّرة)
    if zxcvbn_feedback:
        for s in zxcvbn_feedback:
            if s and s not in suggestions:
                suggestions.append(s)
    if not suggestions:
        suggestions.append("كلمة مرور قوية. واصل اعتماد هذه السياسة في اختيار كلمات المرور.")

    return PasswordAnalysis(
        password_length=length,
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        charset_size=n,
        entropy_bits=round(entropy, 2),
        combinations=combinations,
        crack_time_text=crack_text,
        crack_time_seconds=crack_sec,
        hack_prob=hack_prob,                    # مُهمل، للتوافق
        in_wordlist=in_wordlist,
        has_repeats=has_repeats,
        has_sequences=has_sequences,
        has_keyboard_pattern=has_keyboard,
        has_year=has_year,
        level=level,
        score=score,
        checklist=checklist,
        suggestions=suggestions,
        # حقول جديدة
        patterns=patterns,
        guessability=guessability,
        pattern_risk=pattern_risk,
        dictionary_exposure=dictionary_exposure,
        guess_resistance=guess_resistance,
        wordlist_checked=wordlist_checked,
        zxcvbn_available=zxcvbn_available,
        zxcvbn_score=zxcvbn_score,
        zxcvbn_guesses=zxcvbn_guesses,
        zxcvbn_feedback=zxcvbn_feedback,
        analysis_notes=analysis_notes,
    )


__all__ = [
    # محفوظة (للتوافق الخلفي)
    "PasswordAnalysis",
    "analyze_password",
    "compute_entropy",
    "compute_combinations",
    "estimate_crack_time",
    "estimate_crack_time_seconds",
    "format_crack_time",
    "entropy_to_level",
    "LEVEL_LABELS_AR",
    "LEVEL_COLORS",
    "GUESSES_PER_SECOND",
    # مُهملة (محفوظة للتوافق)
    "hack_probability",
    # جديدة
    "Pattern",
    "detect_patterns",
    "detect_repeated_chars",
    "detect_numeric_sequences",
    "detect_alpha_sequences",
    "detect_keyboard_sequences",
    "detect_common_prefixes",
    "detect_common_suffixes",
    "detect_years",
    "detect_dates",
    "detect_repeated_substrings",
    "detect_common_structures",
    "classify_guessability",
    "classify_pattern_risk",
    "classify_dictionary_exposure",
    "compute_guess_resistance",
    "is_zxcvbn_available",
    "GUESSABILITY_LABELS_AR",
    "GUESSABILITY_COLORS",
    "PATTERN_RISK_LABELS_AR",
    "PATTERN_RISK_COLORS",
    "DICTIONARY_EXPOSURE_LABELS_AR",
    "DICTIONARY_EXPOSURE_COLORS",
    "GUESSABILITY_LEVELS",
    "COMMON_PREFIXES",
    "COMMON_SUFFIXES",
]
