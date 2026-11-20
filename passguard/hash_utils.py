"""
passguard.hash_utils
====================

وحدة دوال التجزئة (Hashing) المستخدمة في الأداة.

تحتوي على:
  1. تنفيذ MD4 بـ Python خالصة (نسخة احتياطية) لأن OpenSSL 3.x في
     كثير من التوزيعات الحديثة يعطّل MD4 افتراضياً. NTLM = MD4(UTF-16LE(pw)).
  2. compute_ntlm(password) — تستخدم passlib إن توفّر، وإلا MD4 المحلي.
  3. تحليل حقول /etc/shadow (الخوارزمية + الملح).
  4. backend تجزئة Unix: passlib أولاً (إن توفّر)، ثم crypt.crypt احتياطياً
     (مع تطبيع تحذير الإهمال)، ثم "unsupported" صريح إن لم يتوفّر أيّ منهما.
     هذا يدعم Python 3.13+ حيث أُزيلت وحدة crypt.
  5. دوال مساعدة لإخفاء كلمات المرور في التقارير.

قواعد أمنية:
  - لا استبدال صامت لخوارزمية أخرى. إن تعذّر التحقق من خوارزمية، نُعيد
    "unsupported" صريحاً.
  - مقارنة ثابتة الزمن (hmac.compare_digest) لتجنّب تسريب التوقيت.
  - لا تُخزّن هذه الوحدة أي كلمة مرور في سجلات.

توافق خلفي:
  - كل الدوال العامة محفوظة بنفس التوقيعات.
  - verify_unix_password(password, full_field) -> bool محفوظة (تُعيد True
    فقط عند التطابق).
  - دوال جديدة: verify_unix_hash, get_hash_backend, can_verify_algo,
    BACKEND_INFO.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import unicodedata
import warnings
from typing import Optional, Tuple

# ---------------------------------------------------------------------------
# متجهات اختبار معروفة (للتحقق من صحة التنفيذ أثناء الاختبارات)
#   NTLM("password")        = 8846F7EAEE8FB117AD06BDD830B7586C
#   NTLM("Password")        = A4F49C406510BDCAB6824EE7C30FD852
#   NTLM("")                = 31D6CFE0D16AE931B73C59D7E0C089C0
#   MD4("")                 = 31d6cfe0d16ae931b73c59d7e0c089c0
#   MD4("abc")              = a448017aaf21d8525fc10ae87aa6729d
# ---------------------------------------------------------------------------

# ===========================================================================
# استيراد backends التجزئة (passlib اختياري، crypt مُهمل لكن نحاوله)
# ===========================================================================

# --- passlib (اختياري لكن مُفضّل: مُختبَر، يدعم bcrypt/argon2/sha256_crypt...) ---
try:
    from passlib.context import CryptContext as _CryptContext
    from passlib.exc import UnknownHashError as _PasslibUnknownHashError
    # نبني CryptContext بكل المخططات المعروفة لـ Unix crypt
    _PASSLIB_CTX = _CryptContext(schemes=[
        "sha512_crypt", "sha256_crypt", "md5_crypt",
        "bcrypt", "bcrypt_sha256",
        "des_crypt",
    ], deprecated="auto")
    _HAS_PASSLIB = True
except Exception:  # pragma: no cover — غياب passlib شائع
    _PASSLIB_CTX = None
    _PasslibUnknownHashError = Exception
    _HAS_PASSLIB = False

# --- crypt (مُهمل في 3.12، مُزال في 3.13) ---
# نُsuppress تحذير الإهمال ونتعامل مع غيابه بأمان.
_crypt_module = None
try:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import crypt as _crypt_module  # type: ignore
    _HAS_CRYPT = True
except ImportError:
    # Python 3.13+ أزالت crypt
    _HAS_CRYPT = False


def get_hash_backend() -> str:
    """إرجاع اسم backend النشط لتجزئة Unix:
    "passlib" / "crypt" / "none"
    """
    if _HAS_PASSLIB:
        return "passlib"
    if _HAS_CRYPT:
        return "crypt"
    return "none"


# معلومات تفصيلية عن الـ backend (للتقارير)
BACKEND_INFO = {
    "passlib_available": _HAS_PASSLIB,
    "crypt_available": _HAS_CRYPT,
    "active_backend": get_hash_backend(),
}


# ===========================================================================
# 1) تنفيذ MD4 بـ Python خالصة (نسخة احتياطية لـ NTLM)
# ===========================================================================
# المصدر: مواصفة RFC 1320 — The MD4 Message-Digest Algorithm.
# تنفيذ تعليمي/إنتاجي معتمد يطابق المتجهات المعروفة. يُستخدم فقط عندما
# يكون passlib غير متاح أو عندما يفشل hashlib.new('md4') بسبب OpenSSL 3.

def _lrot(x: int, n: int) -> int:
    """دوران يساري 32-bit."""
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _md4(message: bytes) -> bytes:
    """إرجاع MD4(message) كـ bytes بطول 16. تنفيذ Python خالص وفق RFC 1320."""
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")

    msg = bytearray(message)
    orig_bit_len = (len(msg) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0x00)
    msg += orig_bit_len.to_bytes(8, "little")

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    def F(x, y, z):
        return (x & y) | ((~x) & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    for chunk_start in range(0, len(msg), 64):
        X = [int.from_bytes(msg[chunk_start + i * 4: chunk_start + i * 4 + 4], "little")
             for i in range(16)]

        AA, BB, CC, DD = A, B, C, D

        # الجولة 1: [ABCD k s]
        r1 = [(0, 3), (1, 7), (2, 11), (3, 19),
              (4, 3), (5, 7), (6, 11), (7, 19),
              (8, 3), (9, 7), (10, 11), (11, 19),
              (12, 3), (13, 7), (14, 11), (15, 19)]
        for idx, (k, s) in enumerate(r1):
            if idx % 4 == 0:
                A = _lrot((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, s)
            elif idx % 4 == 1:
                D = _lrot((D + F(A, B, C) + X[k]) & 0xFFFFFFFF, s)
            elif idx % 4 == 2:
                C = _lrot((C + F(D, A, B) + X[k]) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + F(C, D, A) + X[k]) & 0xFFFFFFFF, s)

        # الجولة 2: قيم s في الجولة 2: 3, 5, 9, 13 (وفق RFC 1320)
        r2 = [(0, 3), (4, 5), (8, 9), (12, 13),
              (1, 3), (5, 5), (9, 9), (13, 13),
              (2, 3), (6, 5), (10, 9), (14, 13),
              (3, 3), (7, 5), (11, 9), (15, 13)]
        for idx, (k, s) in enumerate(r2):
            if idx % 4 == 0:
                A = _lrot((A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif idx % 4 == 1:
                D = _lrot((D + G(A, B, C) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            elif idx % 4 == 2:
                C = _lrot((C + G(D, A, B) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + G(C, D, A) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)

        # الجولة 3: قيم s: 3, 9, 11, 15 (وفق RFC 1320)
        r3 = [(0, 3), (8, 9), (4, 11), (12, 15),
              (2, 3), (10, 9), (6, 11), (14, 15),
              (1, 3), (9, 9), (5, 11), (13, 15),
              (3, 3), (11, 9), (7, 11), (15, 15)]
        for idx, (k, s) in enumerate(r3):
            if idx % 4 == 0:
                A = _lrot((A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif idx % 4 == 1:
                D = _lrot((D + H(A, B, C) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            elif idx % 4 == 2:
                C = _lrot((C + H(D, A, B) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            else:
                B = _lrot((B + H(C, D, A) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return (A.to_bytes(4, "little") + B.to_bytes(4, "little")
            + C.to_bytes(4, "little") + D.to_bytes(4, "little"))


def md4_hex(message: bytes) -> str:
    """إرجاع MD4(message) كـ hex string صغيرة."""
    return _md4(message).hex()


# ===========================================================================
# 2) NTLM Hash
# ===========================================================================

# محاولة استيراد passlib للـ NTLM (اختياري لكن مُفضّل)
try:
    from passlib.hash import nthash as _passlib_nthash  # type: ignore
    _HAS_PASSLIB_NTLM = True
except Exception:  # pragma: no cover
    _passlib_nthash = None
    _HAS_PASSLIB_NTLM = False


def compute_ntlm(password: str) -> str:
    """
    حساب تجزئة NTLM (NT hash) لكلمة مرور نصية.

    الصيغة: NTLM(pw) = MD4(UTF-16LE(pw))

    تستخدم passlib إن كانت متاحة (مُختبَرة وموثوقة)، وإلا تستخدم تنفيذ
    MD4 المحلي. النتيجة دائماً hex string بطول 32 حرفاً (أحرف كبيرة).

    مثال:
        compute_ntlm("Password")  -> "A4F49C406510BDCAB6824EE7C30FD852"
    """
    if password is None:
        password = ""
    utf16 = password.encode("utf-16-le")
    if _HAS_PASSLIB_NTLM:
        try:
            return _passlib_nthash.hash(password).upper()
        except Exception:
            pass
    return md4_hex(utf16).upper()


# ===========================================================================
# 3) تحليل حقول /etc/shadow (Unix crypt)
# ===========================================================================

# خريطة معرّفات صيغة $id$ إلى أسماء الخوارزميات
UNIX_HASH_ALGOS = {
    "1":   "MD5 (crypt)",
    "5":   "SHA-256 (crypt)",
    "6":   "SHA-512 (crypt)",
    "2":   "Blowfish (bcrypt)",
    "2a":  "Blowfish (bcrypt)",
    "2b":  "Blowfish (bcrypt)",
    "2y":  "Blowfish (bcrypt)",
    "y":   "YESCRYPT",
    "gy":  "GOST YESCRYPT",
    "7":   "SHA-512 (stretch)",
    "md5": "SunMD5",
}


def parse_unix_hash_field(field: str) -> Optional[dict]:
    """
    تحليل حقل كلمة المرور في /etc/shadow.

    يعيد dict يحوي:
        {
          "raw": "<الحقل الأصلي>",
          "algo_id": "6",
          "algo_name": "SHA-512 (crypt)",
          "salt": "<الملح>",
          "hash": "<التجزئة>",
          "status": "active" | "locked" | "empty" | "disabled" | "unknown"
        }
    أو None إذا كان الحقل فارغاً تماماً.
    """
    if field is None or field == "":
        return {"raw": "", "algo_id": None, "algo_name": None,
                "salt": None, "hash": None, "status": "empty"}

    # الحسابات المقفلة: تبدأ بـ ! (بما في ذلك !!)
    if field.startswith("!"):
        return {"raw": field, "algo_id": None, "algo_name": None,
                "salt": None, "hash": None, "status": "locked"}

    # الحسابات المعطّلة/بدون كلمة مرور: تبدأ بـ *
    if field.startswith("*"):
        return {"raw": field, "algo_id": None, "algo_name": None,
                "salt": None, "hash": None, "status": "disabled"}

    # صيغة $id$[rounds=N$]salt$hash
    if field.startswith("$"):
        parts = field.split("$")
        if len(parts) < 4:
            return {"raw": field, "algo_id": None, "algo_name": "Unknown ($-format)",
                    "salt": None, "hash": None, "status": "unknown"}
        algo_id = parts[1]
        hash_part = parts[-1]
        remaining = parts[2:-1]
        parameters = {}
        salt = remaining[-1] if remaining else None
        if remaining and remaining[0].startswith("rounds="):
            parameters["rounds"] = remaining[0].split("=", 1)[1]
        return {
            "raw": field,
            "algo_id": algo_id,
            "algo_name": UNIX_HASH_ALGOS.get(algo_id, f"Unknown (${algo_id})"),
            "salt": salt,
            "hash": hash_part,
            "parameters": parameters,
            "rounds": parameters.get("rounds"),
            "status": "active",
        }

    # صيغ قديمة (DES التقليدي) — 13 حرفاً alphanumeric: أول حرفين هما الملح
    if len(field) >= 13 and field.isalnum():
        return {
            "raw": field,
            "algo_id": "DES",
            "algo_name": "DES (traditional crypt)",
            "salt": field[:2],
            "hash": field[2:],
            "status": "active",
        }

    return {"raw": field, "algo_id": None, "algo_name": "Unknown",
            "salt": None, "hash": None, "status": "unknown"}


# ===========================================================================
# 4) backend التحقق من تجزئات Unix
# ===========================================================================

def can_verify_algo(algo_id: Optional[str]) -> bool:
    """Return whether the active backend was actually verified for this format."""
    if not algo_id:
        return False
    if _HAS_PASSLIB:
        passlib_map = {
            "1": "md5_crypt",
            "5": "sha256_crypt",
            "6": "sha512_crypt",
            "2": "bcrypt",
            "2a": "bcrypt",
            "2b": "bcrypt",
            "2y": "bcrypt",
            "DES": "des_crypt",
        }
        scheme = passlib_map.get(algo_id)
        if scheme:
            try:
                handler = _PASSLIB_CTX.handler(scheme)
                test_hash = handler.hash("PassGuardCapabilityProbe")
                return bool(handler.verify("PassGuardCapabilityProbe", test_hash))
            except Exception:
                return False
    if _HAS_CRYPT:
        return algo_id in {"1", "5", "6", "2", "2a", "2b", "2y", "DES"}
    return False


def verify_unix_hash(password: str, full_field: str) -> Tuple[bool, str]:
    """
    التحقق من تطابق كلمة مرور مع حقل تجزئة Unix crypt.

    يعيد tuple (matched: bool, status: str) حيث status:
      - "matched"    : كلمة المرور تطابق التجزئة.
      - "no_match"   : كلمة المرور لا تطابق، لكنّ التحقق تمّ بنجاح.
      - "unsupported": لا يستطيع أيّ backend التحقق من هذه الخوارزمية.
      - "error"      : حدث خطأ أثناء التحقق.

    أولوية الـ backend:
      1. passlib (إن توفّر) — يدعم bcrypt/sha256_crypt/sha512_crypt/md5_crypt/...
      2. crypt.crypt (إن توفّر) — احتياطي للأنظمة التي تدعمها.
      3. "unsupported" — إن لم يتوفّر أيّ backend (Python 3.13+ بدون passlib).

    لا نستبدل خوارزمية أخرى صامتةً: إن لم يتعرف الـ backend على الصيغة،
    نُعيد "unsupported" صريحاً.
    """
    if isinstance(password, bytes):
        password = password.decode("utf-8", errors="replace")
    if not full_field:
        return (False, "no_match")
    parsed = parse_unix_hash_field(full_field)
    if parsed and parsed.get("status") == "unknown":
        return (False, "unsupported")

    # --- مسار passlib ---
    if _HAS_PASSLIB:
        try:
            parsed = parse_unix_hash_field(full_field)
            algo_id = parsed.get("algo_id") if parsed else None
            if not can_verify_algo(algo_id):
                return (False, "unsupported")
            if _PASSLIB_CTX.verify(password, full_field):
                return (True, "matched")
            return (False, "no_match")
        except _PasslibUnknownHashError:
            # passlib لا يتعرف على هذه الصيغة → نجرب crypt
            pass
        except (ValueError, TypeError):
            # صيغة تالفة → not a match لكنّها ليست unsupported
            return (False, "no_match")
        except Exception:
            # خطأ غير متوقّع → نجرّب crypt كاحتياطي
            pass

    # --- مسار crypt.crypt (احتياطي) ---
    if _HAS_CRYPT:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                computed = _crypt_module.crypt(password, full_field)
            if computed is None:
                # crypt.crypt تُعيد None للخوارزميات غير المدعومة على هذا النظام
                return (False, "unsupported")
            if hmac.compare_digest(computed, full_field):
                return (True, "matched")
            return (False, "no_match")
        except OSError:
            # بعض التطبيقات ترفع OSError للخوارزميات غير المدعومة
            return (False, "unsupported")
        except Exception:
            return (False, "error")

    # --- لا backend متاح ---
    return (False, "unsupported")


def compute_unix_hash(password: str, full_field: str) -> str:
    """
    [محفوظة للتوافق الخلفي] حساب تجزئة Unix crypt لكلمة مرور باستخدام
    الحقل الكامل (الذي يتضمن الخوارزمية والملح) كـ salt.

    تستخدم backend نشط (passlib أو crypt). إن لم يتوفّر backend، تُعيد
    سلسلة فارغة (لن تطابق أبداً).

    ملاحظة: للأغراض الجديدة، استخدم verify_unix_hash() التي تُعيد حالة
    صريحة (matched/no_match/unsupported).
    """
    if isinstance(password, bytes):
        password = password.decode("utf-8", errors="replace")
    if _HAS_CRYPT:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                return _crypt_module.crypt(password, full_field)
        except Exception:
            return ""
    # بدون crypt، نُعيد سلسلة لن تطابق أبداً
    # (للأمان: لا نُعيد None لأنّ بعض الكود قد يقارنه)
    return ""


def verify_unix_password(password: str, full_field: str) -> bool:
    """
    [محفوظة للتوافق الخلفي] التحقق من تطابق كلمة مرور مع حقل /etc/shadow.

    تعيد True فقط عند التطابق، False خلاف ذلك (بما في ذلك unsupported).

    للأغراض الجديدة، استخدم verify_unix_hash() التي تميّز بين "no_match"
    و"unsupported".

    تستخدم مقارنة ثابتة الزمن (hmac.compare_digest).
    """
    matched, _status = verify_unix_hash(password, full_field)
    return matched


# ===========================================================================
# 5) دوال إخفاء كلمات المرور في التقارير
# ===========================================================================

def mask_password(pw: str, visible: int = 1) -> str:
    """
    إخفاء كلمة المرور جزئياً في التقارير: يُظهر أول `visible` حرف فقط
    ثم نجوم.

    مثال:
        mask_password("P@ssw0rd123!") -> "P***********"
        mask_password("abc")          -> "a**"
        mask_password("")             -> "(فارغة)"
        mask_password(None)           -> "(لا شيء)"
    """
    if pw is None:
        return "(لا شيء)"
    if pw == "":
        return "(فارغة)"
    if len(pw) <= visible:
        return "*" * len(pw)
    return pw[:visible] + "*" * (len(pw) - visible)


def normalize_password(pw: str, strip: bool = True, nfc: bool = True) -> str:
    """
    توحيد كلمة المرور قبل الفحص/المقارنة:
      - strip: إزالة المسافات الزائدة في البداية والنهاية.
      - nfc: تطبيق تطبيع Unicode NFC.
    لا يُغيّر حالة الأحرف افتراضياً.
    """
    if pw is None:
        return ""
    if strip:
        pw = pw.strip()
    if nfc:
        pw = unicodedata.normalize("NFC", pw)
    return pw


def hash_summary_for_report(algo_name: str, full_field: str) -> str:
    """
    توليد ملخص قصير للتجزئة يظهر في التقرير دون كشف المحتوى الكامل.
    نُظهر أول 8 أحرف من التجزئة فقط + "...".
    """
    parsed = parse_unix_hash_field(full_field)
    h = parsed.get("hash") if parsed else None
    if h and len(h) > 8:
        return f"{algo_name} | {h[:8]}…"
    if h:
        return f"{algo_name} | {h}"
    return algo_name


__all__ = [
    "compute_ntlm",
    "md4_hex",
    "parse_unix_hash_field",
    "compute_unix_hash",
    "verify_unix_password",
    "verify_unix_hash",
    "can_verify_algo",
    "get_hash_backend",
    "BACKEND_INFO",
    "mask_password",
    "normalize_password",
    "hash_summary_for_report",
    "UNIX_HASH_ALGOS",
]
