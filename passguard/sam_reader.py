"""
passguard.sam_reader
====================

قراءة مباشرة لقاعدة SAM في Windows باستخدام مكتبات Microsoft القياسية.

المنهجية المُصرّح بها (Authorized Methodology):
  1. تمكين امتياز SE_BACKUP_PRIVILEGE عبر advapi32 (مكتبة Microsoft القياسية).
  2. تصدير خلايا SAM وSYSTEM عبر RegSaveKeyEx (advapi32، واجهة موثّقة).
  3. تحليل ملفات الخلايا المُصدَّرة (regf format) بـ Python خالص.
  4. استخراج boot key من SYSTEM وNTLM hashes من SAM.
  5. فك التشفير (RC4 + DES) بـ Python خالص وفق الخوارزميات الموثّقة.

المتطلبات:
  - تشغيل على Windows بصلاحيات Administrator أو SYSTEM.
  - صلاحية SE_BACKUP_PRIVILEGE (تُمكَّن آلياً عبر adjust_token_privileges).
  - لا تتجاوز الأداة أيّ ضوابط أمنية في Windows — تستخدم واجهات Microsoft
    الموثّقة فقط، ولا تقرأ SAM أثناء تشغيل النظام مباشرةً (الذي يكون مُقفلاً
    من LSM)، بل تصدّر الخلية ثم تحلّلها offline.

المراجع التقنية:
  - FIPS 46-3: Data Encryption Standard (DES).
  - FIPS 81: DES Modes of Operation.
  - RFC 1320: MD4 (للتحقّق من النتائج).
  - Microsoft Open Specifications: [MS-SAMR] SAM Remote Protocol.
  - registry hive format (regf): موثّق في libregf و python-registry.

الاستخدام:
    from passguard.sam_reader import read_sam_hashes, parse_hive_file
    # على Windows بصلاحيات admin:
    hashes = read_sam_hashes()
    # أو تحليل ملفات مُصدَّرة مسبقاً:
    hashes = read_sam_hashes_from_files('sam.save', 'system.save')

الأمان:
  - لا تتجاوز ضوابط Windows — تتطلّب امتيازات إدارية صريحة.
  - لا تُخزّن كلمات المرور — فقط تجزئات NTLM (الموجودة أصلاً في SAM).
  - القراءة offline بعد تصدير الخلية (لا تُعدّل النظام الحيّ).
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from typing import Dict, List, Optional, Tuple

# ===========================================================================
# 1) RC4 — تنفيذ Python خالص (وفق مواصفة RSA)
# ===========================================================================

def rc4(key: bytes, data: bytes) -> bytes:
    """
    تشفير/فك تشفير RC4 (متماثل: نفس الدالة للتشفير وفكّه).

    المعاملات:
        key:  مفتاح (أيّ طول).
        data: البيانات.

    يعيد البيانات المُشفَّرة/المفكوكة.
    """
    if not key:
        raise ValueError("مفتاح RC4 فارغ.")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray(len(data))
    for idx, byte in enumerate(data):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result[idx] = byte ^ k
    return bytes(result)


# ===========================================================================
# 2) DES — تنفيذ Python خالص وفق FIPS 46-3
# ===========================================================================

# جداول التبديل القياسية (FIPS 46-3)
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# صناديق الاستبدال (S-boxes) — FIPS 46-3
_SBOXES = [
    # S1
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    # S2
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    # S3
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    # S4
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    # S5
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    # S6
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    # S7
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    # S8
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _bytes_to_bits(data: bytes) -> list:
    """تحويل bytes إلى قائمة bits (MSB أولاً)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bits_to_bytes(bits: list) -> bytes:
    """تحويل قائمة bits (MSB أولاً) إلى bytes."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | (bits[i + j] if i + j < len(bits) else 0)
        result.append(byte)
    return bytes(result)


def _permute(bits: list, table: list) -> list:
    """تبديل قائمة bits باستخدام جدول (1-indexed)."""
    return [bits[i - 1] for i in table]


def _left_rotate(bits: list, n: int) -> list:
    """دوران يساري لقائمة bits بمقدار n."""
    n = n % len(bits)
    return bits[n:] + bits[:n]


def _generate_subkeys(key: bytes) -> list:
    """توليد 16 مفتاحاً فرعياً (48-bit) من مفتاح 8 بايت."""
    key_bits = _bytes_to_bits(key)
    permuted = _permute(key_bits, _PC1)
    C = permuted[:28]
    D = permuted[28:]
    subkeys = []
    for i in range(16):
        C = _left_rotate(C, _SHIFTS[i])
        D = _left_rotate(D, _SHIFTS[i])
        subkeys.append(_permute(C + D, _PC2))
    return subkeys


def _f_function(r_bits: list, subkey: list) -> list:
    """دالة Feistel f: توسيع، XOR، S-boxes، تبديل P."""
    expanded = _permute(r_bits, _E)
    xored = [a ^ b for a, b in zip(expanded, subkey)]
    sboxed = []
    for i in range(8):
        block = xored[i * 6:(i + 1) * 6]
        row = (block[0] << 1) | block[5]
        col = (block[1] << 3) | (block[2] << 2) | (block[3] << 1) | block[4]
        value = _SBOXES[i][row * 16 + col]
        for j in range(3, -1, -1):
            sboxed.append((value >> j) & 1)
    return _permute(sboxed, _P)


def des_encrypt_block(block: bytes, key: bytes) -> bytes:
    """تشفير كتلة 8 بايت واحدة بـ DES-ECB."""
    if len(block) != 8 or len(key) != 8:
        raise ValueError("DES يتطلب كتلة ومفتاح 8 بايت.")
    subkeys = _generate_subkeys(key)
    bits = _bytes_to_bits(block)
    permuted = _permute(bits, _IP)
    L, R = permuted[:32], permuted[32:]
    for i in range(16):
        new_L = R
        new_R = [a ^ b for a, b in zip(L, _f_function(R, subkeys[i]))]
        L, R = new_L, new_R
    combined = R + L
    return _bits_to_bytes(_permute(combined, _FP))


def des_decrypt_block(block: bytes, key: bytes) -> bytes:
    """فك تشفير كتلة 8 بايت واحدة بـ DES-ECB."""
    if len(block) != 8 or len(key) != 8:
        raise ValueError("DES يتطلب كتلة ومفتاح 8 بايت.")
    subkeys = _generate_subkeys(key)
    bits = _bytes_to_bits(block)
    permuted = _permute(bits, _IP)
    L, R = permuted[:32], permuted[32:]
    for i in range(15, -1, -1):
        new_L = R
        new_R = [a ^ b for a, b in zip(L, _f_function(R, subkeys[i]))]
        L, R = new_L, new_R
    combined = R + L
    return _bits_to_bytes(_permute(combined, _FP))


# ===========================================================================
# 3) اشتقاق مفاتيح DES من RID (خوارزمية Windows الموثّقة)
# ===========================================================================

def _expand_7_to_8(key7: bytes) -> bytes:
    """توسيع مفتاح 7 بايت إلى 8 بايت مع بتات التماثل (DES parity).

    وفق خوارزمية Microsoft القياسية (transformKey).
    """
    if len(key7) != 7:
        raise ValueError("يتطلب مفتاح 7 بايت.")
    k = list(key7)
    result = bytearray(8)
    result[0] = k[0] >> 1
    result[1] = ((k[0] & 0x01) << 6) | (k[1] >> 2)
    result[2] = ((k[1] & 0x03) << 5) | (k[2] >> 3)
    result[3] = ((k[2] & 0x07) << 4) | (k[3] >> 4)
    result[4] = ((k[3] & 0x0F) << 3) | (k[4] >> 5)
    result[5] = ((k[4] & 0x1F) << 2) | (k[5] >> 6)
    result[6] = ((k[5] & 0x3F) << 1) | (k[6] >> 7)
    result[7] = k[6] & 0x7F
    # إزاحة يسارية 1 وضبط بت التماثل (odd parity)
    for i in range(8):
        b = (result[i] << 1) & 0xFF
        # ضبط بت التماثل: عدد الـ 1s في البتات السبع العليا يجب أن يكون فردياً
        bits_count = bin(b & 0xFE).count("1")
        if bits_count % 2 == 0:
            b |= 1
        result[i] = b
    return bytes(result)


def _rid_to_des_key(rid: int) -> bytes:
    """اشتقاق مفتاح DES (7 بايت ثم توسيع إلى 8) من RID.

    وفق خوارزمية Windows القياسية لفك تشفير تجزئات SAM.
    """
    s = struct.pack("<I", rid)
    key7 = bytes([s[0], s[0], s[1], s[2], s[3], s[3], s[3]])
    return _expand_7_to_8(key7)


def _rid_to_des_key2(rid: int) -> bytes:
    """اشتقاق المفتاح الثاني من RID (للنصف الثاني من التجزئة)."""
    s = struct.pack("<I", rid)
    key7 = bytes([s[3], s[3], s[3], s[0], s[0], s[1], s[2]])
    return _expand_7_to_8(key7)


# ===========================================================================
# 4) محلّل ملفات خلايا السجل (Registry Hive Parser — regf format)
# ===========================================================================

class HiveKey:
    """يمثّل مفتاحاً في خلية السجل."""

    def __init__(self, hive: "RegistryHive", name: str, cell_offset: int):
        self.hive = hive
        self.name = name
        self.cell_offset = cell_offset
        self._subkeys: Optional[List["HiveKey"]] = None
        self._values: Optional[List["HiveValue"]] = None
        self._class_name: Optional[str] = None
        self._flags: int = 0
        self._class_name_offset: int = 0
        self._class_name_length: int = 0

    def _parse(self):
        """تحليل خلية nk لهذا المفتاح."""
        data = self.hive._read_cell(self.cell_offset)
        if len(data) < 4 + 2:
            return
        sig = struct.unpack_from("<H", data, 4)[0]
        if sig != 0x6B6E:  # 'nk'
            return
        self._flags = struct.unpack_from("<H", data, 6)[0]
        subkey_count = struct.unpack_from("<I", data, 0x18)[0]
        subkey_list_offset = struct.unpack_from("<I", data, 0x20)[0]
        values_count = struct.unpack_from("<I", data, 0x28)[0]
        values_list_offset = struct.unpack_from("<I", data, 0x2C)[0]
        self._class_name_offset = struct.unpack_from("<I", data, 0x34)[0]
        name_length = struct.unpack_from("<H", data, 0x4C)[0]
        class_name_length = struct.unpack_from("<H", data, 0x4E)[0]
        self._class_name_length = class_name_length
        # الاسم: ASCII أو UTF-16LE حسب العلم
        if self._flags & 0x20:  # KEY_COMP_NAME
            self.name = data[0x50:0x50 + name_length].decode("latin-1", errors="replace")
        else:
            self.name = data[0x50:0x50 + name_length].decode("utf-16-le", errors="replace")
        # تحميل المفاتيح الفرعية
        self._subkeys = self._parse_subkeys(subkey_list_offset, subkey_count)
        # تحميل القيم
        self._values = self._parse_values(values_list_offset, values_count)

    def _parse_subkeys(self, list_offset: int, count: int) -> List["HiveKey"]:
        if count == 0 or list_offset == 0xFFFFFFFF:
            return []
        data = self.hive._read_cell(list_offset)
        if len(data) < 6:
            return []
        sig = struct.unpack_from("<H", data, 4)[0]
        result: List[HiveKey] = []
        if sig in (0x666C, 0x686C):  # 'lf' or 'lh'
            # قائمة بمقاطع (offset, hash/hint)
            n = struct.unpack_from("<H", data, 6)[0]
            for i in range(min(n, count)):
                off = struct.unpack_from("<I", data, 8 + i * 8)[0]
                if off != 0xFFFFFFFF:
                    key = HiveKey(self.hive, "", off)
                    key._parse()
                    result.append(key)
        elif sig == 0x696C:  # 'li'
            n = struct.unpack_from("<H", data, 6)[0]
            for i in range(min(n, count)):
                off = struct.unpack_from("<I", data, 8 + i * 4)[0]
                if off != 0xFFFFFFFF:
                    key = HiveKey(self.hive, "", off)
                    key._parse()
                    result.append(key)
        elif sig == 0x6972:  # 'ri' — قائمة بقوائم
            n = struct.unpack_from("<H", data, 6)[0]
            for i in range(n):
                sub_off = struct.unpack_from("<I", data, 8 + i * 4)[0]
                if sub_off != 0xFFFFFFFF:
                    # كل إدخال يشير إلى قائمة lf/lh/li أخرى
                    result.extend(self._parse_subkeys(sub_off, count))
        return result

    def _parse_values(self, list_offset: int, count: int) -> List["HiveValue"]:
        if count == 0 or list_offset == 0xFFFFFFFF:
            return []
        data = self.hive._read_cell(list_offset)
        result: List[HiveValue] = []
        for i in range(count):
            if 4 + i * 4 + 4 > len(data):
                break
            vk_off = struct.unpack_from("<I", data, 4 + i * 4)[0]
            if vk_off != 0xFFFFFFFF:
                val = HiveValue(self.hive, vk_off)
                val._parse()
                result.append(val)
        return result

    @property
    def subkeys(self) -> List["HiveKey"]:
        if self._subkeys is None:
            self._parse()
        return self._subkeys or []

    @property
    def values(self) -> List["HiveValue"]:
        if self._values is None:
            self._parse()
        return self._values or []

    @property
    def class_name(self) -> str:
        """اسم الصف (class name) للمفتاح — نص UTF-16LE."""
        if self._class_name is not None:
            return self._class_name
        if self._class_name_length == 0 or self._class_name_offset == 0xFFFFFFFF:
            self._class_name = ""
            return self._class_name
        data = self.hive._read_cell(self._class_name_offset)
        cn = data[:self._class_name_length]
        self._class_name = cn.decode("utf-16-le", errors="replace")
        return self._class_name

    def open(self, name: str) -> Optional["HiveKey"]:
        """فتح مفتاح فرعي بالاسم (غير حساس للحالة)."""
        name_lower = name.lower()
        for sk in self.subkeys:
            if sk.name.lower() == name_lower:
                return sk
        return None

    def value(self, name: str) -> Optional["HiveValue"]:
        """الحصول على قيمة بالاسم (غير حساس للحالة)."""
        name_lower = name.lower()
        for v in self.values:
            if v.name.lower() == name_lower:
                return v
        return None


class HiveValue:
    """يمثّل قيمة في خلية السجل."""

    def __init__(self, hive: "RegistryHive", cell_offset: int):
        self.hive = hive
        self.cell_offset = cell_offset
        self.name: str = ""
        self.data_type: int = 0
        self._data: Optional[bytes] = None
        self.data_size: int = 0

    def _parse(self):
        data = self.hive._read_cell(self.cell_offset)
        if len(data) < 0x18:
            return
        sig = struct.unpack_from("<H", data, 4)[0]
        if sig != 0x6B76:  # 'vk'
            return
        name_length = struct.unpack_from("<H", data, 6)[0]
        self.data_size = struct.unpack_from("<I", data, 8)[0]
        data_offset = struct.unpack_from("<I", data, 0x0C)[0]
        self.data_type = struct.unpack_from("<I", data, 0x10)[0]
        flags = struct.unpack_from("<H", data, 0x14)[0]
        if name_length > 0:
            if flags & 0x01:
                self.name = data[0x18:0x18 + name_length].decode("latin-1", errors="replace")
            else:
                self.name = data[0x18:0x18 + name_length].decode("utf-16-le", errors="replace")
        else:
            self.name = ""
        # البيانات: إن كان MSB من data_size مضبوطاً، البيانات inline
        if self.data_size & 0x80000000:
            # Inline: البيانات في حقل data_offset نفسه (max 4 bytes)
            inline_size = self.data_size & 0x7FFFFFFF
            self._data = struct.pack("<I", data_offset)[:inline_size]
        else:
            actual_size = self.data_size
            if data_offset != 0xFFFFFFFF:
                cell_data = self.hive._read_cell(data_offset)
                self._data = cell_data[:actual_size]
            else:
                self._data = b""

    @property
    def data(self) -> bytes:
        if self._data is None:
            self._parse()
        return self._data or b""


class RegistryHive:
    """محلّل ملف خلية سجل Windows (regf format)."""

    def __init__(self, path: str):
        """
        المعاملات:
            path: مسار ملف الخلية (.save أو أيّ ملف regf).
        """
        self.path = path
        with open(path, "rb") as fh:
            self._buf = fh.read()
        if len(self._buf) < 0x1000:
            raise ValueError(f"ملف الخلية صغير جداً: {len(self._buf)} بايت.")
        magic = self._buf[0:4]
        if magic != b"regf":
            raise ValueError(f"توقيع ملف الخلية غير صحيح: {magic!r} (متوقّع 'regf').")
        # إزاحة المفتاح الجذري (relative to start of hive bins at 0x1000)
        self._root_offset = struct.unpack_from("<I", self._buf, 0x24)[0]
        self._root_key: Optional[HiveKey] = None

    def _read_cell(self, offset: int) -> bytes:
        """قراءة خلية عند الإزاحة المعطاة.

        الإزاحات في هياكل البيانات نسبية لبدء منطقة hbins (0x1000).
        تُعيد الخلية كاملة بما فيها حقل الحجم (4 بايت) لتتوافق مع
        الإزاحات القياسية في هياكل nk/vk/lf/lh (التوقيع عند الإزاحة 4).
        """
        file_pos = 0x1000 + offset
        if file_pos + 4 > len(self._buf):
            return b""
        cell_size = struct.unpack_from("<i", self._buf, file_pos)[0]
        # cell_size سالب = مخصّص (allocated)، موجب = حرّ (free)
        total_size = abs(cell_size)
        if total_size <= 4:
            return b""
        end = min(file_pos + total_size, len(self._buf))
        return self._buf[file_pos:end]

    @property
    def root(self) -> HiveKey:
        """المفتاح الجذري للخلية."""
        if self._root_key is None:
            self._root_key = HiveKey(self, "", self._root_offset)
            self._root_key._parse()
        return self._root_key

    def open(self, path: str) -> Optional[HiveKey]:
        """فتح مسار مثل 'Domains\\Account\\Users' من الجذر."""
        parts = path.replace("/", "\\").split("\\")
        current = self.root
        for part in parts:
            if not part:
                continue
            next_key = current.open(part)
            if next_key is None:
                return None
            current = next_key
        return current


# ===========================================================================
# 5) استخراج boot key وNTLM hashes من SAM/SYSTEM
# ===========================================================================

# تبديل فكّ التشويش لـ boot key
_BOOTKEY_PERM = [0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
                 0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7]

# الثوابت لتوليد مفتاح RC4 لفكّ تشفير HBootKey
_QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
_DIGITS = b"0123456789012345678901234567890123456789\x00"


def detect_sam_revision(f_data: bytes) -> str:
    """Identify the custom legacy SAM format used by this implementation."""
    if len(f_data) < 0x90:
        return "invalid-f-record"

    revision = struct.unpack_from("<I", f_data, 0x60)[0]
    if revision == 1:
        return "legacy-rc4-des-revision-1"
    if revision == 2:
        return "legacy-rc4-des-revision-2"
    return "unsupported-modern-or-unrecognized"


def extract_bootkey(system_hive: RegistryHive) -> bytes:
    """استخراج boot key من خلية SYSTEM.

    Boot key مخزّن في أسماء الصفوف (class names) للمفاتيح الفرعية JD، Skew1،
    GBG، Data تحت ControlSet00X\\Control\\Lsa.
    """
    # إيجاد ControlSet الحالي
    select = system_hive.open("Select")
    if select is None:
        # محاولة ControlSet001 كافتراضي
        cs_name = "ControlSet001"
    else:
        current_val = select.value("Current")
        if current_val is None:
            cs_name = "ControlSet001"
        else:
            cs_num = struct.unpack("<I", current_val.data[:4])[0]
            cs_name = "ControlSet%03d" % cs_num

    lsa = system_hive.open(f"{cs_name}\\Control\\Lsa")
    if lsa is None:
        raise ValueError(f"تعذّر العثور على {cs_name}\\Control\\Lsa في خلية SYSTEM.")

    # أسماء الصفوف لمفاتيح JD, Skew1, GBG, Data
    keys = ["JD", "Skew1", "GBG", "Data"]
    class_hex = ""
    for kname in keys:
        subkey = lsa.open(kname)
        if subkey is None:
            raise ValueError(f"تعذّر العثور على المفتاح الفرعي {kname} تحت Lsa.")
        cn = subkey.class_name
        if not cn:
            raise ValueError(f"اسم الصف فارغ للمفتاح {kname}.")
        class_hex += cn

    # class_hex هو سلسلة hex بطول 32 حرفاً (16 بايت)
    try:
        scrambled = bytes.fromhex(class_hex)
    except ValueError:
        raise ValueError(f"اسم الصف ليس hex صالحاً: {class_hex!r}")

    if len(scrambled) < 16:
        raise ValueError(f"البيانات المجمّعة قصيرة جداً: {len(scrambled)} بايت.")

    # فكّ التشويش بالتبديل
    bootkey = bytes([scrambled[_BOOTKEY_PERM[i]] for i in range(16)])
    return bootkey


def extract_hbootkey(sam_hive: RegistryHive, bootkey: bytes) -> bytes:
    """اشتقاق HBootKey من قيمة F في SAM\\Domains\\Account.

    HBootKey مُشفّر بـ RC4، والمفتاح = MD5(bootkey + QWERTY + revision + DIGITS).
    """
    account = sam_hive.open("Domains\\Account")
    if account is None:
        raise ValueError("تعذّر العثور على Domains\\Account في خلية SAM.")

    f_val = account.value("F")
    if f_val is None or len(f_val.data) < 0x90:
        raise ValueError("قيمة F مفقودة أو قصيرة جداً في Domains\\Account.")

    f_data = f_val.data
    revision = detect_sam_revision(f_data)
    if revision not in {"legacy-rc4-des-revision-1", "legacy-rc4-des-revision-2"}:
        raise ValueError(
            "Unsupported or unverified SAM format: "
            f"{revision}. Live NT hash extraction is not supported."
        )
    # revision عند الإزاحة 0x60 (4 بايت)، HBootKey مشفّر عند 0x70 (0x20 بايت)
    # وفق impacket/creddump
    revision = f_data[0x60:0x64]
    encrypted_hbootkey = f_data[0x70:0x90]

    rc4_key = hashlib.md5(bootkey + _QWERTY + revision + _DIGITS).digest()
    hbootkey = rc4(rc4_key, encrypted_hbootkey)
    return hbootkey


def _decrypt_sam_hash(encrypted_block: bytes, rid: int,
                       hbootkey: bytes) -> Tuple[bytes, str]:
    """فكّ تشفير كتلة تجزئة SAM واحدة.

    المعاملات:
        encrypted_block: الكتلة المشفّرة (عادة 20 بايت: 2 type + 16 encrypted + 2).
        rid:             معرّف المستخدم (Relative ID).
        hbootkey:        المفتاح المُشتق.

    يعيد (hash_bytes, hash_type) حيث hash_type = 'lm' أو 'nt' أو ''.
    """
    if len(encrypted_block) < 18:
        return (b"", "")

    hash_type_bytes = encrypted_block[:2]
    encrypted = encrypted_block[2:18]

    if hash_type_bytes == b"\x01\x00":
        htype = "lm"
    elif hash_type_bytes == b"\x02\x00":
        htype = "nt"
    else:
        return (b"", "")

    # مفتاح RC4 = MD5(rid_LE + hbootkey + hash_type_bytes)
    rid_bytes = struct.pack("<I", rid)
    rc4_key = hashlib.md5(rid_bytes + hbootkey + hash_type_bytes).digest()
    obfkey = rc4(rc4_key, encrypted)

    # فكّ تشفير DES بنصفين
    key1 = _rid_to_des_key(rid)
    key2 = _rid_to_des_key2(rid + 1)

    half1 = des_decrypt_block(obfkey[:8], key1)
    half2 = des_decrypt_block(obfkey[8:16], key2)

    return (half1 + half2, htype)


def extract_user_hashes(sam_hive: RegistryHive,
                         hbootkey: bytes) -> List[dict]:
    """استخراج تجزئات NTLM لكل المستخدمين من SAM.

    يعيد قائمة dicts:
        {"username": str, "rid": int, "lm": str(hex), "nt": str(hex)}
    """
    users = sam_hive.open("Domains\\Account\\Users")
    if users is None:
        raise ValueError("تعذّر العثور على Domains\\Account\\Users في SAM.")

    names_key = users.open("Names")
    results: List[dict] = []

    # خريطة: اسم المستخدم → RID (من قيمة Names)
    # في SAM، كل مفتاح فرعي تحت Names له قيمة افتراضية = RID (DWORD)
    user_rids: Dict[str, int] = {}
    if names_key is not None:
        for sk in names_key.subkeys:
            # القيمة الافتراضية (name="") تحوي RID
            default_val = sk.value("")
            if default_val is not None and len(default_val.data) >= 4:
                rid = struct.unpack("<I", default_val.data[:4])[0]
                user_rids[sk.name] = rid
            else:
                # محاولة قراءة RID من اسم المفتاح الرقمي (hex)
                try:
                    rid = int(sk.name, 16)
                    user_rids[sk.name] = rid
                except ValueError:
                    continue

    # لكل مستخدم: فتح المفتاح Users\<hexRID> وقراءة قيمة V
    for username, rid in user_rids.items():
        rid_hex = "%08X" % rid
        user_key = users.open(rid_hex)
        if user_key is None:
            continue
        v_val = user_key.value("V")
        if v_val is None:
            continue
        v_data = v_val.data
        if len(v_data) < 0xCC:
            continue

        # بنية V: الإزاحات نسبية لبدء V، البيانات الفعلية عند + 0xCC
        # اسم المستخدم: إزاحة عند 0x0C، طول عند 0x10
        u_offset = struct.unpack_from("<I", v_data, 0x0C)[0] + 0xCC
        u_length = struct.unpack_from("<I", v_data, 0x10)[0]
        actual_username = v_data[u_offset:u_offset + u_length]
        try:
            actual_username_str = actual_username.decode("utf-16-le", errors="replace")
        except Exception:
            actual_username_str = username

        # LM hash: إزاحة عند 0x9C، طول عند 0xA0
        lm_offset = struct.unpack_from("<I", v_data, 0x9C)[0] + 0xCC
        lm_length = struct.unpack_from("<I", v_data, 0xA0)[0]
        lm_data = v_data[lm_offset:lm_offset + lm_length]

        # NT hash: إزاحة عند 0xA8، طول عند 0xAC
        nt_offset = struct.unpack_from("<I", v_data, 0xA8)[0] + 0xCC
        nt_length = struct.unpack_from("<I", v_data, 0xAC)[0]
        nt_data = v_data[nt_offset:nt_offset + nt_length]

        # فكّ التشفير
        lm_hash = b""
        nt_hash = b""
        if lm_length >= 20:
            lm_hash, _ = _decrypt_sam_hash(lm_data[:20], rid, hbootkey)
        if nt_length >= 20:
            nt_hash, _ = _decrypt_sam_hash(nt_data[:20], rid, hbootkey)

        # تجزئة فارغة: 31D6CFE0D16AE931B73C59D7E0C089C0 (NTLM للكلمة الفارغة)
        results.append({
            "username": actual_username_str,
            "rid": rid,
            "lm": lm_hash.hex().upper() if lm_hash else "",
            "nt": nt_hash.hex().upper() if nt_hash else "",
        })

    return results


def read_sam_hashes_from_files(sam_path: str,
                                system_path: str) -> List[dict]:
    """قراءة تجزئات SAM من ملفات خلايا مُصدَّرة.

    المعاملات:
        sam_path:    مسار ملف خلية SAM المُصدَّر (reg save HKLM\\SAM).
        system_path: مسار ملف خلية SYSTEM المُصدَّر (reg save HKLM\\SYSTEM).

    يعيد قائمة dicts:
        {"username": str, "rid": int, "lm": str(hex), "nt": str(hex)}

    هذه الدالة تعمل على أيّ منصة (Linux/Windows) طالما وُجدت ملفات الخلايا
    المُصدَّرة. تصدير الخلايا يتطلّب Windows + admin (انظر save_registry_hive).
    """
    if not os.path.exists(sam_path):
        raise FileNotFoundError(f"ملف SAM غير موجود: {sam_path}")
    if not os.path.exists(system_path):
        raise FileNotFoundError(f"ملف SYSTEM غير موجود: {system_path}")

    system_hive = RegistryHive(system_path)
    bootkey = extract_bootkey(system_hive)

    sam_hive = RegistryHive(sam_path)
    hbootkey = extract_hbootkey(sam_hive, bootkey)

    return extract_user_hashes(sam_hive, hbootkey)


# ===========================================================================
# 6) تكامل Windows API — تصدير الخلايا (Windows فقط)
# ===========================================================================

def is_windows() -> bool:
    """هل النظام الحالي Windows؟"""
    return sys.platform == "win32"


def is_admin() -> bool:
    """هل الأداة تعمل بصلاحيات Administrator؟"""
    if not is_windows():
        return False
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def save_registry_hive(key_name: str, output_path: str) -> bool:
    """تصدير خلية سجل باستخدام RegSaveKeyEx (مكتبة advapi32 القياسية).

    يتطلّب:
      - Windows
      - صلاحيات Administrator
      - SE_BACKUP_PRIVILEGE (تُمكَّن آلياً)

    المعاملات:
        key_name:    اسم الخلية مثل 'SAM' أو 'SYSTEM' (تحت HKLM).
        output_path: مسار ملف الإخراج.

    يعيد True عند النجاح، False عند الفشل.
    """
    if not is_windows():
        raise RuntimeError("تصدير الخلايا يتطلّب Windows. "
                           "استخدم read_sam_hashes_from_files() مع ملفات مُصدَّرة.")

    if not is_admin():
        raise PermissionError("تصدير الخلايا يتطلّب صلاحيات Administrator. "
                              "شغّل الأداة كـ Administrator.")

    import ctypes
    from ctypes import wintypes

    # تمكين SE_BACKUP_PRIVILEGE
    if not _enable_privilege("SeBackupPrivilege"):
        raise PermissionError("تعذّر تمكين SE_BACKUP_PRIVILEGE.")

    # فتح مفتاح HKLM\<key_name>
    HKEY_LOCAL_MACHINE = 0x80000002
    KEY_READ = 0x20019
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    hkey = wintypes.HKEY()
    ret = advapi32.RegOpenKeyExW(
        wintypes.HKEY(HKEY_LOCAL_MACHINE),
        key_name, 0, KEY_READ, ctypes.byref(hkey))
    if ret != 0:
        raise OSError(f"RegOpenKeyExW فشل ({ret}): {key_name}")

    try:
        # RegSaveKeyEx يحفظ الخلية إلى ملف
        REG_STANDARD_FORMAT = 1
        ret = advapi32.RegSaveKeyExW(
            hkey, output_path, None, REG_STANDARD_FORMAT)
        if ret != 0:
            # إن وُجد الملف مسبقاً، نحذفه ونعيد المحاولة
            if ret == 183:  # ERROR_ALREADY_EXISTS
                try:
                    os.remove(output_path)
                    ret = advapi32.RegSaveKeyExW(
                        hkey, output_path, None, REG_STANDARD_FORMAT)
                except OSError:
                    pass
            if ret != 0:
                raise OSError(f"RegSaveKeyExW فشل ({ret}) لكتابة {output_path}")
        return True
    finally:
        advapi32.RegCloseKey(hkey)


def _enable_privilege(privilege_name: str) -> bool:
    """تمكين امتياز محدّد في token العملية الحالية (advapi32)."""
    import ctypes
    from ctypes import wintypes

    TOKEN_QUERY = 0x0008
    TOKEN_ADJUST_PRIVILEGES = 0x0020
    SE_PRIVILEGE_ENABLED = 0x00000002

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD),
                    ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID),
                    ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    # فتح token العملية
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            ctypes.byref(token)):
        return False

    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(
                None, privilege_name, ctypes.byref(luid)):
            return False

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

        if not advapi32.AdjustTokenPrivileges(
                token, False, ctypes.byref(tp),
                ctypes.sizeof(TOKEN_PRIVILEGES), None, None):
            return False
        return True
    finally:
        ctypes.windll.kernel32.CloseHandle(token)


def _restrict_windows_temp_directory(directory: str) -> None:
    """Restrict a Windows temporary directory to the current user."""
    if not is_windows():
        return
    import subprocess

    username = os.environ.get("USERNAME")
    if not username:
        return
    try:
        subprocess.run(
            [
                "icacls",
                directory,
                "/inheritance:r",
                "/grant:r",
                f"{username}:(OI)(CI)(F)",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return


def read_sam_hashes(output_dir: Optional[str] = None) -> List[dict]:
    """قراءة تجزئات SAM مباشرة من نظام Windows الحالي.

    سير العمل:
      1. التحقّق من Windows + صلاحيات admin.
      2. تمكين SE_BACKUP_PRIVILEGE.
      3. تصدير خليتي SAM وSYSTEM عبر RegSaveKeyEx.
      4. تحليل الخلايا المُصدَّرة offline واستخراج التجزئات.

    المعاملات:
        output_dir: مجلد لحفظ الخلايا المُصدَّرة مؤقتاً (افتراضي: temp).

    يعيد قائمة dicts: {"username", "rid", "lm", "nt"}.
    """
    if not is_windows():
        raise RuntimeError("القراءة المباشرة من SAM تتطلّب Windows. "
                           "على Linux/أنظمة أخرى، استخدم read_sam_hashes_from_files() "
                           "مع ملفات خلايا مُصدَّرة مسبقاً من نظام Windows.")

    if not is_admin():
        raise PermissionError("القراءة المباشرة من SAM تتطلّب صلاحيات Administrator. "
                              "أعد تشغيل الأداة كـ Administrator.")

    import tempfile
    if output_dir:
        tmp = tempfile.mkdtemp(prefix="passguard-sam-", dir=output_dir)
        owns_directory = True
    else:
        tmp = tempfile.mkdtemp(prefix="passguard-sam-", dir=None)
        owns_directory = True
    try:
        os.chmod(tmp, 0o700)
    except (AttributeError, OSError):
        pass
    if is_windows():
        _restrict_windows_temp_directory(tmp)
    sam_path = os.path.join(tmp, "SAM.save")
    system_path = os.path.join(tmp, "SYSTEM.save")

    try:
        save_registry_hive("SAM", sam_path)
        save_registry_hive("SYSTEM", system_path)
        return read_sam_hashes_from_files(sam_path, system_path)
    finally:
        try:
            if owns_directory:
                import shutil
                shutil.rmtree(tmp)
        except OSError:
            pass


def hashes_to_pwdump(hashes: List[dict]) -> str:
    """تحويل قائمة التجزئات إلى صيغة pwdump.

    الصيغة: username:RID:LM:NT:::
    """
    lines = []
    for h in hashes:
        lm = h.get("lm", "") or "00000000000000000000000000000000"
        nt = h.get("nt", "") or "00000000000000000000000000000000"
        lines.append(f"{h['username']}:{h['rid']}:{lm}:{nt}:::")
    return "\n".join(lines)


__all__ = [
    # Crypto
    "rc4", "des_encrypt_block", "des_decrypt_block",
    # Hive parser
    "RegistryHive", "HiveKey", "HiveValue",
    # SAM extraction
    "extract_bootkey", "extract_hbootkey", "extract_user_hashes",
    "read_sam_hashes_from_files", "read_sam_hashes",
    "hashes_to_pwdump",
    # Windows API
    "save_registry_hive", "is_windows", "is_admin",
    "detect_sam_revision",
]
