"""
passguard.wordlist_manager
==========================

إدارة قوائم كلمات المرور الشائعة: تسجيل قوائم متعددة، بيانات وصفية
(المصدر، الإصدار، عدد الكلمات، الحجم، تاريخ آخر تعديل)، تحقّق التكامل
(SHA-256)، كشف التكرارات، تفعيل/تعطيل، وتحميل آمن مع حدود للملفات الكبيرة.

التصميم:
  - يعتمد على wordlist_loader.py للقراءة الفعلية (لا يكرّر منطق التحليل).
  - لا يُنزِّل قوائم كبيرة تلقائياً — كل القوائم ملفات محلية يُسجّلها المستخدم.
  - سجلّ القوائم (registry) يُحفَظ في JSON بجانب الأداة ليُعاد تحميله بين الجلسات.
  - التشغيل offline بالكامل: لا اتصال شبكي.

قواعد أمنية:
  - لا تُخزَّن كلمات المرور في الـ registry — فقط بيانات وصفية عن الملفات.
  - SHA-256 يكشف التلاعب بالملف بين الجلسات.
  - حدّ أقصى للتحميل الكامل في الذاكرة (max_bytes) لتفادي استنفاد الذاكرة
    مع قوائم ضخمة (rockyou.txt ~14GB مثلاً).
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterator, List, Optional, Set

from .wordlist_loader import iter_wordlist, wordlist_stats


# الحدّ الافتراضي للتحميل الكامل في الذاكرة: 200 MB
# القوائم الأكبر تُقرأ عبر iter_wordlist (تدفّقي) بدلاً من التحميل الكامل.
DEFAULT_MAX_LOAD_BYTES = 200 * 1024 * 1024


@dataclass
class WordlistEntry:
    """بيانات وصفية لقائمة كلمات مسجّلة."""
    name: str                       # اسم بصري فريد
    path: str                       # المسار المطلق للملف
    source: str                     # "bundled" / "custom" / "seclists" / "eff" / ...
    version: str                    # إصدار (مثل "2024.1" أو "unknown")
    enabled: bool                   # مفعّلة أم معطّلة
    sha256: str                     # تجزئة SHA-256 للملف (للتحقّق من التكامل)
    word_count: int                 # عدد الكلمات الفريدة (مُخبّأ)
    size_bytes: int                 # حجم الملف بالبايت
    last_modified: float            # طابع زمني لآخر تعديل (mtime)
    description: str = ""           # وصف اختياري
    duplicate_count: int = 0        # عدد التكرارات داخل الملف (للمعلومات)
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "WordlistEntry":
        return cls(**{k: d[k] for k in cls.__dataclass_fields__ if k in d})


class WordlistManager:
    """مدير قوائم كلمات متعددة مع بيانات وصفية وتكامل.

    الاستخدام:
        mgr = WordlistManager()
        mgr.register("wordlists/wordlist.txt", name="default",
                     source="bundled", version="2024.1")
        mgr.register("/opt/seclists/rockyou.txt", name="rockyou",
                     source="seclists", version="2024")
        all_words = mgr.load_enabled_set()   # دمج كل المُفعّلة
    """

    def __init__(self, registry_path: Optional[str] = None,
                 max_load_bytes: int = DEFAULT_MAX_LOAD_BYTES):
        """
        المعاملات:
            registry_path:  مسار ملف JSON لحفظ سجلّ القوائم. إن None يُستخدم
                            مسار افتراضي بجانب الحزمة.
            max_load_bytes: حدّ أقصى لتحميل قائمة واحدة في الذاكرة كاملة.
        """
        self.max_load_bytes = max_load_bytes
        if registry_path is None:
            # افتراضي: بجانب الحزمة
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            project_dir = os.path.dirname(pkg_dir)
            registry_path = os.path.join(project_dir, "wordlists",
                                         "registry.json")
        self.registry_path = registry_path
        self._entries: Dict[str, WordlistEntry] = {}
        self.load_registry()

    # -------------------------------------------------------------------
    # حساب البيانات الوصفية لملف
    # -------------------------------------------------------------------

    @staticmethod
    def compute_sha256(path: str, chunk_size: int = 65536) -> str:
        """حساب SHA-256 لملف (تدفّقي، يصلح للملفات الكبيرة)."""
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def compute_metadata(path: str) -> dict:
        """حساب كل البيانات الوصفية لملف قائمة.

        يعيد dict:
            sha256, word_count, unique_count, duplicate_count,
            size_bytes, last_modified, avg_length, min_length, max_length
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"ملف القائمة غير موجود: {path}")
        size_bytes = os.path.getsize(path)
        last_modified = os.path.getmtime(path)
        sha256 = WordlistManager.compute_sha256(path)
        # إحصاءات الكلمات (تدفقية، لا تُحمّل كل الملف في الذاكرة)
        seen: Set[str] = set()
        total = 0
        lengths: List[int] = []
        for w in iter_wordlist(path):
            total += 1
            seen.add(w)
            lengths.append(len(w))
        duplicate_count = total - len(seen)
        stats = {
            "sha256": sha256,
            "word_count": total,
            "unique_count": len(seen),
            "duplicate_count": duplicate_count,
            "size_bytes": size_bytes,
            "last_modified": last_modified,
            "avg_length": round(sum(lengths) / len(lengths), 2) if lengths else 0,
            "min_length": min(lengths) if lengths else 0,
            "max_length": max(lengths) if lengths else 0,
        }
        return stats

    # -------------------------------------------------------------------
    # التسجيل
    # -------------------------------------------------------------------

    def register(self, path: str, name: Optional[str] = None,
                 source: str = "custom", version: str = "unknown",
                 description: str = "",
                 verify_integrity: bool = True) -> WordlistEntry:
        """تسجيل قائمة كلمات جديدة أو تحديث موجودة.

        المعاملات:
            path:               مسار ملف القائمة.
            name:               اسم بصري فريد. إن None يُشتقّ من اسم الملف.
            source:             مصدر القائمة (bundled/custom/seclists/eff...).
            version:            إصدار (مثل "2024.1").
            description:        وصف اختياري.
            verify_integrity:   إن True يُعاد حساب SHA-256 (بطيء للملفات الكبيرة).

        يعيد WordlistEntry. يرفع FileNotFoundError إن لم يوجد الملف.
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f"ملف القائمة غير موجود: {path}")
        abs_path = os.path.abspath(path)
        if name is None:
            name = os.path.splitext(os.path.basename(abs_path))[0]

        # حساب البيانات الوصفية
        if verify_integrity:
            meta = self.compute_metadata(abs_path)
        else:
            # استخدام بيانات سريعة بدون SHA (للتسجيل السريع للملفات الكبيرة)
            size_bytes = os.path.getsize(abs_path)
            last_modified = os.path.getmtime(abs_path)
            # SHA يُحسب دائماً للتكامل (حتى لو بطيء) — لكن نسمح بالتخطّي للاختبار
            meta = {
                "sha256": self.compute_sha256(abs_path),
                "word_count": 0, "unique_count": 0, "duplicate_count": 0,
                "size_bytes": size_bytes, "last_modified": last_modified,
                "avg_length": 0, "min_length": 0, "max_length": 0,
            }
            # نعدّ الكلمات بسرعة دون تخزينها
            wc = 0
            for _ in iter_wordlist(abs_path):
                wc += 1
            meta["word_count"] = wc
            meta["unique_count"] = wc   # تقديري دون إزالة التكرارات

        entry = WordlistEntry(
            name=name,
            path=abs_path,
            source=source,
            version=version,
            enabled=True,
            sha256=meta["sha256"],
            word_count=meta["word_count"],
            size_bytes=meta["size_bytes"],
            last_modified=meta["last_modified"],
            description=description,
            duplicate_count=meta.get("duplicate_count", 0),
            registered_at=time.time(),
        )
        self._entries[name] = entry
        self.save_registry()
        return entry

    def unregister(self, name: str) -> bool:
        """إزالة قائمة من السجلّ (لا يحذف الملف)."""
        if name in self._entries:
            del self._entries[name]
            self.save_registry()
            return True
        return False

    # -------------------------------------------------------------------
    # تفعيل/تعطيل
    # -------------------------------------------------------------------

    def enable(self, name: str) -> bool:
        """تفعيل قائمة."""
        if name in self._entries:
            self._entries[name].enabled = True
            self.save_registry()
            return True
        return False

    def disable(self, name: str) -> bool:
        """تعطيل قائمة (تبقى مسجّلة لكن لا تُستخدم في الفحص)."""
        if name in self._entries:
            self._entries[name].enabled = False
            self.save_registry()
            return True
        return False

    # -------------------------------------------------------------------
    # استعلام
    # -------------------------------------------------------------------

    def list_wordlists(self) -> List[WordlistEntry]:
        """قائمة كل القوائم المسجّلة."""
        return list(self._entries.values())

    def list_enabled(self) -> List[WordlistEntry]:
        """قائمة القوائم المفعّلة فقط."""
        return [e for e in self._entries.values() if e.enabled]

    def get(self, name: str) -> Optional[WordlistEntry]:
        """الحصول على إدخال بالاسم."""
        return self._entries.get(name)

    def verify_integrity(self, name: str) -> bool:
        """إعادة التحقق من تكامل ملف قائمة (SHA-256).

        يعيد True إن طابقت التجزئة المسجّلة، False خلاف ذلك (أو إن لم يوجد
        الملف أو القائمة).
        """
        entry = self._entries.get(name)
        if entry is None:
            return False
        if not os.path.exists(entry.path):
            return False
        current_sha = self.compute_sha256(entry.path)
        return current_sha == entry.sha256

    def stats(self) -> dict:
        """ملخّص إجمالي عن كل القوائم المسجّلة."""
        entries = list(self._entries.values())
        enabled = [e for e in entries if e.enabled]
        return {
            "total_lists": len(entries),
            "enabled_lists": len(enabled),
            "total_words": sum(e.word_count for e in entries),
            "enabled_words": sum(e.word_count for e in enabled),
            "total_size_bytes": sum(e.size_bytes for e in entries),
        }

    # -------------------------------------------------------------------
    # تحميل القوائم المفعّلة
    # -------------------------------------------------------------------

    def load_enabled_set(self, case_fold: bool = False,
                         max_bytes: Optional[int] = None) -> Set[str]:
        """دمج كل القوائم المفعّلة في set واحد للبحث الفوري.

        المعاملات:
            case_fold:  تطبيع الحالة.
            max_bytes:  حدّ أقصى إجمالي للذاكرة (افتراضي: max_load_bytes).

        يعيد set من كل الكلمات الفريدة من القوائم المفعّلة.

        يرفع ValueError إن تجاوز الحجم الإجمالي الحدّ.
        """
        limit = max_bytes or self.max_load_bytes
        enabled = self.list_enabled()
        total_size = sum(e.size_bytes for e in enabled)
        if total_size > limit:
            raise ValueError(
                f"الحجم الإجمالي للقوائم المفعّلة ({total_size} بايت) يتجاوز "
                f"الحدّ ({limit}). استخدم iter_enabled() للتدفّق بدلاً من "
                f"التحميل الكامل، أو عطّل بعض القوائم."
            )
        result: Set[str] = set()
        for entry in enabled:
            for w in iter_wordlist(entry.path, case_fold=case_fold):
                result.add(w)
        return result

    def iter_enabled(self, case_fold: bool = False) -> Iterator[str]:
        """مولّد يُنتج كلمات كل القوائم المفعّلة سطراً بسطر (تدفّقي).

        مناسب للقوائم الكبيرة جداً دون استنفاد الذاكرة.
        """
        for entry in self.list_enabled():
            yield from iter_wordlist(entry.path, case_fold=case_fold)

    # -------------------------------------------------------------------
    # الحفظ والتحميل (JSON registry)
    # -------------------------------------------------------------------

    def save_registry(self) -> None:
        """حفظ سجلّ القوائم في JSON."""
        os.makedirs(os.path.dirname(os.path.abspath(self.registry_path)) or ".",
                    exist_ok=True)
        data = {
            "version": 1,
            "saved_at": time.time(),
            "max_load_bytes": self.max_load_bytes,
            "entries": [e.to_dict() for e in self._entries.values()],
        }
        with open(self.registry_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)

    def load_registry(self) -> None:
        """تحميل سجلّ القوائم من JSON إن وُجد."""
        if not os.path.exists(self.registry_path):
            return
        try:
            with open(self.registry_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            for ed in data.get("entries", []):
                entry = WordlistEntry.from_dict(ed)
                self._entries[entry.name] = entry
        except (json.JSONDecodeError, OSError, TypeError):
            # سجلّ تالف — نبدأ بسجلّ فارغ
            self._entries = {}

    # -------------------------------------------------------------------
    # تكامل مع wordlist_loader الموجود
    # -------------------------------------------------------------------

    def get_default_wordlist_path(self) -> Optional[str]:
        """إرجاع مسار أول قائمة مفعّلة (أو None).

        مفيد للتوافق مع الكود القديم الذي يتوقّع مساراً واحداً.
        """
        enabled = self.list_enabled()
        if enabled:
            return enabled[0].path
        return None


__all__ = [
    "WordlistEntry",
    "WordlistManager",
    "DEFAULT_MAX_LOAD_BYTES",
]
