"""
passguard.audit_history
=======================

تخزين بيانات وصفية لتدقيقات كلمات المرور في قاعدة SQLite، مع دعم المقارنة
بين التدقيقات السابقة والحالية.

قواعد أمنية صارمة:
  - لا تُخزَّن كلمات المرور الأصلية أبداً.
  - لا تُخزَّن تجزئات كاملة (hashes) أبداً — فقط معاينات مُخفّاة (first 8 chars).
  - تُخزَّن فقط: بيانات وصفية، عدّادات، ملخّصات النتائج، كلمات مرور مُخفّاة
    (p*******).
  - قاعدة البيانات محلية (offline)، لا اتصال شبكي.

المخطّط:
  - audits:           صفّ واحد لكل تدقيق (timestamp, platform, counts, ...).
  - audit_findings:   ملخّص كل finding (username, status, severity,
                      matched_password_masked — لا نص صريح).
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import sqlite3
import time
from typing import Dict, List, Optional

from .reporter import AuditReport


# ===========================================================================
# المسار الافتراضي لقاعدة البيانات
# ===========================================================================

def _default_db_path() -> str:
    """مسار افتراضي لقاعدة البيانات بجانب الحزمة."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(pkg_dir)
    data_dir = os.path.join(project_dir, "data")
    return os.path.join(data_dir, "passguard_history.db")


# ===========================================================================
# مدير سجلّ التدقيق
# ===========================================================================

class AuditHistory:
    """تخزين واستعلام سجلّ التدقيقات في SQLite.

    الاستخدام:
        hist = AuditHistory()
        audit_id = hist.save_audit(report)
        recent = hist.list_audits(limit=10)
        diff = hist.compare_audits(audit_id_1, audit_id_2)
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        المعاملات:
            db_path: مسار ملف SQLite. إن None يُستخدم مسار افتراضي.
        """
        self.db_path = db_path or _default_db_path()
        os.makedirs(os.path.dirname(os.path.abspath(self.db_path)) or ".",
                    exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """إنشاء الجداول إن لم تكن موجودة."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audits (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    hostname TEXT,
                    tool_version TEXT,
                    hash_backend TEXT,
                    wordlist_path TEXT,
                    wordlist_count INTEGER DEFAULT 0,
                    accounts_scanned INTEGER DEFAULT 0,
                    accounts_weak INTEGER DEFAULT 0,
                    accounts_locked INTEGER DEFAULT 0,
                    accounts_no_match INTEGER DEFAULT 0,
                    accounts_not_assessed INTEGER DEFAULT 0,
                    error_accounts INTEGER DEFAULT 0,
                    skipped_accounts INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0,
                    risk_critical INTEGER DEFAULT 0,
                    risk_high INTEGER DEFAULT 0,
                    risk_medium INTEGER DEFAULT 0,
                    risk_low INTEGER DEFAULT 0,
                    risk_summary TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_findings (
                    finding_rowid INTEGER PRIMARY KEY AUTOINCREMENT,
                    audit_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    source TEXT,
                    algorithm TEXT,
                    status TEXT,
                    severity TEXT,
                    matched_password_masked TEXT,
                    notes TEXT,
                    FOREIGN KEY (audit_id) REFERENCES audits(audit_id)
                        ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_findings_audit
                    ON audit_findings(audit_id);
                CREATE INDEX IF NOT EXISTS idx_audits_platform
                    ON audits(platform);
                CREATE INDEX IF NOT EXISTS idx_audits_timestamp
                    ON audits(timestamp);
            """)

    # -------------------------------------------------------------------
    # الحفظ
    # -------------------------------------------------------------------

    def save_audit(self, report: AuditReport,
                    risk_assessment=None) -> int:
        """حفظ بيانات وصفية لتقرير تدقيق.

        المعاملات:
            report:           AuditReport من تدقيق Linux أو Windows.
            risk_assessment:  RiskAssessment اختياري لتخزين توزيع المخاطر.

        يعيد audit_id (int).

        أمان: لا تُخزَّن كلمات مرور صريحة أو تجزئات كاملة — فقط مُخفّاة.
        """
        report.compute_summary()
        ts = _dt.datetime.now().isoformat(timespec="seconds")

        risk_critical = risk_high = risk_medium = risk_low = 0
        risk_summary = ""
        if risk_assessment is not None:
            dist = risk_assessment.severity_distribution
            risk_critical = dist.get("critical", 0)
            risk_high = dist.get("high", 0)
            risk_medium = dist.get("medium", 0)
            risk_low = dist.get("low", 0)
            risk_summary = risk_assessment.summary

        with sqlite3.connect(self.db_path) as conn:
            cur = conn.execute(
                """INSERT INTO audits (
                    timestamp, platform, hostname, tool_version, hash_backend,
                    wordlist_path, wordlist_count, accounts_scanned,
                    accounts_weak, accounts_locked, accounts_no_match,
                    accounts_not_assessed, error_accounts, skipped_accounts,
                    duration_seconds, risk_critical, risk_high, risk_medium,
                    risk_low, risk_summary
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, report.source_platform, report.hostname,
                 report.tool_version, report.hash_backend,
                 report.wordlist_path, report.wordlist_count,
                 report.accounts_scanned, report.accounts_weak,
                 report.accounts_locked, report.accounts_no_match,
                 report.accounts_not_assessed, report.error_accounts,
                 report.skipped_accounts, report.duration_seconds,
                 risk_critical, risk_high, risk_medium, risk_low,
                 risk_summary))
            audit_id = cur.lastrowid

            # حفظ ملخّص كل finding (فقط البيانات المُخفّاة، لا نص صريح)
            for f in report.findings:
                # تخطّي السجلات الوصفية (system-accounts)
                if f.username.startswith("(") and f.username.endswith(")"):
                    continue
                # لا نُخزّن hash_preview كاملاً — نُخزّنه كما هو (هو أصلاً مُختصر
                # إلى 8 أحرف في reporter). لكن نتأكّد أنّ matched_password_masked
                # ليس نصاً صريحاً.
                masked = f.matched_password_masked
                # تحقّق أمان: إن كان masked يساوي كلمة مرور صريحة (لم تُخفَ)
                # لا نُخزّنه. نُخزّن فقط القيم المُخفّاة (تحوي *).
                if masked and "*" not in masked and masked not in ("(فارغة)", "(لا شيء)"):
                    # لم تُخفَ بشكل صحيح — نتخطّى تخزينها
                    masked = None
                conn.execute(
                    """INSERT INTO audit_findings (
                        audit_id, username, source, algorithm, status,
                        severity, matched_password_masked, notes
                    ) VALUES (?,?,?,?,?,?,?,?)""",
                    (audit_id, f.username, f.source, f.algorithm, f.status,
                     f.severity, masked, f.notes))
            conn.commit()
        return audit_id

    # -------------------------------------------------------------------
    # الاستعلام
    # -------------------------------------------------------------------

    def list_audits(self, limit: int = 50,
                     platform: Optional[str] = None) -> List[dict]:
        """قائمة أحدث التدقيقات (مرتّبة حسب audit_id تنازلياً لضمان ترتيب
        الإدراج حتى لو تطابقت الطوابع الزمنية)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if platform:
                rows = conn.execute(
                    """SELECT * FROM audits WHERE platform=?
                       ORDER BY audit_id DESC LIMIT ?""",
                    (platform, limit)).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM audits
                       ORDER BY audit_id DESC LIMIT ?""",
                    (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_audit(self, audit_id: int) -> Optional[dict]:
        """تفاصيل تدقيق واحد + ملخّص findings."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM audits WHERE audit_id=?",
                (audit_id,)).fetchone()
            if row is None:
                return None
            findings = conn.execute(
                """SELECT username, source, algorithm, status, severity,
                   matched_password_masked, notes
                   FROM audit_findings WHERE audit_id=?""",
                (audit_id,)).fetchall()
            result = dict(row)
            result["findings"] = [dict(f) for f in findings]
            return result

    def get_latest(self, platform: Optional[str] = None) -> Optional[dict]:
        """أحدث تدقيق (لكل المنصات أو لمنصة محدّدة)."""
        audits = self.list_audits(limit=1, platform=platform)
        if not audits:
            return None
        return self.get_audit(audits[0]["audit_id"])

    # -------------------------------------------------------------------
    # المقارنة
    # -------------------------------------------------------------------

    def compare_audits(self, audit_id_1: int,
                        audit_id_2: int) -> dict:
        """مقارنة تدقيقين: الحسابات الضعيفة الجديدة/المُصحَّحة.

        يعيد dict:
            - audit_1, audit_2: بيانات وصفية.
            - new_weak: حسابات ضعيفة في الثاني غير موجودة في الأول.
            - fixed_weak: حسابات ضعيفة في الأول لم تعد ضعيفة في الثاني.
            - still_weak: ضعيفة في كليهما.
            - weak_count_delta: الفرق في عدد الضعفاء.
        """
        a1 = self.get_audit(audit_id_1)
        a2 = self.get_audit(audit_id_2)
        if a1 is None or a2 is None:
            return {"error": "أحد التدقيقين غير موجود"}

        weak_1 = {f["username"] for f in a1.get("findings", [])
                  if f["status"] == "weak"}
        weak_2 = {f["username"] for f in a2.get("findings", [])
                  if f["status"] == "weak"}

        return {
            "audit_1": {"audit_id": audit_id_1, "timestamp": a1["timestamp"],
                        "platform": a1["platform"],
                        "weak_count": len(weak_1)},
            "audit_2": {"audit_id": audit_id_2, "timestamp": a2["timestamp"],
                        "platform": a2["platform"],
                        "weak_count": len(weak_2)},
            "new_weak": sorted(weak_2 - weak_1),
            "fixed_weak": sorted(weak_1 - weak_2),
            "still_weak": sorted(weak_1 & weak_2),
            "weak_count_delta": len(weak_2) - len(weak_1),
        }

    # -------------------------------------------------------------------
    # إحصاءات
    # -------------------------------------------------------------------

    def stats(self) -> dict:
        """إحصاءات إجمالية عن كل التدقيقات المخزّنة."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
            by_platform = dict(conn.execute(
                "SELECT platform, COUNT(*) FROM audits GROUP BY platform"
            ).fetchall())
            total_weak = conn.execute(
                "SELECT SUM(accounts_weak) FROM audits").fetchone()[0] or 0
            total_scanned = conn.execute(
                "SELECT SUM(accounts_scanned) FROM audits").fetchone()[0] or 0
        return {
            "total_audits": total,
            "by_platform": by_platform,
            "total_accounts_scanned": total_scanned,
            "total_weak_accounts": total_weak,
        }

    # -------------------------------------------------------------------
    # تنظيف
    # -------------------------------------------------------------------

    def clear(self) -> int:
        """حذف كل التدقيقات. يعيد عدد الصفوف المحذوفة."""
        with sqlite3.connect(self.db_path) as conn:
            count = conn.execute("SELECT COUNT(*) FROM audits").fetchone()[0]
            conn.execute("DELETE FROM audit_findings")
            conn.execute("DELETE FROM audits")
            conn.commit()
        return count


__all__ = ["AuditHistory"]
