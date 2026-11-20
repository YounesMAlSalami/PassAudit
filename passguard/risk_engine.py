"""
passguard.risk_engine
=====================

محرّك تقييم مخاطر مركزي يجمع نتائج كل المصادر في تقييم موحّد.

المدخلات:
  - تحليل كلمة مرور واحدة (PasswordAnalysis).
  - تقرير تدقيق Linux (AuditReport).
  - تقرير تدقيق Windows (AuditReport).
  - تقرير سياسات كلمات المرور (PolicyReport).
  - نتائج خوارزميات التجزئة (من AuditReport.findings.algorithm).

كل finding يتضمّن:
  - finding_id:       معرّف فريد.
  - title:            عنوان بصري.
  - category:         فئة المخاطرة (password_weakness / hash_algorithm /
                      account_config / policy_gap).
  - severity:         critical / high / medium / low / info.
  - confidence:       high / medium / low.
  - evidence:         الدليل المُكتشَف (مُخفّى لكلمات المرور).
  - detection_source: المصدر (linux_auditor / windows_auditor / ...).
  - description:      وصف ما اكتُشف.
  - remediation:      توصية الإصلاح.

قواعد التصنيف الموثّقة (لا نسب عشوائية):
  - كلمة مرور مطابقة للقائمة → critical / password_weakness / high confidence.
  - كلمة مرور فارغة → critical / account_config / high confidence.
  - حساب مقفل/معطّل → info / account_config / high confidence.
  - خوارزمية تجزئة غير مدعومة → medium / hash_algorithm / medium confidence.
  - خوارزمية ضعيفة (MD5/DES/LM) → high / hash_algorithm / high confidence.
  - سياسة: حدّ طول < 8 → high / policy_gap / high confidence.
  - سياسة: لا قفل حساب → medium / policy_gap / high confidence.
  - تحليل كلمة مرور: guessability=trivial → critical / password_weakness / high.
  - تحليل: pattern_risk=critical → high / password_weakness / medium.

فئات المخاطرة مفصولة: password_weakness، hash_algorithm، account_config،
policy_gap — لا تُدمج في تصنيف واحد.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .reporter import AuditReport
from .password_policy_auditor import PolicyReport


# ===========================================================================
# ثوابت التصنيف
# ===========================================================================

CATEGORIES = [
    "password_weakness",   # كلمات مرور ضعيفة/مكشوفة
    "hash_algorithm",      # خوارزميات تجزئة ضعيفة/غير مدعومة
    "account_config",      # إعدادات حساب (فارغة/مقفلة/معطّلة)
    "policy_gap",          # ثغرات في السياسات
]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
CONFIDENCES = ["high", "medium", "low"]

# ترتيب الخطورة للترتيب
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# ===========================================================================
# نموذج البيانات
# ===========================================================================

@dataclass
class RiskFinding:
    """نتيجة تقييم مخاطر واحدة."""
    finding_id: str
    title: str
    category: str               # انظر CATEGORIES
    severity: str               # critical / high / medium / low / info
    confidence: str             # high / medium / low
    evidence: str               # الدليل (مُخفّى لكلمات المرور)
    detection_source: str       # linux_auditor / windows_auditor / ...
    description: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id, "title": self.title,
            "category": self.category, "severity": self.severity,
            "confidence": self.confidence, "evidence": self.evidence,
            "detection_source": self.detection_source,
            "description": self.description, "remediation": self.remediation,
        }


@dataclass
class RiskAssessment:
    """تقييم مخاطر شامل من كل المصادر."""
    findings: List[RiskFinding] = field(default_factory=list)
    severity_distribution: dict = field(default_factory=dict)
    category_distribution: dict = field(default_factory=dict)
    summary: str = ""

    def add(self, finding: RiskFinding) -> None:
        self.findings.append(finding)

    def compute_distribution(self) -> None:
        """إعادة حساب توزيع الخطورة والفئات."""
        self.severity_distribution = {s: 0 for s in SEVERITIES}
        self.category_distribution = {c: 0 for c in CATEGORIES}
        for f in self.findings:
            if f.severity in self.severity_distribution:
                self.severity_distribution[f.severity] += 1
            if f.category in self.category_distribution:
                self.category_distribution[f.category] += 1

    def to_dict(self) -> dict:
        self.compute_distribution()
        return {
            "findings": [f.to_dict() for f in self.findings],
            "severity_distribution": self.severity_distribution,
            "category_distribution": self.category_distribution,
            "summary": self.summary,
        }

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    def sort_by_severity(self) -> List[RiskFinding]:
        """إعادة قائمة مرتّبة حسب الخطورة (تنازلياً)."""
        return sorted(self.findings,
                      key=lambda f: _SEVERITY_RANK.get(f.severity, 0),
                      reverse=True)


# ===========================================================================
# قواعد التصنيف الموثّقة
# ===========================================================================

# خوارزميات التجزئة الضعيفة (تتطلّب ترقية)
WEAK_HASH_ALGOS = {
    "MD5 (crypt)":        ("high", "خوارزمية MD5 ضعيفة وسريعة الكسر."),
    "DES (traditional crypt)": ("critical", "DES قديم جداً وقابل للكسر فوراً."),
    "SunMD5":             ("high", "SunMD5 ضعيفة."),
    "Blowfish (bcrypt)":  ("info", "bcrypt قوية (تأكّد أنّ cost factor ≥ 12)."),
    "SHA-256 (crypt)":    ("medium", "SHA-256 crypt مقبول لكن bcrypt/yescrypt أفضل."),
    "SHA-512 (crypt)":    ("medium", "SHA-512 crypt مقبول لكن bcrypt/yescrypt أفضل."),
    "YESCRYPT":           ("info", "yescrypt قوية."),
    "GOST YESCRYPT":      ("info", "GOST yescrypt قوية."),
}


# ===========================================================================
# دوال التقييم
# ===========================================================================

def assess_password_analysis(analysis) -> List[RiskFinding]:
    """تقييم مخاطر من تحليل كلمة مرور واحدة (PasswordAnalysis)."""
    findings: List[RiskFinding] = []
    if analysis is None:
        return findings

    # كلمة مكشوفة في القائمة
    if analysis.in_wordlist:
        findings.append(RiskFinding(
            finding_id="PA-001",
            title="كلمة المرور مكشوفة في قائمة التسريبات",
            category="password_weakness",
            severity="critical", confidence="high",
            evidence=f"guessability={analysis.guessability}, dictionary_exposure=exposed",
            detection_source="password_analyzer",
            description="كلمة المرور موجودة في قائمة الكلمات الشائعة، تُخمَّس فوراً.",
            remediation="غيّر كلمة المرور فوراً بكلمة فريدة غير موجودة في أيّ قائمة تسريبات."))

    # قابلية تخمين تافته (حتى لو لم تكن في القائمة)
    if analysis.guessability == "trivial" and not analysis.in_wordlist:
        findings.append(RiskFinding(
            finding_id="PA-002",
            title="قابلية تخمين تافته",
            category="password_weakness",
            severity="critical", confidence="medium",
            evidence=f"entropy={analysis.entropy_bits} bits, guessability={analysis.guessability}",
            detection_source="password_analyzer",
            description="كلمة المرور قصيرة/بسيطة لدرجة تُخمَّس فوراً.",
            remediation="استخدم 12+ حرفاً مع تنوّع أصناف الأحرف."))

    # أنماط حرجة
    if analysis.pattern_risk == "critical":
        findings.append(RiskFinding(
            finding_id="PA-003",
            title="أنماط ضعف حرجة متعدّدة",
            category="password_weakness",
            severity="high", confidence="medium",
            evidence=f"pattern_risk={analysis.pattern_risk}, patterns={len(analysis.patterns)}",
            detection_source="password_analyzer",
            description="اكتُشفت أنماط ضعف حرجة متعدّدة في كلمة المرور.",
            remediation="تجنّب الأنماط المكتشفة (تسلسلات، لوحة مفاتيح، تكرارات)."))

    # طول قصير
    if 0 < analysis.password_length < 8:
        findings.append(RiskFinding(
            finding_id="PA-004",
            title="طول كلمة المرور قصير جداً",
            category="password_weakness",
            severity="high", confidence="high",
            evidence=f"length={analysis.password_length}",
            detection_source="password_analyzer",
            description=f"كلمة المرور بطول {analysis.password_length} حرفاً فقط (< 8).",
            remediation="استخدم 12 حرفاً على الأقل."))

    return findings


def assess_audit_report(report: AuditReport,
                        source_name: str) -> List[RiskFinding]:
    """تقييم مخاطر من تقرير تدقيق (Linux أو Windows)."""
    findings: List[RiskFinding] = []
    if report is None:
        return findings

    for f in report.findings:
        # تخطّي السجلات الوصفية (مثل system-accounts)
        if f.status == "skipped":
            continue

        # كلمة مرور ضعيفة (مطابقة)
        if f.status == "weak":
            findings.append(RiskFinding(
                finding_id=f"{source_name}-WEAK-{f.username}",
                title=f"كلمة مرور ضعيفة للحساب {f.username}",
                category="password_weakness",
                severity="critical", confidence="high",
                evidence=f"matched={f.matched_password_masked}, algo={f.algorithm}",
                detection_source=source_name,
                description=f"كلمة مرور {f.username} مطابقة لإدخال في القائمة الشائعة.",
                remediation=f"أجبر {f.username} على تغيير كلمة المرور فوراً."))

        # كلمة مرور فارغة
        elif f.status == "empty":
            findings.append(RiskFinding(
                finding_id=f"{source_name}-EMPTY-{f.username}",
                title=f"حساب بدون كلمة مرور: {f.username}",
                category="account_config",
                severity="critical", confidence="high",
                evidence=f"algo={f.algorithm}",
                detection_source=source_name,
                description=f"الحساب {f.username} ليس له كلمة مرور مضبوطة.",
                remediation=f"اضبط كلمة مرور قوية لـ {f.username} أو عطّله."))

        # غير مُقيَّمة (خوارزمية غير مدعومة)
        elif f.status == "not_assessed":
            findings.append(RiskFinding(
                finding_id=f"{source_name}-UNSUPP-{f.username}",
                title=f"خوارزمية غير مدعومة: {f.username}",
                category="hash_algorithm",
                severity="medium", confidence="medium",
                evidence=f"algo={f.algorithm}",
                detection_source=source_name,
                description=f"خوارزمية تجزئة {f.username} ({f.algorithm}) غير مدعومة من backend.",
                remediation="ثبّت passlib أو حدّث backend لدعم الخوارزمية."))

        # خطأ معالجة
        elif f.status == "error":
            findings.append(RiskFinding(
                finding_id=f"{source_name}-ERR-{f.username}",
                title=f"خطأ في معالجة الحساب: {f.username}",
                category="account_config",
                severity="medium", confidence="low",
                evidence=f"notes={f.notes[:80]}",
                detection_source=source_name,
                description=f"تعذّر تقييم {f.username}: {f.notes}",
                remediation="راجع ملفات السجل وأعد الفحص."))

        # خوارزمية ضعيفة (حتى لو لم تُطابق القائمة)
        if f.algorithm:
            algo_info = WEAK_HASH_ALGOS.get(f.algorithm)
            if algo_info:
                sev, desc = algo_info
                if sev in ("critical", "high"):
                    findings.append(RiskFinding(
                        finding_id=f"{source_name}-WEAKALGO-{f.username}",
                        title=f"خوارزمية تجزئة ضعيفة: {f.username}",
                        category="hash_algorithm",
                        severity=sev, confidence="high",
                        evidence=f"algo={f.algorithm}",
                        detection_source=source_name,
                        description=desc,
                        remediation="رحّل الحساب إلى bcrypt/yescrypt/argon2."))

    return findings


def assess_policy_report(report: PolicyReport) -> List[RiskFinding]:
    """تقييم مخاطر من تقرير السياسات."""
    findings: List[RiskFinding] = []
    if report is None:
        return findings

    for pf in report.findings:
        if pf.status == "non_compliant":
            findings.append(RiskFinding(
                finding_id=f"POLICY-{pf.policy_id}",
                title=f"ثغرة سياسة: {pf.title}",
                category="policy_gap",
                severity=pf.severity, confidence=pf.confidence,
                evidence=f"source={pf.source}, value={pf.value}",
                detection_source="policy_auditor",
                description=pf.description,
                remediation=pf.remediation))
        elif pf.status == "warning":
            findings.append(RiskFinding(
                finding_id=f"POLICY-{pf.policy_id}",
                title=f"تحذير سياسة: {pf.title}",
                category="policy_gap",
                severity=pf.severity, confidence=pf.confidence,
                evidence=f"source={pf.source}, value={pf.value}",
                detection_source="policy_auditor",
                description=pf.description,
                remediation=pf.remediation))
        elif pf.status == "not_assessed":
            # not_assessed → low severity finding (يتطلّب مراجعة)
            findings.append(RiskFinding(
                finding_id=f"POLICY-NA-{pf.policy_id}",
                title=f"سياسة غير مُقيَّمة: {pf.title}",
                category="policy_gap",
                severity="low", confidence="high",
                evidence=f"source={pf.source}",
                detection_source="policy_auditor",
                description=f"لم يتمكّن المحلّل من تقييم {pf.title}: {pf.description}",
                remediation=pf.remediation))

    return findings


def assess_risk(
    password_analysis=None,
    linux_report: Optional[AuditReport] = None,
    windows_report: Optional[AuditReport] = None,
    policy_report: Optional[PolicyReport] = None,
) -> RiskAssessment:
    """
    بناء تقييم مخاطر مركزي من كل المدخلات المتاحة.

    أيّ مدخل None يُتخطّى. التقييم يجمع كل النتائج في RiskAssessment واحد
    مع توزيع الخطورة والفئات وملخّص بشري.
    """
    assessment = RiskAssessment()

    if password_analysis is not None:
        assessment.findings.extend(assess_password_analysis(password_analysis))
    if linux_report is not None:
        assessment.findings.extend(assess_audit_report(linux_report, "linux_auditor"))
    if windows_report is not None:
        assessment.findings.extend(assess_audit_report(windows_report, "windows_auditor"))
    if policy_report is not None:
        assessment.findings.extend(assess_policy_report(policy_report))

    assessment.compute_distribution()

    # ملخّص بشري
    n_critical = assessment.severity_distribution.get("critical", 0)
    n_high = assessment.severity_distribution.get("high", 0)
    n_medium = assessment.severity_distribution.get("medium", 0)
    n_total = len(assessment.findings)
    if n_critical > 0:
        assessment.summary = (
            f"تقييم المخاطر: {n_critical} خطر حرج، {n_high} عالي، "
            f"{n_medium} متوسط، {n_total} إجمالي. "
            f"تتطلّب إصلاحاً عاجلاً للمخاطر الحرجة.")
    elif n_high > 0:
        assessment.summary = (
            f"تقييم المخاطر: {n_high} خطر عالي، {n_medium} متوسط، {n_total} إجمالي. "
            f"خطط لإصلاح المخاطر العالية.")
    elif n_medium > 0:
        assessment.summary = (
            f"تقييم المخاطر: {n_medium} خطر متوسط، {n_total} إجمالي. "
            f"لا مخاطر حرجة أو عالية.")
    elif n_total > 0:
        assessment.summary = (
            f"تقييم المخاطر: {n_total} مخاطر منخفضة/معلوماتية فقط.")
    else:
        assessment.summary = "تقييم المخاطر: لا توجد مخاطر مكتشفة."

    return assessment


__all__ = [
    "RiskFinding", "RiskAssessment",
    "assess_risk", "assess_password_analysis",
    "assess_audit_report", "assess_policy_report",
    "CATEGORIES", "SEVERITIES", "CONFIDENCES", "WEAK_HASH_ALGOS",
]
