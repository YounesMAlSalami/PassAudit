"""
passguard.password_policy_auditor
=================================

تقييم سياسات كلمات المرور وحماية الحسابات من مصادر متعددة، مع تتبّع صريح
للمصدر لكل تقييم.

المصادر المدعومة:
  - Linux:  /etc/login.defs (إعدادات الشيخوخة)، /etc/pam.d/ (وحدات PAM
            مثل pam_pwquality/pam_cracklib)، بيانات chage.
  - Windows: تصدير Local Security Policy (secpol.msc → .inf)، تصدير
            Active Directory (fine-grained password policies).

قواعد صارمة:
  - كل تقييم يُحدِّد مصدره بوضوح.
  - إن لم يتوفّر الدليل المطلوب، الحالة = "not_assessed" — لا نخترع قيماً
    ولا نفترض أنّ غياب البيانات يعني الامتثال.
  - لا نسب مئوية عشوائية: تصنيفات وصفيّة (compliant/non_compliant/warning).

سياسات تُقيَّم:
  - الحدّ الأدنى لطول كلمة المرور.
  - سجلّ كلمات المرور (password history).
  - الحدّ الأقصى لعمر كلمة المرور.
  - الحدّ الأدنى لعمر كلمة المرور.
  - سياسة قفل الحساب.
  - تعقيد كلمة المرور.
  - حالة MFA (تقييم محدود — يتطلّب فحص PAM أو تصدير AD).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional


# ===========================================================================
# نماذج البيانات
# ===========================================================================

@dataclass
class PolicyFinding:
    """نتيجة تقييم سياسة واحدة."""
    policy_id: str              # معرّف آلي (min_password_length, ...)
    title: str                  # عنوان بصري
    source: str                 # مصدر الدليل (linux-login.defs, linux-PAM, ...)
    value: str                  # القيمة المكتشفة أو "Not Assessed"
    status: str                 # compliant / non_compliant / warning / not_assessed
    severity: str               # critical / high / medium / low / info
    confidence: str             # high / medium / low
    description: str
    remediation: str
    evidence: str = ""          # الدليل الخام (سطر الإعداد، إلخ)

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id, "title": self.title,
            "source": self.source, "value": self.value,
            "status": self.status, "severity": self.severity,
            "confidence": self.confidence, "description": self.description,
            "remediation": self.remediation, "evidence": self.evidence,
        }


@dataclass
class PolicyReport:
    """تقرير تقييم السياسات."""
    platform: str                       # "linux" / "windows"
    source_files: List[str] = field(default_factory=list)
    findings: List[PolicyFinding] = field(default_factory=list)
    assessment_notes: List[str] = field(default_factory=list)

    def add(self, finding: PolicyFinding) -> None:
        self.findings.append(finding)

    @property
    def compliant_count(self) -> int:
        return sum(1 for f in self.findings if f.status == "compliant")

    @property
    def non_compliant_count(self) -> int:
        return sum(1 for f in self.findings if f.status == "non_compliant")

    @property
    def not_assessed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == "not_assessed")

    def to_dict(self) -> dict:
        return {
            "platform": self.platform,
            "source_files": self.source_files,
            "findings": [f.to_dict() for f in self.findings],
            "summary": {
                "total": len(self.findings),
                "compliant": self.compliant_count,
                "non_compliant": self.non_compliant_count,
                "not_assessed": self.not_assessed_count,
            },
            "assessment_notes": self.assessment_notes,
        }


# ===========================================================================
# تقييم سياسات Linux
# ===========================================================================

def _parse_login_defs(path: str) -> dict:
    """تحليل /etc/login.defs وإرجاع {key: value}."""
    result: dict = {}
    if not path or not os.path.exists(path):
        return result
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    result[parts[0]] = parts[1]
    except OSError:
        pass
    return result


def _parse_pam_pwquality(pam_dir: str) -> dict:
    """البحث في /etc/pam.d/ عن وحدات pam_pwquality/pam_cracklib وإعداداتها.

    أيضاً يلتقط معامل `remember` من سطر pam_unix (سجلّ كلمات المرور).
    """
    settings: dict = {"module": None, "args": {}, "remember": None}
    if not pam_dir or not os.path.isdir(pam_dir):
        return settings
    candidates = ["common-password", "system-auth", "password-auth"]
    for fname in candidates:
        path = os.path.join(pam_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split()
                    if len(parts) < 3 or parts[0] != "password":
                        continue
                    module = parts[2]
                    # pam_pwquality / pam_cracklib: إعدادات التعقيد
                    if "pam_pwquality" in module or "pam_cracklib" in module:
                        if not settings["module"]:
                            settings["module"] = os.path.basename(module)
                        args = parts[3:]
                        for arg in args:
                            if "=" in arg:
                                k, v = arg.split("=", 1)
                                settings["args"][k] = v
                    # pam_unix: قد يحوي remember=N
                    if "pam_unix" in module:
                        args = parts[3:]
                        for arg in args:
                            if arg.startswith("remember="):
                                try:
                                    settings["remember"] = int(arg.split("=", 1)[1])
                                except ValueError:
                                    pass
        except OSError:
            continue
    return settings


def audit_linux_password_policy(
    login_defs_path: str = "/etc/login.defs",
    pam_dir: str = "/etc/pam.d/",
    chage_data: Optional[dict] = None,
) -> PolicyReport:
    """
    تقييم سياسات كلمات المرور في Linux من /etc/login.defs وPAM.

    المعاملات:
        login_defs_path: مسار /etc/login.defs.
        pam_dir:         مسار مجلد PAM (/etc/pam.d/).
        chage_data:      بيانات شيخوخة كلمة المرور (من chage -l) كـ dict
                         اختياري لكل مستخدم. إن None → not_assessed.

    يعيد PolicyReport. كل finding يحدّد مصدره.
    """
    report = PolicyReport(platform="linux")
    if os.path.exists(login_defs_path):
        report.source_files.append(login_defs_path)
    if os.path.isdir(pam_dir):
        report.source_files.append(pam_dir)

    login_defs = _parse_login_defs(login_defs_path)
    pam_settings = _parse_pam_pwquality(pam_dir)

    # --- الحدّ الأدنى لطول كلمة المرور ---
    min_len = None
    source = "not_assessed"
    evidence = ""
    if pam_settings["args"].get("minlen"):
        min_len = int(pam_settings["args"]["minlen"])
        source = "linux-PAM"
        evidence = f"{pam_settings['module']}: minlen={min_len}"
    elif login_defs.get("PASS_MIN_LEN"):
        # PASS_MIN_LEN في login.defs مُهمل وغالباً غير مُفعّل
        try:
            min_len = int(login_defs["PASS_MIN_LEN"])
            source = "linux-login.defs (deprecated)"
            evidence = f"PASS_MIN_LEN {min_len} (مُهمل، استخدم pam_pwquality)"
        except ValueError:
            pass
    if min_len is not None:
        if min_len < 8:
            status, severity = "non_compliant", "high"
        elif min_len < 12:
            status, severity = "warning", "medium"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="min_password_length",
            title="الحدّ الأدنى لطول كلمة المرور",
            source=source, value=str(min_len),
            status=status, severity=severity, confidence="high",
            description=f"الحدّ الأدنى للطول = {min_len}. المعيار: ≥ 12.",
            remediation="اضبط minlen=12 في pam_pwquality." if "PAM" in source
                       else "استخدم pam_pwquality بـ minlen=12.",
            evidence=evidence))
    else:
        report.add(PolicyFinding(
            policy_id="min_password_length",
            title="الحدّ الأدنى لطول كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُعثر على إعداد حدّ أدنى للطول في login.defs أو PAM.",
            remediation="ثبّت pam_pwquality واضبط minlen=12.",
            evidence=""))

    # --- تعقيد كلمة المرور ---
    if pam_settings["module"]:
        has_complexity = any(k in pam_settings["args"]
                             for k in ["dcredit", "ucredit", "lcredit", "ocredit"])
        if has_complexity:
            report.add(PolicyFinding(
                policy_id="password_complexity",
                title="تعقيد كلمة المرور",
                source="linux-PAM", value=str(pam_settings["args"]),
                status="compliant", severity="info", confidence="high",
                description=f"وحدة {pam_settings['module']} مُفعّلة بمتطلّبات تعقيد.",
                remediation="راجع أنّ dcredit/ucredit/lcredit/ocredit ≥ 1.",
                evidence=str(pam_settings["args"])))
        else:
            report.add(PolicyFinding(
                policy_id="password_complexity",
                title="تعقيد كلمة المرور",
                source="linux-PAM", value="module without credit args",
                status="warning", severity="medium", confidence="medium",
                description=f"وحدة {pam_settings['module']} موجودة لكن بدون متطلّبات تعقيد صريحة.",
                remediation="أضف dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1.",
                evidence=str(pam_settings)))
    else:
        report.add(PolicyFinding(
            policy_id="password_complexity",
            title="تعقيد كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُعثر على pam_pwquality أو pam_cracklib في PAM.",
            remediation="ثبّت وفعّل pam_pwquality بمتطلّبات تعقيد.",
            evidence=""))

    # --- الحدّ الأقصى لعمر كلمة المرور ---
    max_days = None
    if login_defs.get("PASS_MAX_DAYS"):
        try:
            max_days = int(login_defs["PASS_MAX_DAYS"])
        except ValueError:
            pass
    if max_days is not None:
        # نتحقّق من الحالات الأكثر خطورة أولاً (ترتيب التحقّق مهم)
        if max_days == 99999 or max_days > 365:
            status, severity = "non_compliant", "high"
        elif max_days > 90:
            status, severity = "non_compliant", "medium"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="max_password_age",
            title="الحدّ الأقصى لعمر كلمة المرور",
            source="linux-login.defs", value=f"{max_days} days",
            status=status, severity=severity, confidence="high",
            description=f"PASS_MAX_DAYS = {max_days}. المعيار: ≤ 90 يوماً.",
            remediation="اضبط PASS_MAX_DAYS=90 في /etc/login.defs.",
            evidence=f"PASS_MAX_DAYS {max_days}"))
    else:
        report.add(PolicyFinding(
            policy_id="max_password_age",
            title="الحدّ الأقصى لعمر كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="low", confidence="high",
            description="لم يُعثر على PASS_MAX_DAYS في /etc/login.defs.",
            remediation="اضبط PASS_MAX_DAYS=90.",
            evidence=""))

    # --- الحدّ الأدنى لعمر كلمة المرور ---
    min_days = None
    if login_defs.get("PASS_MIN_DAYS"):
        try:
            min_days = int(login_defs["PASS_MIN_DAYS"])
        except ValueError:
            pass
    if min_days is not None:
        if min_days < 1:
            status, severity = "warning", "low"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="min_password_age",
            title="الحدّ الأدنى لعمر كلمة المرور",
            source="linux-login.defs", value=f"{min_days} days",
            status=status, severity=severity, confidence="high",
            description=f"PASS_MIN_DAYS = {min_days}. يمنع تغيير كلمة المرور فوراً بعد تغييرها.",
            remediation="اضبط PASS_MIN_DAYS=1 على الأقل.",
            evidence=f"PASS_MIN_DAYS {min_days}"))
    else:
        report.add(PolicyFinding(
            policy_id="min_password_age",
            title="الحدّ الأدنى لعمر كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="low", confidence="high",
            description="لم يُعثر على PASS_MIN_DAYS.",
            remediation="اضبط PASS_MIN_DAYS=1.",
            evidence=""))

    # --- سجلّ كلمات المرور (password history) ---
    # pam_unix يدعم remember=N (نلتقطه من _parse_pam_pwquality)
    remember = pam_settings.get("remember")
    if remember is None and pam_settings["args"].get("remember"):
        try:
            remember = int(pam_settings["args"]["remember"])
        except ValueError:
            pass
    if remember is not None:
        if remember < 5:
            status, severity = "warning", "medium"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="password_history",
            title="سجلّ كلمات المرور",
            source="linux-PAM", value=f"remember={remember}",
            status=status, severity=severity, confidence="high",
            description=f"يُحتفظ بـ {remember} كلمة مرور سابقة. المعيار: ≥ 5.",
            remediation="اضبط remember=5 في pam_unix.",
            evidence=f"remember={remember}"))
    else:
        report.add(PolicyFinding(
            policy_id="password_history",
            title="سجلّ كلمات المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُعثر على إعداد remember في PAM.",
            remediation="أضف remember=5 إلى pam_unix في /etc/pam.d/common-password.",
            evidence=""))

    # --- قفل الحساب (account lockout) ---
    # Linux لا يملك سياسة قفل مدمجة قياسية مثل Windows. نتحقّق من pam_faillock/pam_tally2.
    lockout_module = None
    if os.path.isdir(pam_dir):
        for fname in ["common-auth", "system-auth", "password-auth"]:
            path = os.path.join(pam_dir, fname)
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                    if "pam_faillock" in content:
                        lockout_module = "pam_faillock"
                        break
                    if "pam_tally2" in content or "pam_tally" in content:
                        lockout_module = "pam_tally2"
                        break
            except OSError:
                continue
    if lockout_module:
        report.add(PolicyFinding(
            policy_id="account_lockout",
            title="سياسة قفل الحساب",
            source="linux-PAM", value=lockout_module,
            status="compliant", severity="info", confidence="medium",
            description=f"وحدة {lockout_module} مُفعّلة لقفل الحساب بعد محاولات فاشلة.",
            remediation="راجع إعدادات deny/lock_time في pam_faillock.",
            evidence=lockout_module))
    else:
        report.add(PolicyFinding(
            policy_id="account_lockout",
            title="سياسة قفل الحساب",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُعثر على pam_faillock أو pam_tally2. Linux لا يملك قفلاً افتراضياً.",
            remediation="ثبّت pam_faillock بـ deny=5 unlock_time=600.",
            evidence=""))

    # --- MFA ---
    # فحص محدود: نتحقّق من pam_google_authenticator أو pam_oath في PAM
    mfa_found = False
    if os.path.isdir(pam_dir):
        for fname in os.listdir(pam_dir):
            if fname.startswith(".") or fname in ["other", "common-", "system-"]:
                continue
            path = os.path.join(pam_dir, fname)
            if not os.path.isfile(path):
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
                    if "pam_google_authenticator" in content or "pam_oath" in content:
                        mfa_found = True
                        break
            except OSError:
                continue
    if mfa_found:
        report.add(PolicyFinding(
            policy_id="mfa_enforcement",
            title="حالة MFA",
            source="linux-PAM", value="MFA module detected",
            status="compliant", severity="info", confidence="low",
            description="وُجدت وحدة MFA (pam_google_authenticator/pam_oath) في PAM.",
            remediation="تأكّد من إلزامية MFA للحسابات الحسّاسة.",
            evidence="MFA module found in PAM"))
    else:
        report.add(PolicyFinding(
            policy_id="mfa_enforcement",
            title="حالة MFA",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="low", confidence="medium",
            description="لم يُعثر على وحدة MFA في PAM. لا يمكن الجزم بدون فحص أدوات خارجية.",
            remediation="فكّر في تفعيل pam_google_authenticator للحسابات الحسّاسة.",
            evidence=""))

    return report


# ===========================================================================
# تقييم سياسات Windows
# ===========================================================================

def _parse_lsp_inf(path: str) -> dict:
    """تحليل تصدير Local Security Policy (.inf) إلى dict {section: {key: val}}."""
    result: dict = {}
    if not path or not os.path.exists(path):
        return result
    current_section = None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith(";") or line.startswith("[Unicode]"):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    current_section = line[1:-1]
                    result[current_section] = {}
                    continue
                if "=" in line and current_section:
                    k, v = line.split("=", 1)
                    result[current_section][k.strip()] = v.strip()
    except OSError:
        pass
    return result


def audit_windows_password_policy(
    lsp_export_path: Optional[str] = None,
    ad_export_path: Optional[str] = None,
) -> PolicyReport:
    """
    تقييم سياسات كلمات المرور في Windows من تصدير LSP أو AD.

    المعاملات:
        lsp_export_path: مسار تصدير secpol.msc (.inf).
        ad_export_path:  مسار تصدير سياسة AD (JSON/CSV). اختياري.

    يعيد PolicyReport. إن لم يتوفّر أيّ مصدر → كل التقييمات not_assessed.
    """
    report = PolicyReport(platform="windows")

    lsp_data = _parse_lsp_inf(lsp_export_path) if lsp_export_path else {}
    if lsp_export_path and os.path.exists(lsp_export_path):
        report.source_files.append(lsp_export_path)
    if ad_export_path and os.path.exists(ad_export_path):
        report.source_files.append(ad_export_path)

    pw_policy = lsp_data.get("Password Policy", {})
    lockout_policy = lsp_data.get("Account Lockout Policy", {})

    def _get_int(d, key):
        v = d.get(key)
        if v is None:
            return None
        try:
            return int(v)
        except (ValueError, TypeError):
            return None

    # --- الحدّ الأدنى للطول ---
    min_len = _get_int(pw_policy, "MinimumPasswordLength")
    if min_len is not None:
        if min_len < 8:
            status, severity = "non_compliant", "high"
        elif min_len < 12:
            status, severity = "warning", "medium"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="min_password_length",
            title="الحدّ الأدنى لطول كلمة المرور",
            source="windows-LSP", value=str(min_len),
            status=status, severity=severity, confidence="high",
            description=f"MinimumPasswordLength = {min_len}. المعيار: ≥ 12.",
            remediation="اضبط MinimumPasswordLength=12 في Local Security Policy.",
            evidence=f"MinimumPasswordLength={min_len}"))
    else:
        report.add(PolicyFinding(
            policy_id="min_password_length",
            title="الحدّ الأدنى لطول كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُقدِّم تصدير LSP قيمة MinimumPasswordLength.",
            remediation="صدّر secpol.msc ووفّر المسار.",
            evidence=""))

    # --- التعقيد ---
    complexity = pw_policy.get("PasswordComplexity")
    if complexity is not None:
        enabled = complexity in ("1", 1, "enabled", "true")
        report.add(PolicyFinding(
            policy_id="password_complexity",
            title="تعقيد كلمة المرور",
            source="windows-LSP", value="Enabled" if enabled else "Disabled",
            status="compliant" if enabled else "non_compliant",
            severity="info" if enabled else "high", confidence="high",
            description=f"PasswordComplexity = {complexity}.",
            remediation="فعّل PasswordComplexity=1.",
            evidence=f"PasswordComplexity={complexity}"))
    else:
        report.add(PolicyFinding(
            policy_id="password_complexity",
            title="تعقيد كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُقدِّم تصدير LSP قيمة PasswordComplexity.",
            remediation="صدّر secpol.msc ووفّر المسار.",
            evidence=""))

    # --- الحدّ الأقصى للعمر ---
    max_age = _get_int(pw_policy, "MaximumPasswordAge")
    if max_age is not None:
        if max_age > 90:
            status, severity = "non_compliant", "medium"
        elif max_age == 0:
            status, severity = "non_compliant", "high"   # كلمات لا تنتهي
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="max_password_age",
            title="الحدّ الأقصى لعمر كلمة المرور",
            source="windows-LSP", value=f"{max_age} days",
            status=status, severity=severity, confidence="high",
            description=f"MaximumPasswordAge = {max_age}. المعيار: ≤ 90 يوماً.",
            remediation="اضبط MaximumPasswordAge=90.",
            evidence=f"MaximumPasswordAge={max_age}"))
    else:
        report.add(PolicyFinding(
            policy_id="max_password_age",
            title="الحدّ الأقصى لعمر كلمة المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="low", confidence="high",
            description="لم يُقدِّم تصدير LSP قيمة MaximumPasswordAge.",
            remediation="صدّر secpol.msc ووفّر المسار.",
            evidence=""))

    # --- سجلّ كلمات المرور ---
    history = _get_int(pw_policy, "PasswordHistorySize")
    if history is not None:
        if history < 5:
            status, severity = "warning", "medium"
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="password_history",
            title="سجلّ كلمات المرور",
            source="windows-LSP", value=str(history),
            status=status, severity=severity, confidence="high",
            description=f"PasswordHistorySize = {history}. المعيار: ≥ 5.",
            remediation="اضبط PasswordHistorySize=5.",
            evidence=f"PasswordHistorySize={history}"))
    else:
        report.add(PolicyFinding(
            policy_id="password_history",
            title="سجلّ كلمات المرور",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُقدِّم تصدير LSP قيمة PasswordHistorySize.",
            remediation="صدّر secpol.msc ووفّر المسار.",
            evidence=""))

    # --- قفل الحساب ---
    lockout_threshold = _get_int(lockout_policy, "LockoutBadCount")
    if lockout_threshold is not None:
        if lockout_threshold == 0:
            status, severity = "non_compliant", "high"   # لا قفل
        else:
            status, severity = "compliant", "info"
        report.add(PolicyFinding(
            policy_id="account_lockout",
            title="سياسة قفل الحساب",
            source="windows-LSP", value=f"threshold={lockout_threshold}",
            status=status, severity=severity, confidence="high",
            description=f"LockoutBadCount = {lockout_threshold}. 0 = لا قفل.",
            remediation="اضبط LockoutBadCount=5.",
            evidence=f"LockoutBadCount={lockout_threshold}"))
    else:
        report.add(PolicyFinding(
            policy_id="account_lockout",
            title="سياسة قفل الحساب",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="medium", confidence="high",
            description="لم يُقدِّم تصدير LSP قيمة LockoutBadCount.",
            remediation="صدّر secpol.msc ووفّر المسار.",
            evidence=""))

    # --- MFA ---
    # Windows: لا يمكن تقييم MFA من LSP فقط. يتطلّب فحص AD/Azure AD.
    if ad_export_path and os.path.exists(ad_export_path):
        report.add(PolicyFinding(
            policy_id="mfa_enforcement",
            title="حالة MFA",
            source="AD-export", value="Provided (requires manual review)",
            status="not_assessed", severity="low", confidence="low",
            description="تصدير AD مُقدَّم لكن تقييم MFA يتطلّب مراجعة يدوية للسياسات.",
            remediation="راجع سياسات Conditional Access في AD/Azure AD.",
            evidence=ad_export_path))
    else:
        report.add(PolicyFinding(
            policy_id="mfa_enforcement",
            title="حالة MFA",
            source="not_assessed", value="Not Assessed",
            status="not_assessed", severity="low", confidence="high",
            description="تقييم MFA يتطلّب تصدير AD/Azure AD — لم يُقدَّم.",
            remediation="وفّر تصدير AD لمراجعة MFA.",
            evidence=""))

    if not lsp_data and not ad_export_path:
        report.assessment_notes.append(
            "لم يُقدَّم أيّ مصدر سياسة (LSP أو AD). كل التقييمات not_assessed.")

    return report


__all__ = [
    "PolicyFinding", "PolicyReport",
    "audit_linux_password_policy", "audit_windows_password_policy",
]
