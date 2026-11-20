"""
passguard.reporter
==================

وحدة توليد تقارير التدقيق بثلاث صيغ: JSON, CSV, HTML.

قواعد صارمة:
  1. لا تُخزّن كلمات المرور كنص صريح في أي تقرير. كل كلمة مرور مطابقة
     تُعرض مُخفّاة جزئياً عبر mask_password().
  2. تصنيف النتائج الواضح:
       - weak        : كلمة المرور مطابقة لإدخال في القائمة (حرج).
       - no_match    : لم تُطابق أي كلمة في القائمة — هذا لا يعني الأمان،
                       فقط أنّ القائمة المُستخدمة لم تكشفها.
       - locked      : الحساب مقفل (! prefix).
       - disabled    : الحساب معطّل (* prefix).
       - empty       : لا توجد كلمة مرور مضبوطة.
       - unknown     : صيغة تجزئة غير معروفة.
       - error       : حدث خطأ أثناء معالجة الحساب.
       - not_assessed: خوارزمية التجزئة غير مدعومة من backend النشط،
                       تعذّر التحقق منها.
       - skipped     : حساب مستثنى (نظامي) — للتوافق.
       - secure      : [مُهمل] يُعامَل كـ "no_match" للتوافق الخلفي.
  3. تقارير HTML عربية RTL متجاوبة، لا تحتوي على كلمة المرور الأصلية.

هيكل البيانات:
    Finding        — سجل واحد لكل حساب.
    AuditReport    — تقرير كامل (قائمة Findings + بيانات وصفية).
"""

from __future__ import annotations

import csv
import datetime as _dt
import html
import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ===========================================================================
# ثوابت تصنيف النتائج
# ===========================================================================

# الحالات الرسمية لتصنيف نتيجة فحص حساب
RESULT_STATES = [
    "weak",         # كلمة المرور مطابقة للقائمة (حرج)
    "no_match",     # لم تُطابق — لا يعني الأمان
    "locked",       # مقفل
    "disabled",     # معطّل
    "empty",        # بدون كلمة مرور
    "unknown",      # صيغة غير معروفة
    "error",        # خطأ في المعالجة
    "not_assessed", # خوارزمية غير مدعومة
    "skipped",      # مستثنى (نظامي) — للتوافق
    "secure",       # [مُهمل] يُعامَل كـ no_match
]

# خريطة الحالة → الخطورة الافتراضية
DEFAULT_SEVERITY = {
    "weak":         "critical",
    "no_match":     "low",       # لم يُكشف، لكن ليس دليلاً على الأمان
    "locked":       "info",
    "disabled":     "info",
    "empty":        "high",
    "unknown":      "medium",    # صيغة غير معروفة تستحقّ المراجعة
    "error":        "medium",
    "not_assessed": "medium",    # تعذّر التحقق — يستحقّ المراجعة
    "skipped":      "info",
    "secure":       "low",       # [مُهمل]
}

# تسميات الحالات بالعربية (للتقارير والواجهة)
STATUS_LABELS_AR = {
    "weak":         "🔴 ضعيفة (مطابقة)",
    "no_match":     "🟡 لم تُطابق",
    "locked":       "⚪ مقفلة",
    "disabled":     "⚪ معطّلة",
    "empty":        "🟠 فارغة",
    "unknown":      "❔ غير معروفة",
    "error":        "⚠️ خطأ",
    "not_assessed": "⚠️ غير مُقيَّمة",
    "skipped":      "⏭️ مستثناة",
    "secure":       "🟡 لم تُطابق",   # [مُهمل] نفس no_match
}

# ===========================================================================
# نماذج البيانات
# ===========================================================================

@dataclass
class Finding:
    """سجل نتيجة فحص حساب واحد."""
    username: str
    source: str                       # "linux-shadow" أو "windows-ntlm"
    algorithm: str                    # اسم الخوارزمية المكتشفة
    status: str                       # انظر RESULT_STATES
    matched_password_masked: Optional[str] = None   # كلمة المرور المطابقة مُخفّاة
    hash_preview: Optional[str] = None              # أول 8 أحرف من التجزئة
    severity: str = "info"            # "critical" | "high" | "medium" | "low" | "info"
    notes: str = ""
    uid: Optional[int] = None
    salt: Optional[str] = None
    rounds: Optional[str] = None
    verification_backend: Optional[str] = None
    audit_source: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AuditReport:
    """تقرير تدقيق كامل."""
    tool_name: str = "PassGuard"
    tool_version: str = "2.0.0"
    generated_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    hostname: str = ""
    source_platform: str = ""         # "linux" أو "windows"
    wordlist_path: str = ""
    wordlist_count: int = 0
    accounts_scanned: int = 0
    accounts_weak: int = 0
    accounts_locked: int = 0
    accounts_no_match: int = 0        # لم تُطابق (لا يعني الأمان)
    accounts_not_assessed: int = 0    # خوارزمية غير مدعومة
    accounts_secure: int = 0          # [مُهمل] = accounts_no_match للتوافق
    findings: List[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0
    # بيانات وصفية إضافية (لتقارير Phase 5)
    hash_backend: str = ""            # "passlib" / "crypt" / "none"
    skipped_accounts: int = 0
    error_accounts: int = 0
    metadata: dict = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def compute_summary(self) -> None:
        """إعادة حساب العدّادات الإجمالية من قائمة findings."""
        self.accounts_scanned = len(self.findings)
        self.accounts_weak = sum(1 for f in self.findings if f.status == "weak")
        self.accounts_locked = sum(1 for f in self.findings
                                   if f.status in ("locked", "disabled"))
        # no_match يشمل "secure" المُهمل للتوافق الخلفي
        self.accounts_no_match = sum(1 for f in self.findings
                                     if f.status in ("no_match", "secure"))
        self.accounts_not_assessed = sum(1 for f in self.findings
                                         if f.status == "not_assessed")
        self.accounts_secure = self.accounts_no_match   # compat
        self.skipped_accounts = sum(1 for f in self.findings if f.status == "skipped")
        self.error_accounts = sum(1 for f in self.findings if f.status == "error")

    def to_dict(self) -> dict:
        self.compute_summary()
        return {
            "tool": {"name": self.tool_name, "version": self.tool_version},
            "generated_at": self.generated_at,
            "hostname": self.hostname,
            "source_platform": self.source_platform,
            "wordlist": {"path": self.wordlist_path, "count": self.wordlist_count},
            "hash_backend": self.hash_backend,
            "summary": {
                "accounts_scanned": self.accounts_scanned,
                "accounts_weak": self.accounts_weak,
                "accounts_locked": self.accounts_locked,
                "accounts_no_match": self.accounts_no_match,
                "accounts_not_assessed": self.accounts_not_assessed,
                "accounts_secure": self.accounts_secure,
                "skipped_accounts": self.skipped_accounts,
                "error_accounts": self.error_accounts,
                "duration_seconds": round(self.duration_seconds, 3),
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


# ===========================================================================
# مُصدّرات
# ===========================================================================

def to_json(report: AuditReport, path: str) -> str:
    """كتابة التقرير كـ JSON منسّق."""
    report.compute_summary()
    data = report.to_dict()
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    return path


def to_csv(report: AuditReport, path: str) -> str:
    """كتابة التقرير كـ CSV (UTF-8 with BOM ليتوافق مع Excel)."""
    report.compute_summary()
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "username", "source", "algorithm", "status",
            "matched_password_masked", "hash_preview", "severity", "notes",
            "uid", "salt", "rounds", "verification_backend", "audit_source",
        ])
        for f in report.findings:
            writer.writerow([
                f.username, f.source, f.algorithm, f.status,
                f.matched_password_masked or "",
                f.hash_preview or "",
                f.severity, f.notes,
                f.uid if f.uid is not None else "",
                f.salt or "",
                f.rounds or "",
                f.verification_backend or "",
                f.audit_source or "",
            ])
    return path


def to_html(report: AuditReport, path: str,
            risk_assessment=None, policy_report=None) -> str:
    """كتابة تقرير HTML عربي RTL متجاوب.

    المعاملات الاختيارية (جديدة، للتوافق الخلفي):
        risk_assessment: RiskAssessment لتضمين توزيع المخاطر.
        policy_report:   PolicyReport لتضمين تقييم السياسات.

    التقرير يشمل: ملخّص تنفيذي، نطاق التقييم، المنهجية، النتائج، توزيع
    المخاطر (إن وُفر)، تقييم السياسات (إن وُفر)، توصيات الإصلاح، وحدود التقييم.
    """
    report.compute_summary()
    data = report.to_dict()
    summary = data["summary"]

    # --- ملخّص تنفيذي ---
    if report.accounts_weak > 0:
        exec_summary = (
            f"تمّ اكتشاف <strong>{report.accounts_weak}</strong> حساب بكلمة مرور "
            f"ضعيفة (مطابقة للقائمة) من أصل {report.accounts_scanned} حساب مُفحوص. "
            f"تتطلّب هذه الحسابات إجراءً عاجلاً لإجبار تغيير كلمات المرور.")
    elif report.accounts_scanned == 0:
        exec_summary = "لم تُفحص أيّ حسابات في هذا التدقيق."
    else:
        exec_summary = (
            f"لم تُكتشف كلمات مرور ضعيفة في هذا التدقيق ({report.accounts_scanned} "
            f"حساب). ملاحظة: عدم التطابق لا يعني الأمان — فقط أنّ القائمة "
            f"المُستخدمة لم تكشفها.")

    # --- توزيع المخاطر (إن وُفر) ---
    risk_section = ""
    if risk_assessment is not None:
        dist = risk_assessment.severity_distribution
        risk_section = f"""
    <section class="card">
      <h2>📊 توزيع المخاطر</h2>
      <div class="summary">
        <div class="stat"><div class="num" style="color:var(--danger)">{dist.get('critical',0)}</div><div class="lbl">حرج</div></div>
        <div class="stat"><div class="num" style="color:#f97316">{dist.get('high',0)}</div><div class="lbl">عالي</div></div>
        <div class="stat"><div class="num" style="color:var(--warn)">{dist.get('medium',0)}</div><div class="lbl">متوسط</div></div>
        <div class="stat"><div class="num" style="color:var(--ok)">{dist.get('low',0)}</div><div class="lbl">منخفض</div></div>
      </div>
      <p>{html.escape(risk_assessment.summary)}</p>
    </section>"""

    # --- تقييم السياسات (إن وُفر) ---
    policy_section = ""
    if policy_report is not None:
        pol_rows = []
        for pf in policy_report.findings:
            status_color = {"compliant": "var(--ok)",
                            "non_compliant": "var(--danger)",
                            "warning": "var(--warn)",
                            "not_assessed": "var(--muted)"
                            }.get(pf.status, "var(--muted)")
            pol_rows.append(
                f"""<tr>
                  <td>{html.escape(pf.title)}</td>
                  <td>{html.escape(pf.source)}</td>
                  <td style="color:{status_color}">{html.escape(pf.value)}</td>
                  <td>{html.escape(pf.remediation)}</td>
                </tr>""")
        policy_section = f"""
    <section class="card">
      <h2>📋 تقييم السياسات ({html.escape(policy_report.platform)})</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>السياسة</th><th>المصدر</th><th>القيمة</th><th>الإصلاح</th></tr></thead>
          <tbody>{"".join(pol_rows)}</tbody>
        </table>
      </div>
    </section>"""

    # --- توصيات الإصلاح ---
    recommendations: List[str] = []
    if report.accounts_weak > 0:
        recommendations.append(
            f"أجبر {report.accounts_weak} حساباً على تغيير كلمات المرور فوراً.")
    if report.accounts_not_assessed > 0:
        recommendations.append(
            f"راجع {report.accounts_not_assessed} حساباً بخوارزمية غير مدعومة — "
            f"حدّث backend أو رحّلها لخوارزمية مدعومة.")
    if report.error_accounts > 0:
        recommendations.append(
            f"حقّق في {report.error_accounts} خطأ في المعالجة وأعد الفحص.")
    empty_count = sum(1 for f in report.findings if f.status == "empty")
    if empty_count > 0:
        recommendations.append(
            f"{empty_count} حساب بدون كلمة مرور — اضبط كلمات مرور قوية أو عطّلها.")
    if not recommendations:
        recommendations.append("لا توصيات إصلاح عاجلة — واصل المراقبة الدورية.")
    rec_html = "".join(f"<li>{html.escape(r)}</li>" for r in recommendations)

    # صفوف الجدول
    rows_html = []
    for f in data["findings"]:
        severity_class = {
            "critical": "sev-critical",
            "high": "sev-high",
            "medium": "sev-medium",
            "low": "sev-low",
            "info": "sev-info",
        }.get(f["severity"], "sev-info")
        status_label = STATUS_LABELS_AR.get(f["status"], f["status"])
        rows_html.append(
            f"""<tr class="{severity_class}">
                <td>{html.escape(f['username'])}</td>
                <td>{html.escape(f['source'])}</td>
                <td>{html.escape(f['algorithm'])}</td>
                <td>{status_label}</td>
                <td dir="ltr">{html.escape(f['matched_password_masked'] or '—')}</td>
                <td dir="ltr">{html.escape(f['hash_preview'] or '—')}</td>
                <td>{html.escape(f['notes'] or '')}</td>
              </tr>"""
        )

    html_doc = f"""<!doctype html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تقرير تدقيق كلمات المرور — {html.escape(data['tool']['name'])}</title>
<style>
  :root {{
    --bg: #0f172a; --card: #1e293b; --fg: #e2e8f0; --muted: #94a3b8;
    --accent: #38bdf8; --danger: #f87171; --warn: #fbbf24; --ok: #34d399;
    --border: #334155;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; font-family: "Segoe UI", "Noto Sans", Tahoma, sans-serif;
    background: var(--bg); color: var(--fg); padding: 1rem;
    line-height: 1.6;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  header {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1.25rem 1.5rem; margin-bottom: 1rem;
  }}
  header h1 {{ margin: 0 0 .25rem; color: var(--accent); font-size: 1.4rem; }}
  header .meta {{ color: var(--muted); font-size: .9rem; }}
  .summary {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: .75rem; margin-bottom: 1rem;
  }}
  .stat {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: .85rem 1rem; text-align: center;
  }}
  .stat .num {{ font-size: 1.6rem; font-weight: 700; }}
  .stat .lbl {{ color: var(--muted); font-size: .8rem; }}
  .stat.weak .num {{ color: var(--danger); }}
  .stat.secure .num {{ color: var(--ok); }}
  .stat.no-match .num {{ color: var(--warn); }}
  .stat.not-assessed .num {{ color: var(--warn); }}
  .stat.error .num {{ color: var(--danger); }}
  .stat.locked .num {{ color: var(--muted); }}
  .stat.scanned .num {{ color: var(--accent); }}
  .table-wrap {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; overflow-x: auto;
  }}
  .card {{
    background: var(--card); border: 1px solid var(--border);
    border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 1rem;
  }}
  .card h2 {{ margin: 0 0 .5rem; color: var(--accent); font-size: 1.1rem; }}
  .card ul {{ margin: .25rem 0; padding-right: 1.5rem; }}
  .card li {{ margin: .3rem 0; }}
  table {{ border-collapse: collapse; width: 100%; min-width: 760px; }}
  th, td {{ padding: .7rem .85rem; text-align: right; border-bottom: 1px solid var(--border); }}
  th {{ background: #0f172a; color: var(--accent); font-weight: 600; font-size: .85rem; }}
  tr.sev-critical {{ background: rgba(248,113,113,.08); }}
  tr.sev-high {{ background: rgba(251,146,60,.07); }}
  tr.sev-medium {{ background: rgba(251,191,36,.06); }}
  .badge {{ display:inline-block; padding:.15rem .55rem; border-radius:999px; font-size:.75rem; }}
  footer {{ color: var(--muted); font-size: .8rem; margin-top: 1rem; text-align:center; }}
  @media (max-width: 640px) {{
    header h1 {{ font-size: 1.15rem; }}
    .stat .num {{ font-size: 1.25rem; }}
  }}
</style>
</head>
<body>
  <div class="container">
    <header>
      <h1>🔒 تقرير تدقيق كلمات المرور</h1>
      <div class="meta">
        الأداة: {html.escape(data['tool']['name'])} v{html.escape(data['tool']['version'])} ·
        التاريخ: {html.escape(data['generated_at'])} ·
        المنصة: {html.escape(data['source_platform'] or '—')} ·
        الجهاز: {html.escape(data['hostname'] or '—')} ·
        backend التجزئة: {html.escape(data.get('hash_backend') or '—')}
      </div>
    </header>

    <section class="summary">
      <div class="stat scanned"><div class="num">{summary['accounts_scanned']}</div><div class="lbl">حسابات مُفحوصة</div></div>
      <div class="stat weak"><div class="num">{summary['accounts_weak']}</div><div class="lbl">كلمات ضعيفة (مطابقة)</div></div>
      <div class="stat locked"><div class="num">{summary['accounts_locked']}</div><div class="lbl">مقفلة/معطّلة</div></div>
      <div class="stat no-match"><div class="num">{summary['accounts_no_match']}</div><div class="lbl">لم تُطابق القائمة</div></div>
      <div class="stat not-assessed"><div class="num">{summary['accounts_not_assessed']}</div><div class="lbl">غير مُقيَّمة</div></div>
      <div class="stat error"><div class="num">{summary.get('error_accounts', 0)}</div><div class="lbl">أخطاء معالجة</div></div>
    </section>

    <section class="card">
      <h2>📌 الملخّص التنفيذي</h2>
      <p>{exec_summary}</p>
    </section>

    <section class="card">
      <h2>🔍 نطاق التقييم</h2>
      <ul>
        <li><strong>المنصة:</strong> {html.escape(data['source_platform'] or '—')}</li>
        <li><strong>الجهاز:</strong> {html.escape(data['hostname'] or '—')}</li>
        <li><strong>backend التجزئة:</strong> {html.escape(data.get('hash_backend') or '—')}</li>
        <li><strong>القائمة:</strong> {html.escape(os.path.basename(report.wordlist_path))} ({report.wordlist_count} كلمة)</li>
        <li><strong>الحسابات المُفحوصة:</strong> {report.accounts_scanned}</li>
        <li><strong>الحسابات المستثناة:</strong> {report.skipped_accounts}</li>
        <li><strong>مدّة الفحص:</strong> {report.duration_seconds:.2f} ثانية</li>
      </ul>
    </section>

    <section class="card">
      <h2>🛠️ منهجية التقييم</h2>
      <p>تُفحص تجزئات كلمات المرور ضدّ قائمة كلمات شائعة (wordlist). لكل حساب،
      تُطبَّق خوارزمية التجزئة على كل كلمة في القائمة وتُقارَن النتيجة بالتجزئة
      المخزّنة (مقارنة ثابتة الزمن). التطابق يعني أنّ كلمة المرور هي تلك الكلمة.</p>
      <ul>
        <li>Linux: قراءة /etc/shadow (يتطلب sudo)، التوازي عبر multiprocessing.</li>
        <li>Windows: ملف تجزئات NTLM مُستخرَج (pwdump/secretsdump)، جدول بحث مُسبق الحساب.</li>
        <li>لا تُخزَّن كلمات المرور الأصلية — فقط مُخفّاة (p*******) في التقارير.</li>
      </ul>
    </section>

    {risk_section}
    {policy_section}

    <section class="card">
      <h2>🔧 النتائج التفصيلية</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>المستخدم</th><th>المصدر</th><th>الخوارزمية</th>
              <th>الحالة</th><th>كلمة المرور المطابقة</th>
              <th>معاينة التجزئة</th><th>ملاحظات</th>
            </tr>
          </thead>
          <tbody>
            {"".join(rows_html) if rows_html else '<tr><td colspan="7" style="text-align:center;color:var(--muted)">لا توجد نتائج.</td></tr>'}
          </tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>✅ توصيات الإصلاح</h2>
      <ul>{rec_html}</ul>
    </section>

    <section class="card">
      <h2>⚠️ حدود التقييم</h2>
      <ul>
        <li>عدم تطابق كلمة مرور مع القائمة <strong>لا يعني أنّها آمنة</strong> —
            فقط أنّ هذه القائمة بالذات لم تكشفها.</li>
        <li>جودة الفحص تعتمد على جودة وحجم القائمة المُستخدمة.</li>
        <li>وقت الكسر التقديري يفترض هجوم offline على NTLM — تجزئات Unix
            الحديثة (bcrypt/argon2) أبطأ بملايين المرّات.</li>
        <li>هذا الفحص لا يقيّم عوامل أخرى مثل التصيّد الاجتماعي أو برمجيات
            انتحال كلمات المرور.</li>
      </ul>
    </section>

    <footer>
      <strong>تنبيه:</strong> عدم تطابق كلمة مرور مع القائمة المُستخدمة لا يعني أنّها آمنة —
      فقط أنّ هذه القائمة بالذات لم تكشفها. قد تكون مكشوفة في قوائم أخرى لم تُفحص.<br>
      لا تُخزّن هذه الأداة كلمات المرور الأصلية في تقاريرها. المعروض هنا كلمات مُخفّاة
      جزئياً لأغراض التدقيق الإداري فقط.
    </footer>
  </div>
</body>
</html>
"""
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html_doc)
    return path


__all__ = [
    "Finding", "AuditReport", "to_json", "to_csv", "to_html",
    "RESULT_STATES", "DEFAULT_SEVERITY", "STATUS_LABELS_AR",
]
