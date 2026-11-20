"""
passguard.gui
=============

الواجهة الرسومية الموحّدة لـ PassGuard بثلاثة تبويبات:
  1. 🔑 فاحص كلمات المرور  — تحليل لحظي مع إنتروبيا، وقت كسر، قائمة تحقّق.
  2. 🛡️ تدقيق الحسابات     — تدقيق Linux تلقائياً (/etc/shadow) + Windows
                              (اختيار ملف تجزئات SAM/NTLM).
  3. 🎲 مولّد كلمات المرور  — توليد كلمات قوية آمنة تشفيرياً.

تصميم داكن عصري، عربي RTL، متجاوب.

ملاحظات أمنية:
  - لا تُسجَّل كلمة المرور المدخلة في أي ملف أو سجل.
  - الفحص لحظي بـ debounce لتجنّب إعادة الحساب المستمر.
  - تدقيق Linux يتطلّب صلاحيات root (sudo) لقراءة /etc/shadow.
  - تدقيق Windows يأخذ ملف تجزئات مُستخرَج مسبقاً (لأنّ SAM حيّ مقفل).
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from .password_analyzer import (
    analyze_password,
    LEVEL_COLORS,
    LEVEL_LABELS_AR,
    GUESSABILITY_LABELS_AR,
    GUESSABILITY_COLORS,
    PATTERN_RISK_LABELS_AR,
    PATTERN_RISK_COLORS,
)
from .password_generator import generate_password, generate_passphrase
from .wordlist_loader import load_wordlist_set
from .linux_auditor import audit_linux_shadow
from .windows_auditor import audit_windows_hashes, audit_windows_sam_direct
from .reporter import to_json, to_html, to_csv
from .hash_utils import mask_password


# ===========================================================================
# ألوان وأساسيات التصميم الداكن
# ===========================================================================

COLORS = {
    "bg":         "#0f172a",   # خلفية رئيسية (slate-900)
    "card":       "#1e293b",   # خلفية البطاقات (slate-800)
    "card_alt":   "#172033",   # خلفية بديلة (slate-800 أعمق)
    "fg":         "#e2e8f0",   # نص رئيسي (slate-200)
    "muted":      "#94a3b8",   # نص ثانوي (slate-400)
    "accent":     "#38bdf8",   # لون مميّز (sky-400)
    "accent_alt": "#0ea5e9",   # لون مميّز بديل
    "border":     "#334155",   # حدود (slate-700)
    "success":    "#22c55e",   # نجاح
    "warning":    "#f59e0b",   # تحذير
    "danger":     "#ef4444",   # خطر
    "input_bg":   "#0f172a",   # خلفية حقل الإدخال
}

FONT_FAMILY = "Segoe UI"
MONO_FAMILY = "Consolas"


def _font(size: int, weight: str = "normal") -> tuple:
    """بناء tuple خط."""
    return (FONT_FAMILY, size, weight)


def _mono_font(size: int, weight: str = "normal") -> tuple:
    return (MONO_FAMILY, size, weight)


# ===========================================================================
# التطبيق الرئيسي
# ===========================================================================

class PassGuardApp:
    """النافذة الرئيسية بثلاثة تبويبات."""

    def __init__(self, wordlist_path: Optional[str] = None):
        self.wordlist_path = wordlist_path
        self.wordlist_set: Optional[set] = None
        self._load_wordlist()

        # قائمة آمنة للخيوط لتلقي نتائج التدقيق من worker threads
        self._audit_queue: "queue.Queue" = queue.Queue()

        self.root = tk.Tk()
        self.root.title("PassGuard — أداة تدقيق كلمات المرور")
        self.root.geometry("1080x760")
        self.root.minsize(940, 680)
        self.root.configure(bg=COLORS["bg"])

        # محاولة ضبط أيقونة النافذة (اختياري)
        try:
            self.root.attributes("-toolwindow", False)
        except Exception:
            pass

        self._setup_styles()
        self._build_layout()
        # بدء استطلاع دوري لقائمة التدقيق (آمن للخيوط)
        self._poll_audit_queue()

    # -------------------------------------------------------------------
    # تحميل القائمة
    # -------------------------------------------------------------------
    def _load_wordlist(self) -> None:
        """تحميل ملف القائمة في set للبحث الفوري."""
        if not self.wordlist_path:
            # البحث عن القائمة في مواقع افتراضية
            candidates = [
                os.path.join(os.getcwd(), "wordlists", "wordlist.txt"),
                os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                             "wordlists", "wordlist.txt"),
                os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "wordlists", "wordlist.txt"),
            ]
            for c in candidates:
                if os.path.exists(c):
                    self.wordlist_path = c
                    break
        if self.wordlist_path and os.path.exists(self.wordlist_path):
            try:
                self.wordlist_set = load_wordlist_set(self.wordlist_path,
                                                      case_fold=True)
            except Exception as e:
                print(f"[!] تعذّر تحميل القائمة: {e}", file=sys.stderr)
                self.wordlist_set = None

    # -------------------------------------------------------------------
    # أنماط ttk
    # -------------------------------------------------------------------
    def _setup_styles(self) -> None:
        """ضبط أنماط ttk ليتوافق مع التصميم الداكن."""
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # تبويبات
        style.configure("TNotebook", background=COLORS["bg"], borderwidth=0)
        style.configure("TNotebook.Tab",
                        background=COLORS["card"],
                        foreground=COLORS["muted"],
                        padding=(18, 10),
                        font=_font(11, "bold"),
                        borderwidth=0)
        style.map("TNotebook.Tab",
                  background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "#0f172a")])

        # أزرار
        style.configure("TButton",
                        background=COLORS["card"],
                        foreground=COLORS["fg"],
                        font=_font(10, "bold"),
                        padding=(14, 8),
                        borderwidth=0,
                        relief="flat")
        style.map("TButton",
                  background=[("active", COLORS["accent"]),
                              ("pressed", COLORS["accent_alt"])],
                  foreground=[("active", "#0f172a")])

        style.configure("Accent.TButton",
                        background=COLORS["accent"],
                        foreground="#0f172a",
                        font=_font(11, "bold"),
                        padding=(16, 10))
        style.map("Accent.TButton",
                  background=[("active", COLORS["accent_alt"])],
                  foreground=[("active", "#0f172a")])

        style.configure("Danger.TButton",
                        background=COLORS["danger"],
                        foreground="white",
                        font=_font(10, "bold"),
                        padding=(14, 8))
        style.map("Danger.TButton",
                  background=[("active", "#dc2626")])

        # Checkbutton
        style.configure("TCheckbutton",
                        background=COLORS["card"],
                        foreground=COLORS["fg"],
                        font=_font(10),
                        borderwidth=0)
        style.map("TCheckbutton",
                  background=[("active", COLORS["card"])],
                  foreground=[("active", COLORS["fg"])])

        # Entry
        style.configure("TEntry",
                        fieldbackground=COLORS["input_bg"],
                        foreground=COLORS["fg"],
                        insertcolor=COLORS["fg"],
                        borderwidth=1,
                        relief="solid")
        style.map("TEntry",
                  bordercolor=[("focus", COLORS["accent"])])

        # Treeview (جدول النتائج)
        style.configure("Treeview",
                        background=COLORS["card_alt"],
                        foreground=COLORS["fg"],
                        fieldbackground=COLORS["card_alt"],
                        borderwidth=0,
                        font=_font(10),
                        rowheight=28)
        style.configure("Treeview.Heading",
                        background=COLORS["bg"],
                        foreground=COLORS["accent"],
                        font=_font(10, "bold"),
                        relief="flat")
        style.map("Treeview",
                  background=[("selected", COLORS["accent"])],
                  foreground=[("selected", "#0f172a")])

        # Scrollbar
        style.configure("TScrollbar",
                        background=COLORS["card"],
                        troughcolor=COLORS["bg"],
                        borderwidth=0,
                        arrowcolor=COLORS["muted"])

    # -------------------------------------------------------------------
    # بناء الواجهة
    # -------------------------------------------------------------------
    def _build_layout(self) -> None:
        """بناء البنية الكاملة للواجهة."""
        # ====== الرأس ======
        header = tk.Frame(self.root, bg=COLORS["bg"], height=64)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        title = tk.Label(header, text="🛡️  PassGuard",
                         font=_font(20, "bold"),
                         fg=COLORS["accent"], bg=COLORS["bg"])
        title.pack(side="right", padx=20, pady=10)

        subtitle = tk.Label(header, text="أداة تدقيق وفحص سلامة كلمات المرور",
                            font=_font(11),
                            fg=COLORS["muted"], bg=COLORS["bg"])
        subtitle.pack(side="right", pady=10)

        # مؤشر حالة القائمة
        if self.wordlist_set is not None:
            wl_status = f"📊 القائمة محمّلة: {len(self.wordlist_set):,} كلمة"
            wl_color = COLORS["success"]
        else:
            wl_status = "⚠️ لم تُحمَّل القائمة — بعض الفحوصات معطّلة"
            wl_color = COLORS["warning"]
        wl_label = tk.Label(header, text=wl_status, font=_font(9),
                            fg=wl_color, bg=COLORS["bg"])
        wl_label.pack(side="left", padx=20, pady=10)

        # ====== التبويبات ======
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self._build_checker_tab()
        self._build_audit_tab()
        self._build_generator_tab()

    # ===================================================================
    # التبويب 1: فاحص كلمات المرور
    # ===================================================================
    def _build_checker_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.notebook.add(tab, text="  🔑  فاحص كلمات المرور  ")

        # العنوان
        title_frame = tk.Frame(tab, bg=COLORS["bg"])
        title_frame.pack(fill="x", padx=24, pady=(18, 6))
        tk.Label(title_frame, text="محلّل كلمات المرور",
                 font=_font(16, "bold"),
                 fg=COLORS["fg"], bg=COLORS["bg"]).pack(side="right")
        tk.Label(title_frame,
                 text="🔐 كلمة المرور تُحلَّل محلياً ولا تُرسل لأي خادم",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["bg"]).pack(side="right",
                                                           padx=(10, 0))

        # ====== إطار الإدخال ======
        input_card = tk.Frame(tab, bg=COLORS["card"], highlightbackground=COLORS["border"],
                              highlightthickness=1)
        input_card.pack(fill="x", padx=24, pady=(0, 10))

        tk.Label(input_card, text="أدخل كلمة المرور للفحص:",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(anchor="w",
                                                          padx=16, pady=(12, 4))

        entry_row = tk.Frame(input_card, bg=COLORS["card"])
        entry_row.pack(fill="x", padx=16, pady=(0, 12))

        self.pw_var = tk.StringVar()
        self.pw_entry = tk.Entry(entry_row, textvariable=self.pw_var,
                                 font=_mono_font(14), show="*",
                                 width=32,
                                 fg=COLORS["fg"], bg=COLORS["input_bg"],
                                 insertbackground=COLORS["fg"],
                                 relief="solid", borderwidth=1,
                                 highlightthickness=1,
                                 highlightcolor=COLORS["accent"],
                                 highlightbackground=COLORS["border"])
        self.pw_entry.pack(side="right", fill="x", expand=True,
                          ipady=8, padx=(8, 0))
        self.pw_entry.focus_set()

        # زر الإظهار/الإخفاء
        self.show_var = tk.BooleanVar(value=False)
        show_cb = tk.Checkbutton(entry_row, text="👁 إظهار",
                                 variable=self.show_var,
                                 command=self._toggle_show,
                                 font=_font(10),
                                 fg=COLORS["muted"], bg=COLORS["card"],
                                 selectcolor=COLORS["input_bg"],
                                 activebackground=COLORS["card"],
                                 activeforeground=COLORS["fg"],
                                 borderwidth=0)
        show_cb.pack(side="right", padx=(8, 0))

        # زر التوليد السريع
        gen_btn = ttk.Button(entry_row, text="🎲 توليد",
                             command=self._quick_generate,
                             style="TButton")
        gen_btn.pack(side="right", padx=(8, 0))

        # ====== مقياس القوة ======
        strength_card = tk.Frame(tab, bg=COLORS["card"],
                                 highlightbackground=COLORS["border"],
                                 highlightthickness=1)
        strength_card.pack(fill="x", padx=24, pady=(0, 10))

        self.strength_label = tk.Label(strength_card,
                                       text="القوة: —",
                                       font=_font(12, "bold"),
                                       fg=COLORS["muted"], bg=COLORS["card"])
        self.strength_label.pack(anchor="w", padx=16, pady=(12, 4))

        # شريط القوة (Canvas)
        self.bar_canvas = tk.Canvas(strength_card, height=18,
                                    bg=COLORS["input_bg"],
                                    highlightthickness=0)
        self.bar_canvas.pack(fill="x", padx=16, pady=(0, 12))
        self.bar_rect = self.bar_canvas.create_rectangle(0, 0, 0, 18,
                                                         fill=COLORS["border"],
                                                         width=0)
        # ربط حدث تغيير الحجم لتحديث العرض
        self.bar_canvas.bind("<Configure>",
                             lambda e: self._update_bar_width())

        # ====== شبكة المقاييس (4 خانات) ======
        metrics_card = tk.Frame(tab, bg=COLORS["card"],
                                highlightbackground=COLORS["border"],
                                highlightthickness=1)
        metrics_card.pack(fill="x", padx=24, pady=(0, 10))

        self.metric_vars = {}
        metrics = [
            ("entropy",      "الإنتروبيا (نظرية)",  "—"),
            ("crack",        "وقت الكسر التقديري",  "—"),
            ("guessability", "قابلية التخمين",      "—"),
            ("pattern_risk", "خطر الأنماط",         "—"),
            ("combos",       "التركيبات الممكنة",   "—"),
        ]
        for i, (key, label, default) in enumerate(metrics):
            box = tk.Frame(metrics_card, bg=COLORS["card_alt"],
                           highlightbackground=COLORS["border"],
                           highlightthickness=1)
            box.grid(row=0, column=i, sticky="nsew",
                     padx=(0 if i == 0 else 6, 0), pady=12)
            metrics_card.grid_columnconfigure(i, weight=1, uniform="metric")
            tk.Label(box, text=label, font=_font(9),
                     fg=COLORS["muted"], bg=COLORS["card_alt"]).pack(pady=(8, 0))
            v = tk.Label(box, text=default, font=_font(13, "bold"),
                         fg=COLORS["fg"], bg=COLORS["card_alt"])
            v.pack(pady=(2, 10))
            self.metric_vars[key] = v

        # ====== قائمة التحقّق ======
        checklist_card = tk.Frame(tab, bg=COLORS["card"],
                                  highlightbackground=COLORS["border"],
                                  highlightthickness=1)
        checklist_card.pack(fill="x", padx=24, pady=(0, 10))

        tk.Label(checklist_card, text="✓ قائمة التحقّق الأمنية",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(anchor="w",
                                                          padx=16, pady=(12, 4))

        cl_grid = tk.Frame(checklist_card, bg=COLORS["card"])
        cl_grid.pack(fill="x", padx=16, pady=(0, 12))

        self.checklist_items = [
            ("length_12",     "12+ حرفاً"),
            ("lower",         "أحرف صغيرة (a-z)"),
            ("upper",         "أحرف كبيرة (A-Z)"),
            ("digit",         "أرقام (0-9)"),
            ("symbol",        "رموز (!@#$)"),
            ("not_in_wordlist","ليست في القائمة الشائعة"),
            ("no_repeats",    "لا تكرارات (aaa)"),
            ("no_sequences",  "لا تسلسلات (1234)"),
            ("no_keyboard",   "لا أنماط لوحة مفاتيح"),
            ("no_year",       "لا سنوات (2024)"),
            ("no_patterns",   "لا أنماط ضعيفة مكتشفة"),
        ]
        self.checklist_labels = {}
        for i, (key, label) in enumerate(self.checklist_items):
            row = i // 2
            col = i % 2
            item = tk.Frame(cl_grid, bg=COLORS["card"])
            item.grid(row=row, column=col, sticky="w",
                      padx=(0 if col == 0 else 20, 0),
                      pady=3)
            mark = tk.Label(item, text="○", font=_font(11, "bold"),
                            fg=COLORS["muted"], bg=COLORS["card"], width=2)
            mark.pack(side="right")
            lbl = tk.Label(item, text=label, font=_font(10),
                           fg=COLORS["muted"], bg=COLORS["card"])
            lbl.pack(side="right")
            self.checklist_labels[key] = (mark, lbl)

        # ====== حالة التسريب ======
        self.leak_banner = tk.Label(tab, text="أدخل كلمة مرور للبدء...",
                                    font=_font(11, "bold"),
                                    fg=COLORS["muted"], bg=COLORS["card"],
                                    padx=16, pady=10,
                                    highlightbackground=COLORS["border"],
                                    highlightthickness=1)
        self.leak_banner.pack(fill="x", padx=24, pady=(0, 10))

        # ====== الاقتراحات ======
        sug_card = tk.Frame(tab, bg=COLORS["card"],
                            highlightbackground=COLORS["border"],
                            highlightthickness=1)
        sug_card.pack(fill="both", expand=True, padx=24, pady=(0, 16))

        tk.Label(sug_card, text="💡 اقتراحات التحسين",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(anchor="w",
                                                          padx=16, pady=(12, 4))

        self.sug_text = tk.Text(sug_card, height=4,
                                font=_font(10),
                                fg=COLORS["fg"], bg=COLORS["input_bg"],
                                relief="flat", padx=12, pady=8,
                                highlightthickness=1,
                                highlightbackground=COLORS["border"],
                                highlightcolor=COLORS["accent"],
                                wrap="word")
        self.sug_text.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        # ====== ربط الإدخال بالفحص الفوري ======
        self.pw_var.trace_add("write", self._schedule_check)
        self._after_id: Optional[str] = None
        # الفحص الابتدائي
        self._do_check()

    def _toggle_show(self) -> None:
        self.pw_entry.configure(show="" if self.show_var.get() else "*")

    def _quick_generate(self) -> None:
        """توليد سريع لكلمة مرور قوية ووضعها في الحقل."""
        pw = generate_password(length=16, use_upper=True, use_lower=True,
                               use_digits=True, use_symbols=True,
                               avoid_ambiguous=True)
        self.pw_var.set(pw)
        self.show_var.set(True)
        self._toggle_show()

    def _schedule_check(self, *_args) -> None:
        """جدولة الفحص بعد تأخير قصير (debounce)."""
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
        self._after_id = self.root.after(180, self._do_check)

    def _do_check(self) -> None:
        """تنفيذ الفحص الفعلي وتحديث كل العناصر."""
        pw = self.pw_var.get()
        if not pw:
            self._reset_ui()
            return

        # فحص القائمة (إن وُجدت)
        in_wl = False
        if self.wordlist_set is not None:
            in_wl = pw.casefold() in self.wordlist_set

        analysis = analyze_password(pw, in_wordlist=in_wl)
        self._render_analysis(analysis)

    def _reset_ui(self) -> None:
        """إعادة الواجهة إلى الحالة الابتدائية."""
        self.strength_label.configure(text="القوة: —", fg=COLORS["muted"])
        self.bar_canvas.itemconfig(self.bar_rect, fill=COLORS["border"])
        self.bar_canvas.coords(self.bar_rect, 0, 0, 0, 18)
        for v in self.metric_vars.values():
            v.configure(text="—")
        for mark, lbl in self.checklist_labels.values():
            mark.configure(text="○", fg=COLORS["muted"])
            lbl.configure(fg=COLORS["muted"])
        self.leak_banner.configure(text="أدخل كلمة مرور للبدء...",
                                   fg=COLORS["muted"],
                                   highlightbackground=COLORS["border"])
        self.sug_text.configure(state="normal")
        self.sug_text.delete("1.0", "end")
        self.sug_text.configure(state="disabled")

    def _render_analysis(self, analysis) -> None:
        """عرض نتائج التحليل في الواجهة."""
        level = analysis.level
        color = LEVEL_COLORS.get(level, COLORS["muted"])
        label = LEVEL_LABELS_AR.get(level, "—")

        # القوة
        self.strength_label.configure(
            text=f"القوة: {label}   ({analysis.score}/100)",
            fg=color)

        # شريط القوة
        self.bar_canvas.itemconfig(self.bar_rect, fill=color)
        w = self.bar_canvas.winfo_width() or 600
        self.bar_canvas.coords(self.bar_rect, 0, 0,
                               int(w * analysis.score / 100), 18)

        # المقاييس: الإنتروبيا + وقت الكسر + قابلية التخمين + خطر الأنماط + التركيبات
        self.metric_vars["entropy"].configure(
            text=f"{analysis.entropy_bits} bits")
        self.metric_vars["crack"].configure(text=analysis.crack_time_text)

        # قابلية التخمين (تحل محل hack_prob المُهمَلة)
        guess_label = GUESSABILITY_LABELS_AR.get(analysis.guessability, "—")
        guess_color = GUESSABILITY_COLORS.get(analysis.guessability, COLORS["muted"])
        self.metric_vars["guessability"].configure(
            text=guess_label, fg=guess_color)

        # خطر الأنماط
        risk_label = PATTERN_RISK_LABELS_AR.get(analysis.pattern_risk, "—")
        risk_color = PATTERN_RISK_COLORS.get(analysis.pattern_risk, COLORS["muted"])
        self.metric_vars["pattern_risk"].configure(
            text=risk_label, fg=risk_color)

        # تنسيق عدد التركيبات بصورة مقروءة
        combos = analysis.combinations
        if combos >= 10**15:
            combos_text = f"{combos / 10**15:.1f}×10¹⁵"
        elif combos >= 10**12:
            combos_text = f"{combos / 10**12:.1f}×10¹²"
        elif combos >= 10**9:
            combos_text = f"{combos / 10**9:.1f}×10⁹"
        elif combos >= 10**6:
            combos_text = f"{combos / 10**6:.1f}×10⁶"
        elif combos > 0:
            combos_text = f"{combos:,}"
        else:
            combos_text = "0"
        self.metric_vars["combos"].configure(text=combos_text)

        # قائمة التحقّق
        for key, (mark, lbl) in self.checklist_labels.items():
            ok = analysis.checklist.get(key, False)
            if ok:
                mark.configure(text="✓", fg=COLORS["success"])
                lbl.configure(fg=COLORS["success"])
            else:
                mark.configure(text="✗", fg=COLORS["danger"])
                lbl.configure(fg=COLORS["muted"])

        # حالة التعرّض للقاموس (تحل محل عرض hack_prob)
        if analysis.dictionary_exposure == "exposed":
            self.leak_banner.configure(
                text="⚠️  كلمة المرور مُدرجة في قائمة التسريبات الشائعة! غيّرها فوراً.",
                fg=COLORS["danger"],
                highlightbackground=COLORS["danger"])
        elif analysis.dictionary_exposure == "not_exposed":
            self.leak_banner.configure(
                text="✅  لم تُعثر عليها في قائمة التسريبات الشائعة.",
                fg=COLORS["success"],
                highlightbackground=COLORS["success"])
        else:   # not_checked
            self.leak_banner.configure(
                text="ℹ️  لم يُفحص التعرّض للقاموس — لا يمكن الجزم بأمان كلمة المرور.",
                fg=COLORS["warning"],
                highlightbackground=COLORS["warning"])

        # الاقتراحات + ملاحظات التحليل + مقاومة التخمين
        self.sug_text.configure(state="normal")
        self.sug_text.delete("1.0", "end")
        lines: list = []
        # مقاومة التخمين أولاً (ملخّص تفسيري)
        if analysis.guess_resistance:
            lines.append(f"◉ {analysis.guess_resistance}")
        # ملاحظات التحليل (مثل غياب zxcvbn)
        for note in analysis.analysis_notes:
            lines.append(f"ℹ️ {note}")
        # الاقتراحات
        if analysis.suggestions:
            lines.extend(f"• {s}" for s in analysis.suggestions)
        self.sug_text.insert("1.0", "\n".join(lines))
        self.sug_text.configure(state="disabled")

    def _update_bar_width(self) -> None:
        """تحديث عرض شريط القوة عند تغيير حجم النافذة."""
        pw = self.pw_var.get()
        if not pw:
            return
        in_wl = False
        if self.wordlist_set is not None:
            in_wl = pw.casefold() in self.wordlist_set
        analysis = analyze_password(pw, in_wordlist=in_wl)
        level = analysis.level
        color = LEVEL_COLORS.get(level, COLORS["muted"])
        w = self.bar_canvas.winfo_width()
        if w > 1:
            self.bar_canvas.coords(self.bar_rect, 0, 0,
                                   int(w * analysis.score / 100), 18)
            self.bar_canvas.itemconfig(self.bar_rect, fill=color)

    # ===================================================================
    # التبويب 2: تدقيق الحسابات
    # ===================================================================
    def _build_audit_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.notebook.add(tab, text="  🛡️  تدقيق الحسابات  ")

        # العنوان
        title_frame = tk.Frame(tab, bg=COLORS["bg"])
        title_frame.pack(fill="x", padx=24, pady=(18, 6))
        tk.Label(title_frame, text="تدقيق حسابات النظام",
                 font=_font(16, "bold"),
                 fg=COLORS["fg"], bg=COLORS["bg"]).pack(side="right")
        tk.Label(title_frame,
                 text="🔍 فحص كلمات مرور الحسابات المحلية ضدّ القائمة الشائعة",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["bg"]).pack(side="right",
                                                           padx=(10, 0))

        # ====== قسم Linux ======
        linux_card = tk.Frame(tab, bg=COLORS["card"],
                              highlightbackground=COLORS["border"],
                              highlightthickness=1)
        linux_card.pack(fill="x", padx=24, pady=(0, 12))

        tk.Label(linux_card, text="🐧  تدقيق Linux المحلي",
                 font=_font(13, "bold"),
                 fg=COLORS["accent"], bg=COLORS["card"]).pack(anchor="w",
                                                               padx=16,
                                                               pady=(14, 2))

        tk.Label(linux_card,
                 text="تقرأ الأداة تلقائياً من /etc/shadow و /etc/passwd.\n"
                      "يجب تشغيل الأداة بصلاحيات root (sudo) لقراءة /etc/shadow.",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["card"],
                 justify="right").pack(anchor="w", padx=16, pady=(0, 8))

        # حالة الصلاحية
        self.linux_perm_label = tk.Label(linux_card,
                                         text=self._check_linux_perms(),
                                         font=_font(9, "bold"),
                                         fg=COLORS["warning"],
                                         bg=COLORS["card"])
        self.linux_perm_label.pack(anchor="w", padx=16, pady=(0, 8))

        btn_row1 = tk.Frame(linux_card, bg=COLORS["card"])
        btn_row1.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(btn_row1, text="🔍 بدء تدقيق Linux",
                   command=self._run_linux_audit,
                   style="Accent.TButton").pack(side="right")
        self.linux_progress = tk.Label(btn_row1, text="",
                                       font=_font(9),
                                       fg=COLORS["muted"],
                                       bg=COLORS["card"])
        self.linux_progress.pack(side="right", padx=(10, 0))

        # ====== قسم Windows ======
        win_card = tk.Frame(tab, bg=COLORS["card"],
                            highlightbackground=COLORS["border"],
                            highlightthickness=1)
        win_card.pack(fill="x", padx=24, pady=(0, 12))

        tk.Label(win_card, text="🪟  تدقيق Windows NTLM",
                 font=_font(13, "bold"),
                 fg=COLORS["accent"], bg=COLORS["card"]).pack(anchor="w",
                                                              padx=16,
                                                              pady=(14, 2))

        tk.Label(win_card,
                 text="طريقتان للتدقيق:\n"
                      "① مباشر: زر «قراءة SAM مباشرة» يستخدم RegSaveKeyEx (مكتبة advapi32 القياسية)\n"
                      "    لتصدير خلايا SAM/SYSTEM ثمّ استخراج التجزئات (RC4+DES). يتطلّب Windows + admin.\n"
                      "② من ملف: حدّد ملف تجزئات مُستخرَج مسبقاً (pwdump/secretsdump):\n"
                      "    secretsdump.py -sam SAM -system SYSTEM LOCAL > hashes.txt\n"
                      "الصيغ المدعومة: pwdump, user:NT, LM:NT, NT وحدها.",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["card"],
                 justify="right").pack(anchor="w", padx=16, pady=(0, 8))

        file_row = tk.Frame(win_card, bg=COLORS["card"])
        file_row.pack(fill="x", padx=16, pady=(0, 8))
        self.win_file_var = tk.StringVar(value="")
        self.win_file_entry = tk.Entry(file_row,
                                       textvariable=self.win_file_var,
                                       font=_font(9),
                                       fg=COLORS["fg"],
                                       bg=COLORS["input_bg"],
                                       insertbackground=COLORS["fg"],
                                       relief="solid", borderwidth=1)
        self.win_file_entry.pack(side="right", fill="x", expand=True,
                                 ipady=6, padx=(8, 0))
        ttk.Button(file_row, text="📁 استعراض...",
                   command=self._pick_win_file).pack(side="right")

        btn_row2 = tk.Frame(win_card, bg=COLORS["card"])
        btn_row2.pack(fill="x", padx=16, pady=(0, 14))
        ttk.Button(btn_row2, text="🔍 بدء تدقيق Windows",
                   command=self._run_windows_audit,
                   style="Accent.TButton").pack(side="right")
        ttk.Button(btn_row2, text="🔑 قراءة SAM مباشرة",
                   command=self._run_windows_sam_direct,
                   style="Accent.TButton").pack(side="right", padx=(0, 8))
        self.win_progress = tk.Label(btn_row2, text="",
                                     font=_font(9),
                                     fg=COLORS["muted"],
                                     bg=COLORS["card"])
        self.win_progress.pack(side="right", padx=(10, 0))

        # ====== جدول النتائج ======
        results_card = tk.Frame(tab, bg=COLORS["card"],
                                highlightbackground=COLORS["border"],
                                highlightthickness=1)
        results_card.pack(fill="both", expand=True, padx=24, pady=(0, 8))

        res_header = tk.Frame(results_card, bg=COLORS["card"])
        res_header.pack(fill="x", padx=16, pady=(12, 4))
        tk.Label(res_header, text="📋 نتائج التدقيق",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(side="right")

        # أزرار التصدير
        export_row = tk.Frame(results_card, bg=COLORS["card"])
        export_row.pack(fill="x", padx=16, pady=(0, 4))
        ttk.Button(export_row, text="💾 JSON",
                   command=lambda: self._export("json")).pack(side="right",
                                                               padx=(4, 0))
        ttk.Button(export_row, text="🌐 HTML",
                   command=lambda: self._export("html")).pack(side="right",
                                                               padx=(4, 0))
        ttk.Button(export_row, text="📊 CSV",
                   command=lambda: self._export("csv")).pack(side="right",
                                                              padx=(4, 0))

        # جدول النتائج
        tree_frame = tk.Frame(results_card, bg=COLORS["card"])
        tree_frame.pack(fill="both", expand=True, padx=16, pady=(0, 14))

        cols = ("user", "source", "algo", "status", "matched", "severity")
        self.results_tree = ttk.Treeview(tree_frame, columns=cols,
                                         show="headings", height=8)
        headings = [
            ("user",     "المستخدم",          140),
            ("source",   "المصدر",            100),
            ("algo",     "الخوارزمية",        160),
            ("status",   "الحالة",            110),
            ("matched",  "كلمة المرور المطابقة", 150),
            ("severity", "الخطورة",           90),
        ]
        for col, text, width in headings:
            self.results_tree.heading(col, text=text)
            self.results_tree.column(col, width=width, anchor="center")

        vbar = ttk.Scrollbar(tree_frame, orient="vertical",
                             command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=vbar.set)
        self.results_tree.pack(side="right", fill="both", expand=True)
        vbar.pack(side="right", fill="y")

        # علامات لونية للخطورة
        self.results_tree.tag_configure("critical",
                                        background="#7f1d1d",
                                        foreground="#fecaca")
        self.results_tree.tag_configure("high",
                                        background="#7c2d12",
                                        foreground="#fed7aa")
        self.results_tree.tag_configure("medium",
                                        background="#78350f",
                                        foreground="#fde68a")
        self.results_tree.tag_configure("low",
                                        background="#14532d",
                                        foreground="#bbf7d0")
        self.results_tree.tag_configure("info",
                                        background=COLORS["card_alt"],
                                        foreground=COLORS["muted"])

        # ملخّص سريع
        self.audit_summary_label = tk.Label(results_card, text="",
                                            font=_font(10, "bold"),
                                            fg=COLORS["muted"],
                                            bg=COLORS["card"])
        self.audit_summary_label.pack(anchor="w", padx=16, pady=(0, 12))

        # تقرير حالي محفوظ في الذاكرة
        self.current_report = None

    def _check_linux_perms(self) -> str:
        """فحص صلاحية قراءة /etc/shadow."""
        if os.name != "posix":
            return "ℹ️ هذا النظام ليس POSIX — تدقيق Linux غير متاح."
        try:
            if os.access("/etc/shadow", os.R_OK):
                return "✅ صلاحية قراءة /etc/shadow متاحة."
            else:
                return "⚠️ لا توجد صلاحية قراءة /etc/shadow — شغّل الأداة بـ sudo."
        except Exception:
            return "⚠️ تعذّر التحقق من صلاحية /etc/shadow."

    def _pick_win_file(self) -> None:
        """فتح مربّع اختيار ملف التجزئات."""
        path = filedialog.askopenfilename(
            title="اختر ملف تجزئات NTLM",
            filetypes=[("ملفات نصية", "*.txt"),
                       ("كل الملفات", "*.*")])
        if path:
            self.win_file_var.set(path)

    def _run_linux_audit(self) -> None:
        """تشغيل تدقيق Linux في خيط منفصل (لعدم تجميد الواجهة)."""
        if self.wordlist_set is None:
            messagebox.showerror("خطأ",
                                 "ملف القائمة غير محمّل. ضع wordlists/wordlist.txt.")
            return
        self.linux_progress.configure(text="⏳ جاري التدقيق...",
                                      fg=COLORS["accent"])
        threading.Thread(target=self._linux_audit_thread,
                         daemon=True).start()

    def _linux_audit_thread(self) -> None:
        """خيط تدقيق Linux. يضع النتائج/الأخطاء في قائمة آمنة للخيوط."""
        try:
            report = audit_linux_shadow(
                shadow_path="/etc/shadow",
                passwd_path="/etc/passwd",
                wordlist_path=self.wordlist_path,
                progress_cb=lambda msg, d, t: self._audit_queue.put(
                    ("progress", "linux", msg, d, t)),
            )
            self._audit_queue.put(("done", report))
        except PermissionError as e:
            self._audit_queue.put(("error", "صلاحية غير كافية",
                                   f"{e}\n\nشغّل الأداة بـ sudo."))
        except Exception as e:
            self._audit_queue.put(("error", "خطأ غير متوقّع", str(e)))

    def _run_windows_audit(self) -> None:
        """تشغيل تدقيق Windows."""
        if self.wordlist_set is None:
            messagebox.showerror("خطأ",
                                 "ملف القائمة غير محمّل.")
            return
        path = self.win_file_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("خطأ",
                                 "حدّد ملف تجزئات صحيحاً أولاً.")
            return
        self.win_progress.configure(text="⏳ جاري التدقيق...",
                                    fg=COLORS["accent"])
        threading.Thread(target=self._windows_audit_thread,
                         args=(path,), daemon=True).start()

    def _windows_audit_thread(self, path: str) -> None:
        """خيط تدقيق Windows. يضع النتائج/الأخطاء في قائمة آمنة للخيوط."""
        try:
            report = audit_windows_hashes(
                hash_file_path=path,
                wordlist_path=self.wordlist_path,
                progress_cb=lambda msg, d, t: self._audit_queue.put(
                    ("progress", "windows", msg, d, t)),
            )
            self._audit_queue.put(("done", report))
        except Exception as e:
            self._audit_queue.put(("error", "خطأ غير متوقّع", str(e)))

    def _run_windows_sam_direct(self) -> None:
        """قراءة SAM مباشرة (RegSaveKeyEx) — يتطلّب Windows + admin."""
        if self.wordlist_set is None:
            messagebox.showerror("خطأ",
                                 "ملف القائمة غير محمّل.")
            return
        from .sam_reader import is_windows, is_admin
        if not is_windows():
            messagebox.showerror(
                "غير مدعوم",
                "القراءة المباشرة من SAM تتطلّب Windows.\n"
                "على أنظمة أخرى، صدّر الخلايا أولاً ثمّ استخدم «بدء تدقيق Windows».")
            return
        if not is_admin():
            messagebox.showerror(
                "صلاحية غير كافية",
                "القراءة المباشرة من SAM تتطلّب صلاحيات Administrator.\n"
                "أعد تشغيل الأداة كـ Administrator.")
            return
        if not messagebox.askyesno(
                "تأكيد القراءة المباشرة",
                "سيتم تصدير خليتي SAM وSYSTEM عبر RegSaveKeyEx (مكتبة advapi32)\n"
                "واستخراج تجزئات NTLM منها، ثمّ تدقيقها ضدّ القائمة.\n"
                "هذا الإجراء مصرّح به ويستخدم واجهات Microsoft القياسية.\n\n"
                "هل تريد المتابعة؟"):
            return
        self.win_progress.configure(text="⏳ قراءة SAM مباشرة...",
                                    fg=COLORS["accent"])
        threading.Thread(target=self._windows_sam_direct_thread,
                         daemon=True).start()

    def _windows_sam_direct_thread(self) -> None:
        """خيط القراءة المباشرة من SAM."""
        try:
            report = audit_windows_sam_direct(
                wordlist_path=self.wordlist_path,
                progress_cb=lambda msg, d, t: self._audit_queue.put(
                    ("progress", "windows", msg, d, t)),
            )
            self._audit_queue.put(("done", report))
        except PermissionError as e:
            self._audit_queue.put(("error", "خطأ صلاحية", str(e)))
        except RuntimeError as e:
            self._audit_queue.put(("error", "غير مدعوم", str(e)))
        except Exception as e:
            self._audit_queue.put(("error", "خطأ غير متوقّع", str(e)))

    def _poll_audit_queue(self) -> None:
        """استطلاع دوري لقائمة التدقيق (آمن للخيوط، يُستدعى من الخيط الرئيسي).

        هذه الطريقة تتجنّب استدعاء root.after() من خيط غير رئيسي، وهو ما
        يسبب RuntimeError في tkinter.
        """
        try:
            while True:
                item = self._audit_queue.get_nowait()
                kind = item[0]
                if kind == "progress":
                    _, source, msg, d, t = item
                    if source == "linux":
                        target = self.linux_progress
                    else:
                        target = self.win_progress
                    if t:
                        target.configure(text=f"{msg}  ({d}/{t})",
                                         fg=COLORS["accent"])
                    else:
                        target.configure(text=msg, fg=COLORS["accent"])
                elif kind == "done":
                    report = item[1]
                    self._on_audit_done(report)
                elif kind == "error":
                    _, title, msg = item
                    self._audit_error(title, msg)
        except queue.Empty:
            pass
        # إعادة الجدولة كل 100ms
        self.root.after(100, self._poll_audit_queue)

    def _on_audit_done(self, report) -> None:
        """عرض نتائج التدقيق في الجدول."""
        self.current_report = report
        # مسح الجدول
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        status_ar = {
            "weak":         "🔴 ضعيفة (مطابقة)",
            "no_match":     "🟡 لم تُطابق",
            "secure":       "🟡 لم تُطابق",   # [مُهمل] نفس no_match
            "locked":       "⚪ مقفلة",
            "disabled":     "⚪ معطّلة",
            "empty":        "🟠 فارغة",
            "unknown":      "❔ غير معروفة",
            "error":        "⚠️ خطأ",
            "not_assessed": "⚠️ غير مُقيَّمة",
            "skipped":      "⏭️ مستثناة",
        }
        for f in report.findings:
            self.results_tree.insert(
                "", "end",
                values=(f.username, f.source, f.algorithm,
                        status_ar.get(f.status, f.status),
                        f.matched_password_masked or "—",
                        f.severity),
                tags=(f.severity,))

        report.compute_summary()
        self.audit_summary_label.configure(
            text=f"المجموع: {report.accounts_scanned} | "
                 f"🔴 ضعيفة: {report.accounts_weak} | "
                 f"⚪ مقفلة: {report.accounts_locked} | "
                 f"🟡 لم تُطابق: {report.accounts_no_match} | "
                 f"⚠️ غير مُقيَّمة: {report.accounts_not_assessed} | "
                 f"الزمن: {report.duration_seconds:.2f}s",
            fg=COLORS["fg"])

        self.linux_progress.configure(text="✅ اكتمل.",
                                      fg=COLORS["success"])
        self.win_progress.configure(text="✅ اكتمل.",
                                    fg=COLORS["success"])

        if report.accounts_weak > 0:
            messagebox.showwarning(
                "اكتمل التدقيق",
                f"تمّ اكتشاف {report.accounts_weak} حساب بكلمة مرور ضعيفة!\n"
                f"راجع جدول النتائج وصدّر التقرير.")

    def _audit_error(self, title: str, msg: str) -> None:
        """عرض خطأ التدقيق."""
        self.linux_progress.configure(text="", fg=COLORS["muted"])
        self.win_progress.configure(text="", fg=COLORS["muted"])
        messagebox.showerror(title, msg)

    def _export(self, fmt: str) -> None:
        """تصدير التقرير الحالي."""
        if self.current_report is None:
            messagebox.showinfo("تنبيه", "لا يوجد تقرير لتصديره. شغّل التدقيق أولاً.")
            return
        ext = {"json": ".json", "html": ".html", "csv": ".csv"}[fmt]
        default = f"passguard_report_{int(time.time())}{ext}"
        path = filedialog.asksaveasfilename(
            title="حفظ التقرير",
            defaultextension=ext,
            initialfile=default,
            filetypes=[(f"{fmt.upper()} files", f"*{ext}")])
        if not path:
            return
        try:
            if fmt == "json":
                to_json(self.current_report, path)
            elif fmt == "html":
                to_html(self.current_report, path)
            elif fmt == "csv":
                to_csv(self.current_report, path)
            messagebox.showinfo("تمّ", f"تمّ حفظ التقرير:\n{path}")
        except Exception as e:
            messagebox.showerror("خطأ", f"تعذّر الحفظ: {e}")

    # ===================================================================
    # التبويب 3: مولّد كلمات المرور
    # ===================================================================
    def _build_generator_tab(self) -> None:
        tab = tk.Frame(self.notebook, bg=COLORS["bg"])
        self.notebook.add(tab, text="  🎲  مولّد كلمات المرور  ")

        # العنوان
        title_frame = tk.Frame(tab, bg=COLORS["bg"])
        title_frame.pack(fill="x", padx=24, pady=(18, 6))
        tk.Label(title_frame, text="مولّد كلمات المرور القوية",
                 font=_font(16, "bold"),
                 fg=COLORS["fg"], bg=COLORS["bg"]).pack(side="right")
        tk.Label(title_frame,
                 text="🔐 مولّد آمن تشفيرياً باستخدام secrets",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["bg"]).pack(side="right",
                                                           padx=(10, 0))

        # ====== الكلمة المُولّدة ======
        out_card = tk.Frame(tab, bg=COLORS["card"],
                            highlightbackground=COLORS["border"],
                            highlightthickness=1)
        out_card.pack(fill="x", padx=24, pady=(0, 12))

        tk.Label(out_card, text="الكلمة المُولّدة:",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(anchor="w",
                                                          padx=16, pady=(14, 4))

        out_row = tk.Frame(out_card, bg=COLORS["card"])
        out_row.pack(fill="x", padx=16, pady=(0, 8))
        self.gen_output_var = tk.StringVar(value="")
        self.gen_output_entry = tk.Entry(out_row,
                                         textvariable=self.gen_output_var,
                                         font=_mono_font(15, "bold"),
                                         fg=COLORS["accent"],
                                         bg=COLORS["input_bg"],
                                         insertbackground=COLORS["fg"],
                                         relief="solid", borderwidth=1,
                                         readonlybackground=COLORS["input_bg"],
                                         state="readonly",
                                         justify="center")
        self.gen_output_entry.pack(side="right", fill="x", expand=True,
                                   ipady=10, padx=(8, 0))
        ttk.Button(out_row, text="📋 نسخ",
                   command=self._copy_generated).pack(side="right")
        ttk.Button(out_row, text="✨ استخدم في الفاحص",
                   command=self._use_generated_in_checker).pack(side="right",
                                                                 padx=(0, 4))

        # قوة الكلمة المُولّدة
        self.gen_strength_label = tk.Label(out_card,
                                           text="",
                                           font=_font(10, "bold"),
                                           fg=COLORS["muted"],
                                           bg=COLORS["card"])
        self.gen_strength_label.pack(anchor="w", padx=16, pady=(0, 14))

        # ====== خيارات التوليد ======
        opts_card = tk.Frame(tab, bg=COLORS["card"],
                             highlightbackground=COLORS["border"],
                             highlightthickness=1)
        opts_card.pack(fill="x", padx=24, pady=(0, 12))

        tk.Label(opts_card, text="⚙️ خيارات التوليد",
                 font=_font(11, "bold"),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(anchor="w",
                                                          padx=16, pady=(14, 8))

        # الطول
        len_row = tk.Frame(opts_card, bg=COLORS["card"])
        len_row.pack(fill="x", padx=16, pady=(0, 8))
        tk.Label(len_row, text="الطول:", font=_font(11),
                 fg=COLORS["fg"], bg=COLORS["card"]).pack(side="right",
                                                          padx=(0, 10))
        self.length_var = tk.IntVar(value=16)
        length_spin = tk.Spinbox(len_row, from_=8, to=64,
                                 textvariable=self.length_var,
                                 width=6, font=_font(11, "bold"),
                                 fg=COLORS["fg"], bg=COLORS["input_bg"],
                                 relief="solid", borderwidth=1,
                                 buttonbackground=COLORS["card"],
                                 highlightthickness=0)
        length_spin.pack(side="right")
        # شريط تمرير للطول
        self.length_scale = tk.Scale(len_row, from_=8, to=64,
                                     orient="horizontal",
                                     variable=self.length_var,
                                     length=240,
                                     font=_font(9),
                                     fg=COLORS["muted"], bg=COLORS["card"],
                                     troughcolor=COLORS["input_bg"],
                                     highlightthickness=0,
                                     activebackground=COLORS["accent"],
                                     showvalue=False)
        self.length_scale.pack(side="right", padx=(20, 0))

        # أصناف الأحرف
        cls_row = tk.Frame(opts_card, bg=COLORS["card"])
        cls_row.pack(fill="x", padx=16, pady=(0, 8))

        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)
        self.avoid_ambig_var = tk.BooleanVar(value=True)

        opts = [
            (self.use_upper_var,    "أحرف كبيرة (A-Z)"),
            (self.use_lower_var,    "أحرف صغيرة (a-z)"),
            (self.use_digits_var,   "أرقام (0-9)"),
            (self.use_symbols_var,  "رموز (!@#$)"),
            (self.avoid_ambig_var,  "استبعاد الملتبسة (O/0/l/1)"),
        ]
        for i, (var, label) in enumerate(opts):
            row = i // 3
            col = i % 3
            cb = tk.Checkbutton(cls_row, text=label, variable=var,
                                font=_font(10),
                                fg=COLORS["fg"], bg=COLORS["card"],
                                selectcolor=COLORS["input_bg"],
                                activebackground=COLORS["card"],
                                activeforeground=COLORS["fg"],
                                borderwidth=0, anchor="e")
            cb.grid(row=row, column=col, sticky="w",
                    padx=(0 if col == 0 else 20, 0), pady=3)

        # زر التوليد
        btn_row = tk.Frame(opts_card, bg=COLORS["card"])
        btn_row.pack(fill="x", padx=16, pady=(8, 14))
        ttk.Button(btn_row, text="🎲 توليد كلمة مرور",
                   command=self._generate_password,
                   style="Accent.TButton").pack(side="right")
        ttk.Button(btn_row, text="🎲 توليد عبارة مرور (passphrase)",
                   command=self._generate_passphrase).pack(side="right",
                                                            padx=(0, 8))

        # ملاحظة
        tk.Label(opts_card,
                 text="ملاحظة: استخدم الطول 16+ مع تفعيل كل الأصناف لأقصى قوة.\n"
                      "عبارة المرور (passphrase) أسهل في الحفظ وأعلى إنتروبيا.",
                 font=_font(9),
                 fg=COLORS["muted"], bg=COLORS["card"],
                 justify="right").pack(anchor="w", padx=16, pady=(0, 14))

    def _generate_password(self) -> None:
        """توليد كلمة مرور وعرضها."""
        try:
            pw = generate_password(
                length=self.length_var.get(),
                use_upper=self.use_upper_var.get(),
                use_lower=self.use_lower_var.get(),
                use_digits=self.use_digits_var.get(),
                use_symbols=self.use_symbols_var.get(),
                avoid_ambiguous=self.avoid_ambig_var.get(),
            )
        except ValueError as e:
            messagebox.showerror("خطأ", str(e))
            return
        self.gen_output_var.set(pw)
        # تحديث قوة الكلمة المُولّدة
        in_wl = False
        if self.wordlist_set is not None:
            in_wl = pw.casefold() in self.wordlist_set
        analysis = analyze_password(pw, in_wordlist=in_wl)
        level = analysis.level
        color = LEVEL_COLORS.get(level, COLORS["muted"])
        label = LEVEL_LABELS_AR.get(level, "—")
        guess_label = GUESSABILITY_LABELS_AR.get(analysis.guessability, "—")
        self.gen_strength_label.configure(
            text=f"القوة: {label} ({analysis.score}/100) | "
                 f"قابلية التخمين: {guess_label} | "
                 f"الإنتروبيا: {analysis.entropy_bits} bits | "
                 f"وقت الكسر: {analysis.crack_time_text}",
            fg=color)

    def _generate_passphrase(self) -> None:
        """توليد عبارة مرور."""
        pw = generate_passphrase(num_words=4, separator="-")
        self.gen_output_var.set(pw)
        in_wl = False
        if self.wordlist_set is not None:
            in_wl = pw.casefold() in self.wordlist_set
        analysis = analyze_password(pw, in_wordlist=in_wl)
        level = analysis.level
        color = LEVEL_COLORS.get(level, COLORS["muted"])
        label = LEVEL_LABELS_AR.get(level, "—")
        guess_label = GUESSABILITY_LABELS_AR.get(analysis.guessability, "—")
        self.gen_strength_label.configure(
            text=f"القوة: {label} ({analysis.score}/100) | "
                 f"قابلية التخمين: {guess_label} | "
                 f"الإنتروبيا: {analysis.entropy_bits} bits | "
                 f"وقت الكسر: {analysis.crack_time_text}",
            fg=color)

    def _copy_generated(self) -> None:
        """نسخ الكلمة المُولّدة إلى الحافظة."""
        pw = self.gen_output_var.get()
        if not pw:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(pw)
        self.gen_strength_label.configure(
            text="✅ تمّ نسخ الكلمة إلى الحافظة.",
            fg=COLORS["success"])

    def _use_generated_in_checker(self) -> None:
        """أخذ الكلمة المُولّدة إلى تبويب الفاحص."""
        pw = self.gen_output_var.get()
        if not pw:
            return
        self.pw_var.set(pw)
        self.show_var.set(True)
        self._toggle_show()
        self.notebook.select(0)   # التبويب الأول

    # ===================================================================
    # تشغيل
    # ===================================================================
    def run(self) -> None:
        self.root.mainloop()


def launch_gui(wordlist_path: Optional[str] = None) -> None:
    """نقطة دخول لإطلاق الواجهة."""
    app = PassGuardApp(wordlist_path=wordlist_path)
    app.run()


if __name__ == "__main__":
    launch_gui()
