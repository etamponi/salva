"""Interfaccia grafica (Tkinter) di salva.

Riusa lo stesso motore della CLI: i consigli (advice) e i controlli read-only
(checks). Non modifica nulla sul sistema, si limita a osservare e suggerire.

Avvio:
    salva-gui            (binario / entry point)
    salva gui            (dalla CLI)
    python3 -m salva gui
"""
from __future__ import annotations

import json
import os
import queue
import sys
import threading

import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog, messagebox, ttk

from . import __version__, advice
from .checks import ALL_CHECKS, Finding, Severity
from .ui import sev_label, sev_symbol

# Colori per gravita' (versione GUI; la CLI usa i codici ANSI di ui.py)
SEV_COLOR = {
    Severity.OK: "#2e7d32",
    Severity.INFO: "#1565c0",
    Severity.LOW: "#00838f",
    Severity.MEDIUM: "#e65100",
    Severity.HIGH: "#c62828",
    Severity.CRITICAL: "#b71c1c",
}

ACCENT = "#0b7285"
MUTED = "#5f6b7a"


class SalvaApp:
    """La finestra principale. Costruibile anche senza avviare il mainloop
    (usato dai test headless)."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: "queue.Queue" = queue.Queue()
        self.finding_map: dict[str, Finding] = {}
        self.results: list[tuple[str, list[Finding]]] = []
        self.counts: dict[Severity, int] = {}
        self.check_vars: dict[str, tk.BooleanVar] = {}

        self._init_style()
        self._build()

    # ---- costruzione UI ---------------------------------------------------

    def _init_style(self) -> None:
        self.style = ttk.Style(self.root)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass
        base = tkfont.nametofont("TkDefaultFont")
        self.font_bold = tkfont.Font(
            family=base.cget("family"), size=base.cget("size"), weight="bold"
        )
        self.font_title = tkfont.Font(
            family=base.cget("family"), size=base.cget("size") + 6, weight="bold"
        )
        self.font_mono = tkfont.nametofont("TkFixedFont")

    def _build(self) -> None:
        # intestazione
        head = ttk.Frame(self.root, padding=(14, 12, 14, 8))
        head.pack(side="top", fill="x")
        ttk.Label(head, text="salva", font=self.font_title,
                  foreground=ACCENT).pack(side="left")
        ttk.Label(head, text="  audit di sicurezza per la tua infrastruttura",
                  foreground=MUTED).pack(side="left", pady=(8, 0))
        ttk.Label(head, text=f"v{__version__}", foreground=MUTED).pack(side="right",
                                                                       pady=(8, 0))

        # barra di stato pinnata in basso PRIMA del notebook: cosi' l'area
        # espandibile non la schiaccia su finestre basse.
        self.status_var = tk.StringVar(value="Pronto. Premi «Esegui audit».")
        bar = ttk.Frame(self.root, padding=(14, 4))
        bar.pack(side="bottom", fill="x")
        ttk.Label(bar, textvariable=self.status_var, foreground=MUTED).pack(side="left")
        ttk.Label(bar, text="read-only · non modifica nulla",
                  foreground=MUTED).pack(side="right")

        nb = ttk.Notebook(self.root)
        self.nb = nb
        nb.pack(side="top", fill="both", expand=True, padx=10, pady=(0, 6))
        self._build_audit_tab(nb)
        self._build_advice_tab(nb)

    def _build_audit_tab(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="  Audit  ")

        # riga controlli + pulsanti
        top = ttk.Frame(tab)
        top.pack(fill="x")

        sel = ttk.LabelFrame(top, text="Controlli", padding=8)
        sel.pack(side="left", fill="x", expand=True)
        for i, cls in enumerate(ALL_CHECKS):
            var = tk.BooleanVar(value=True)
            self.check_vars[cls.id] = var
            ttk.Checkbutton(sel, text=cls.id, variable=var).grid(
                row=i // 4, column=i % 4, sticky="w", padx=6, pady=2)

        btns = ttk.Frame(top, padding=(10, 0, 0, 0))
        btns.pack(side="right", fill="y")
        self.run_btn = ttk.Button(btns, text="▶  Esegui audit", command=self.start_audit)
        self.run_btn.pack(fill="x")
        self.export_btn = ttk.Button(btns, text="Esporta report…",
                                     command=self._export, state="disabled")
        self.export_btn.pack(fill="x", pady=(6, 0))

        self.progress = ttk.Progressbar(tab, mode="indeterminate")
        self.progress.pack(fill="x", pady=(8, 6))

        if not sys.platform.startswith("linux"):
            ttk.Label(
                tab,
                text=("Nota: i controlli di sistema sono pensati per Linux; "
                      "qui vengono eseguiti solo quelli applicabili. "
                      "I consigli valgono su ogni piattaforma."),
                foreground=SEV_COLOR[Severity.MEDIUM], wraplength=880,
            ).pack(fill="x", pady=(0, 6))

        # riepilogo pinnato in basso (prima del pannello espandibile)
        self.summary_var = tk.StringVar(value="")
        self.summary = ttk.Label(tab, textvariable=self.summary_var,
                                 font=self.font_bold)
        self.summary.pack(side="bottom", fill="x", pady=(8, 0))

        # albero risultati + dettaglio (pannello verticale)
        pane = ttk.Panedwindow(tab, orient="vertical")
        pane.pack(fill="both", expand=True)

        tree_frame = ttk.Frame(pane)
        self.tree = ttk.Treeview(tree_frame, columns=("sev",), show="tree headings",
                                 height=12)
        self.tree.heading("#0", text="Controllo / esito")
        self.tree.heading("sev", text="Gravità")
        self.tree.column("#0", width=600, anchor="w")
        self.tree.column("sev", width=120, anchor="w")
        vs = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(f"sev{int(sev)}", foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        pane.add(tree_frame, weight=3)

        detail_frame = ttk.Frame(pane)
        self.detail = tk.Text(detail_frame, height=8, wrap="word", relief="flat",
                              background="#fbfcfd", padx=10, pady=8,
                              state="disabled")
        self.detail.pack(fill="both", expand=True)
        self.detail.tag_configure("h", font=self.font_bold)
        self.detail.tag_configure("h2", font=self.font_bold, foreground=ACCENT,
                                  spacing1=6)
        self.detail.tag_configure("fix", foreground=SEV_COLOR[Severity.OK])
        pane.add(detail_frame, weight=2)

    def _build_advice_tab(self, nb: ttk.Notebook) -> None:
        tab = ttk.Frame(nb, padding=10)
        nb.add(tab, text="  Consigli  ")

        left = ttk.Frame(tab)
        left.pack(side="left", fill="y")
        ttk.Label(left, text="Aree", font=self.font_bold).pack(anchor="w")
        self.topic_list = tk.Listbox(left, width=22, height=18, exportselection=False,
                                     activestyle="none")
        self.topic_list.pack(fill="y", expand=True, pady=(4, 0))
        for t in advice.TOPICS:
            self.topic_list.insert("end", t.title)
        self.topic_list.bind("<<ListboxSelect>>", self._on_topic)

        right = ttk.Frame(tab, padding=(12, 0, 0, 0))
        right.pack(side="left", fill="both", expand=True)
        self.tips = tk.Text(right, wrap="word", relief="flat", background="#fbfcfd",
                            padx=12, pady=10, state="disabled")
        self.tips.pack(fill="both", expand=True)
        self.tips.tag_configure("h", font=self.font_title, foreground=ACCENT,
                                spacing3=8)
        self.tips.tag_configure("bullet", spacing1=4, spacing3=4, lmargin2=18)

        self.topic_list.selection_set(0)
        self._show_topic(0)

    # ---- logica audit -----------------------------------------------------

    def _reset_results(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.finding_map.clear()
        self.results.clear()
        self.counts.clear()
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.config(state="disabled")
        self.summary_var.set("")

    def start_audit(self) -> None:
        """Avvia l'audit in un thread di background (non blocca la UI)."""
        selected = [c for c in ALL_CHECKS if self.check_vars[c.id].get()]
        if not selected:
            messagebox.showinfo("salva", "Seleziona almeno un controllo.")
            return
        self._reset_results()
        self.run_btn.config(state="disabled")
        self.export_btn.config(state="disabled")
        self.progress.start(12)
        self.status_var.set("Analisi in corso…")
        threading.Thread(target=self._worker, args=(selected,), daemon=True).start()
        self.root.after(80, self._poll)

    def _worker(self, checks) -> None:
        for cls in checks:
            chk = cls()
            try:
                if not chk.applicable():
                    continue
                findings = chk.run()
            except Exception as exc:  # un controllo che esplode non ferma l'audit
                findings = [Finding(chk.id, "Errore interno nel controllo",
                                    Severity.INFO, str(exc))]
            self.queue.put(("result", chk.title, findings))
        self.queue.put(("done",))

    def _poll(self) -> None:
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "result":
                    self._add_result(item[1], item[2])
                elif item[0] == "done":
                    self._finish()
                    return
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _add_result(self, title: str, findings: list[Finding]) -> None:
        self.results.append((title, findings))
        worst = max((f.severity for f in findings), default=Severity.OK)
        parent = self.tree.insert("", "end", text=title, open=True,
                                  tags=(f"sev{int(worst)}",))
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            badge = f"{sev_symbol(f.severity)} {sev_label(f.severity)}"
            iid = self.tree.insert(parent, "end", text=f.title, values=(badge,),
                                   tags=(f"sev{int(f.severity)}",))
            self.finding_map[iid] = f
            self.counts[f.severity] = self.counts.get(f.severity, 0) + 1

    def _finish(self) -> None:
        self.progress.stop()
        self.run_btn.config(state="normal")
        self.export_btn.config(state="normal" if self.results else "disabled")
        parts = []
        for sev in sorted(Severity, key=lambda s: -int(s)):
            n = self.counts.get(sev, 0)
            if n:
                parts.append(f"{sev_label(sev)}: {n}")
        worst = max((s for s, n in self.counts.items() if n), default=Severity.OK)
        summary = "Riepilogo — " + ("   ".join(parts) if parts else "nessun esito")
        if worst >= Severity.HIGH:
            summary += "   ·  problemi ad alta priorita' da correggere"
        elif worst >= Severity.MEDIUM:
            summary += "   ·  alcune cose da sistemare"
        elif self.results:
            summary += "   ·  nessun problema serio"
        self.summary_var.set(summary)
        self.summary.configure(foreground=SEV_COLOR[worst])
        self.status_var.set("Audit completato.")

    def run_all_sync(self) -> None:
        """Variante sincrona usata dai test headless (blocca la UI)."""
        selected = [c for c in ALL_CHECKS if self.check_vars[c.id].get()]
        self._reset_results()
        for cls in selected:
            chk = cls()
            try:
                if not chk.applicable():
                    continue
                findings = chk.run()
            except Exception as exc:
                findings = [Finding(chk.id, "Errore interno", Severity.INFO, str(exc))]
            self._add_result(chk.title, findings)
        self._finish()

    # ---- interazioni ------------------------------------------------------

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        self.detail.config(state="normal")
        self.detail.delete("1.0", "end")
        f = self.finding_map.get(sel[0]) if sel else None
        if f is None:
            self.detail.config(state="disabled")
            return
        self.detail.insert("end", f.title + "\n", ("h",))
        self.detail.insert("end", f"Gravità: {sev_label(f.severity)}\n\n")
        if f.detail:
            self.detail.insert("end", f.detail + "\n\n")
        if f.remediation:
            self.detail.insert("end", "Come rimediare\n", ("h2",))
            self.detail.insert("end", "→ " + f.remediation + "\n", ("fix",))
        self.detail.config(state="disabled")

    def _on_topic(self, _event=None) -> None:
        sel = self.topic_list.curselection()
        if sel:
            self._show_topic(sel[0])

    def _show_topic(self, index: int) -> None:
        topic = advice.TOPICS[index]
        self.tips.config(state="normal")
        self.tips.delete("1.0", "end")
        self.tips.insert("end", topic.title + "\n", ("h",))
        for tip in topic.tips:
            self.tips.insert("end", "•  " + tip + "\n", ("bullet",))
        self.tips.config(state="disabled")

    def _export(self) -> None:
        if not self.results:
            messagebox.showinfo("salva", "Esegui prima un audit.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Testo", "*.txt")],
            initialfile="salva-report.json",
        )
        if not path:
            return
        try:
            if path.lower().endswith(".txt"):
                self._write_text(path)
            else:
                self._write_json(path)
        except OSError as exc:
            messagebox.showerror("salva", f"Impossibile salvare:\n{exc}")
            return
        self.status_var.set(f"Report salvato in {path}")

    def _write_json(self, path: str) -> None:
        payload = {
            "version": __version__,
            "results": [
                {"check": title, "findings": [f.as_dict() for f in findings]}
                for title, findings in self.results
            ],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)

    def _write_text(self, path: str) -> None:
        lines = [f"salva {__version__} — report audit", ""]
        for title, findings in self.results:
            lines.append(f"== {title} ==")
            for f in sorted(findings, key=lambda x: -int(x.severity)):
                lines.append(f"  [{sev_label(f.severity)}] {f.title}")
                if f.detail:
                    lines.append(f"      {f.detail}")
                if f.remediation:
                    lines.append(f"      -> {f.remediation}")
            lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    # SALVA_GUI_SELFTEST: apre la finestra, esegue un audit e si chiude da sola.
    # Serve allo smoke test headless (Xvfb) del binario, anche in CI.
    selftest = bool(os.environ.get("SALVA_GUI_SELFTEST"))

    root = tk.Tk()
    root.title(f"salva {__version__} — sicurezza infrastrutture")
    try:
        root.tk.call("tk", "scaling", 1.2)
    except tk.TclError:
        pass
    app = SalvaApp(root)
    root.geometry("960x660")
    root.minsize(780, 540)

    if selftest:
        def _run_and_close():
            app.run_all_sync()
            root.after(500, root.destroy)
        root.after(300, _run_and_close)

    root.mainloop()
    if selftest:
        print("salva GUI selftest OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
