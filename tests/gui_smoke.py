"""Smoke test headless della GUI (richiede un display; usare con xvfb-run).

    xvfb-run -a python3 tests/gui_smoke.py [screenshot_base.png]

Costruisce la finestra, esegue un audit sincrono e verifica che l'albero dei
risultati si popoli e che l'export (JSON/testo) funzioni. Se si passa un
percorso, salva due screenshot del display (scheda Audit e scheda Consigli)
usando ImageMagick 'import'.
"""
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk  # noqa: E402

from salva.gui import SalvaApp  # noqa: E402


def _pump(root, n=5):
    for _ in range(n):
        root.update()


def _shot(path):
    subprocess.run(["import", "-window", "root", path], check=False)


def main() -> int:
    base = sys.argv[1] if len(sys.argv) > 1 else None
    root = tk.Tk()
    root.geometry("980x680")
    app = SalvaApp(root)
    _pump(root)

    app.run_all_sync()
    _pump(root)

    top = app.tree.get_children()
    assert top, "l'albero dei risultati e' vuoto"
    total = len(app.finding_map)
    assert total > 0, "nessun finding prodotto"
    assert app.results, "results vuoto"
    assert sum(app.counts.values()) == total, "conteggi incoerenti"

    # seleziona il primo esito e verifica che il pannello dettaglio si riempia
    first_child = app.tree.get_children(top[0])[0]
    app.tree.selection_set(first_child)
    app._on_select()
    _pump(root, 3)
    detail_txt = app.detail.get("1.0", "end").strip()
    assert detail_txt, "pannello dettaglio vuoto dopo la selezione"

    # export json + testo
    with tempfile.TemporaryDirectory() as d:
        jp, tp = os.path.join(d, "r.json"), os.path.join(d, "r.txt")
        app._write_json(jp)
        app._write_text(tp)
        data = json.load(open(jp, encoding="utf-8"))
        assert data["results"], "export JSON vuoto"
        assert os.path.getsize(tp) > 0, "export testo vuoto"

    if base:
        _shot(base)

    # scheda consigli
    app.nb.select(1)
    app._show_topic(1)
    _pump(root, 3)
    if base:
        root_, ext = os.path.splitext(base)
        _shot(f"{root_}_consigli{ext}")

    counts = ", ".join(f"{s.name}:{n}"
                       for s, n in sorted(app.counts.items(), key=lambda kv: -int(kv[0])))
    root.destroy()
    print(f"GUI SMOKE OK — {len(top)} controlli, {total} esiti  [{counts}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
