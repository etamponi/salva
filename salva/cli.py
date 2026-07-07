"""Interfaccia a riga di comando di salva."""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__, advice, ui
from .checks import ALL_CHECKS, Finding, Severity, registry


def _print_advice(args) -> int:
    print(ui.banner())
    topics = advice.TOPICS
    if args.topic:
        t = advice.by_key(args.topic)
        if t is None:
            keys = ", ".join(x.key for x in advice.TOPICS)
            print(ui.c(f"\n  Area '{args.topic}' non trovata. Disponibili: {keys}\n",
                       "yellow"))
            return 2
        topics = [t]

    for t in topics:
        print(ui.header(t.title, f"salva advice {t.key}"))
        for tip in t.tips:
            bullet = ui.c("  ●", "cyan")
            print(f"{bullet} {ui.wrap(tip, '    ')[4:]}")
    print()
    if not args.topic:
        hint = ("Approfondisci un'area con  " + ui.c("salva advice <area>", "bold")
                + "  e verifica il sistema con  " + ui.c("salva check", "bold") + ".")
        print(ui.wrap(hint, "  "))
        print()
    return 0


def _selected_checks(only: str | None):
    reg = registry()
    if not only:
        return list(ALL_CHECKS)
    chosen = []
    for name in only.split(","):
        name = name.strip()
        if name in reg:
            chosen.append(reg[name])
        else:
            print(ui.c(f"Controllo sconosciuto: {name} "
                       f"(disponibili: {', '.join(reg)})", "yellow"),
                  file=sys.stderr)
    return chosen


def _run_checks(checks):
    results: list[tuple[str, list[Finding]]] = []
    for cls in checks:
        check = cls()
        try:
            if not check.applicable():
                continue
            findings = check.run()
        except Exception as exc:  # un controllo che esplode non deve fermare l'audit
            findings = [Finding(check.id, f"Errore interno nel controllo",
                                Severity.INFO, str(exc))]
        results.append((check.title, findings))
    return results


def _print_report(results) -> None:
    print(ui.banner())
    if not sys.platform.startswith("linux"):
        note = ("Nota: i controlli di sistema di salva sono pensati per Linux; "
                "qui eseguo solo quelli applicabili. I consigli di 'salva advice' "
                "valgono su ogni piattaforma.")
        print()
        print(ui.wrap(ui.c(note, "yellow"), "  "))
    for title, findings in results:
        print(ui.header(title))
        for f in sorted(findings, key=lambda x: -int(x.severity)):
            badge = ui.sev_badge(f.severity)
            print(f"  {badge}  {ui.c(f.title, 'bold')}")
            if f.detail:
                print(ui.wrap(f.detail, "             "))
            if f.remediation:
                fix = ui.c("→ ", "green") + f.remediation
                print(ui.wrap(fix, "             "))
    print()


def _summary(results) -> tuple[dict, int]:
    counts = {s: 0 for s in Severity}
    for _, findings in results:
        for f in findings:
            counts[f.severity] += 1

    print(ui.rule("═"))
    parts = []
    for sev in sorted(Severity, key=lambda s: -int(s)):
        n = counts[sev]
        if n:
            parts.append(ui.c(f"{ui.sev_label(sev)}: {n}", ui.sev_color(sev), "bold"))
    line = "  Riepilogo — " + ("   ".join(parts) if parts else "nessun esito")
    print(line)

    worst = max((s for s in Severity if counts[s]), default=Severity.OK)
    if worst >= Severity.HIGH:
        verdict = ui.c("  Ci sono problemi ad alta priorita' da correggere.", "red", "bold")
    elif worst >= Severity.MEDIUM:
        verdict = ui.c("  Alcune cose da sistemare, niente di critico.", "yellow")
    else:
        verdict = ui.c("  Nessun problema serio rilevato. Ottimo lavoro.", "green")
    print(verdict)
    print()

    # exit code: 2 se HIGH/CRITICAL, 1 se MEDIUM/LOW, 0 altrimenti (utile in cron/CI)
    if worst >= Severity.HIGH:
        code = 2
    elif worst >= Severity.LOW:
        code = 1
    else:
        code = 0
    return counts, code


def _check(args) -> int:
    checks = _selected_checks(args.only)
    if not checks:
        return 2
    results = _run_checks(checks)

    if args.json:
        payload = {
            "version": __version__,
            "results": [
                {"check": title, "findings": [f.as_dict() for f in findings]}
                for title, findings in results
            ],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        worst = max((f.severity for _, fs in results for f in fs), default=Severity.OK)
        return 2 if worst >= Severity.HIGH else (1 if worst >= Severity.LOW else 0)

    _print_report(results)
    _, code = _summary(results)
    return code


def _list_checks(_args) -> int:
    print(ui.banner())
    print(ui.header("Controlli disponibili"))
    for cls in ALL_CHECKS:
        print(f"  {ui.c(cls.id, 'bold', 'cyan'):<24} {cls.title}")
    print("\n  Esegui un sottoinsieme con  "
          + ui.c("salva check --only ssh,firewall", "bold") + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="salva",
        description="Assistente per la messa in sicurezza di infrastrutture Linux.",
    )
    p.add_argument("--version", action="version", version=f"salva {__version__}")
    sub = p.add_subparsers(dest="command")

    pa = sub.add_parser("advice", help="mostra consigli di best practice")
    pa.add_argument("topic", nargs="?", help="area specifica (es. accessi, rete, backup)")
    pa.set_defaults(func=_print_advice)

    pc = sub.add_parser("check", help="esegue l'audit read-only del sistema")
    pc.add_argument("--only", help="controlli da eseguire, separati da virgola")
    pc.add_argument("--json", action="store_true", help="output in formato JSON")
    pc.set_defaults(func=_check)

    pl = sub.add_parser("list-checks", help="elenca i controlli disponibili")
    pl.set_defaults(func=_list_checks)

    pg = sub.add_parser("gui", help="apre l'interfaccia grafica")
    pg.set_defaults(func=_gui)

    return p


def _gui(_args) -> int:
    # import ritardato: tkinter serve solo alla GUI, non alla CLI.
    try:
        from .gui import main as gui_main
    except Exception as exc:  # es. Tk non disponibile
        print(ui.c(f"Impossibile avviare la GUI: {exc}", "red"), file=sys.stderr)
        print("Su Linux potrebbe mancare il pacchetto Tk: prova "
              "'sudo apt install python3-tk'.", file=sys.stderr)
        return 1
    return gui_main([])


def _default(_args) -> int:
    print(ui.banner())
    print(ui.header("Da dove partire"))
    lead = ("Sono salva: ti aiuto a mettere in sicurezza i tuoi server Linux. "
            "Ecco tre primi consigli, poi lascio decidere a te.")
    print(ui.wrap(lead, "  "))
    print()
    starters = [
        "Disabilita il login di root via SSH e passa all'autenticazione a chiave.",
        "Alza un firewall in default-deny e apri solo le porte che ti servono.",
        "Abilita gli aggiornamenti automatici di sicurezza e pianifica i riavvii.",
    ]
    for tip in starters:
        print(f"  {ui.c('●', 'cyan')} {ui.wrap(tip, '    ')[4:]}")
    print()
    cmds = [
        (ui.c("salva advice", "bold"), "tutti i consigli, per area"),
        (ui.c("salva check", "bold"), "audit read-only di questa macchina"),
        (ui.c("salva list-checks", "bold"), "elenco dei controlli disponibili"),
    ]
    print(ui.header("Comandi"))
    for cmd, desc in cmds:
        print(f"  {cmd:<28} {ui.c(desc, 'dim')}")
    print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        return _default(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
