"""Verifica che esista un firewall attivo (ufw / nftables / iptables)."""
from __future__ import annotations

from .base import IS_LINUX, Check, Finding, Severity, has_cmd, is_root, run_cmd


class FirewallCheck(Check):
    id = "firewall"
    title = "Firewall / filtraggio del traffico"

    def applicable(self) -> bool:
        # ufw/nftables/iptables sono strumenti Linux (Mac usa pf, Windows il suo).
        return IS_LINUX

    def run(self) -> list[Finding]:
        out: list[Finding] = []

        # ufw
        if has_cmd("ufw"):
            rc, so, _ = run_cmd(["ufw", "status"])
            if rc == 0 and "Status: active" in so:
                return [self.ok("ufw attivo", so.strip().splitlines()[0])]
            if rc == 0 and "Status: inactive" in so:
                out.append(self.finding(
                    "ufw installato ma inattivo",
                    Severity.HIGH,
                    "E' presente ufw ma il firewall non filtra nulla.",
                    "Definisci le regole e attiva: 'ufw default deny incoming', "
                    "'ufw allow OpenSSH', poi 'ufw enable'.",
                ))
                return out

        # nftables
        if has_cmd("nft"):
            rc, so, _ = run_cmd(["nft", "list", "ruleset"])
            if rc == 0 and so.strip():
                if "policy drop" in so or "drop" in so.lower():
                    return [self.ok("nftables con regole attive",
                                    "Ruleset nftables presente.")]
                return [self.finding(
                    "nftables presente ma senza regole di blocco",
                    Severity.MEDIUM,
                    "Ci sono regole nftables ma nessuna policy di drop evidente.",
                    "Verifica che le catene input abbiano 'policy drop' e whitelist esplicite.",
                )]
            if rc != 0 and not is_root():
                out.append(self.finding(
                    "Stato nftables non verificabile",
                    Severity.INFO,
                    "Servono privilegi di root per leggere il ruleset.",
                    "Riesegui come root.",
                ))

        # iptables (legacy)
        if has_cmd("iptables"):
            rc, so, _ = run_cmd(["iptables", "-S"])
            if rc == 0:
                policies = [l for l in so.splitlines() if l.startswith("-P")]
                rules = [l for l in so.splitlines() if l.startswith("-A")]
                drop_input = any("INPUT DROP" in p for p in policies)
                if drop_input or rules:
                    return [self.ok("iptables con regole attive",
                                    f"{len(rules)} regole, policy: {', '.join(policies)}")]
                out.append(self.finding(
                    "iptables senza regole (tutto permesso)",
                    Severity.HIGH,
                    "Le catene sono in policy ACCEPT senza regole: nessun filtraggio.",
                    "Imposta policy di default DROP su INPUT e apri solo i servizi necessari, "
                    "oppure usa ufw/nftables per gestirlo piu' facilmente.",
                ))
                return out

        if not is_root():
            return [self.finding(
                "Firewall non verificabile senza root",
                Severity.INFO,
                "Nessuno stato firewall leggibile con l'utente corrente.",
                "Riesegui come root per verificare ufw/nftables/iptables.",
            )]

        if not out:
            out.append(self.finding(
                "Nessun firewall attivo rilevato",
                Severity.HIGH,
                "Non risultano ufw, nftables o iptables con regole attive.",
                "Installa e configura un firewall (ufw e' il piu' semplice): "
                "'ufw default deny incoming', 'ufw allow OpenSSH', 'ufw enable'.",
            ))
        return out
