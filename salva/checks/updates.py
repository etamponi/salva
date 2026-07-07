"""Stato degli aggiornamenti di sicurezza e patching."""
from __future__ import annotations

import os

from .base import IS_LINUX, Check, Finding, Severity, has_cmd, read_text, run_cmd


class UpdatesCheck(Check):
    id = "updates"
    title = "Aggiornamenti e patching"

    def applicable(self) -> bool:
        return IS_LINUX

    def run(self) -> list[Finding]:
        out: list[Finding] = []

        # Serve un riavvio in sospeso? (kernel/librerie aggiornati)
        if os.path.exists("/var/run/reboot-required"):
            pkgs = read_text("/var/run/reboot-required.pkgs") or ""
            n = len([l for l in pkgs.splitlines() if l.strip()])
            out.append(self.finding(
                "Riavvio richiesto",
                Severity.MEDIUM,
                f"Aggiornamenti applicati richiedono un riavvio"
                + (f" ({n} pacchetti, es. kernel)." if n else "."),
                "Pianifica un riavvio: le patch (specie del kernel) non sono "
                "attive finche' non si riavvia.",
            ))

        if has_cmd("apt-get"):
            out.extend(self._apt())
        elif has_cmd("dnf") or has_cmd("yum"):
            out.extend(self._rpm())
        else:
            out.append(self.finding(
                "Package manager non riconosciuto",
                Severity.INFO,
                "Impossibile stimare gli aggiornamenti in sospeso.",
                "Controlla manualmente gli update di sicurezza della tua distro.",
            ))

        # Aggiornamenti automatici di sicurezza
        out.extend(self._unattended())
        return out

    def _apt(self) -> list[Finding]:
        rc, so, _ = run_cmd(["apt-get", "-s", "upgrade"], timeout=60)
        if rc != 0:
            return [self.finding(
                "Impossibile simulare gli upgrade apt",
                Severity.INFO,
                "apt-get -s upgrade non ha risposto (rete/lock?).",
                "Esegui 'apt update' e 'apt list --upgradable' manualmente.",
            )]
        inst = [l for l in so.splitlines() if l.startswith("Inst ")]
        sec = [l for l in inst if "security" in l.lower()]
        if not inst:
            return [self.ok("Sistema apt aggiornato", "Nessun upgrade in sospeso.")]
        sev = Severity.HIGH if sec else Severity.MEDIUM
        detail = f"{len(inst)} pacchetti aggiornabili"
        if sec:
            detail += f", di cui {len(sec)} di sicurezza"
        return [self.finding(
            "Aggiornamenti in sospeso",
            sev,
            detail + ".",
            "Applica gli aggiornamenti: 'apt update && apt upgrade' "
            "(dopo aver verificato l'impatto in produzione).",
        )]

    def _rpm(self) -> list[Finding]:
        tool = "dnf" if has_cmd("dnf") else "yum"
        rc, so, _ = run_cmd([tool, "-q", "check-update"], timeout=90)
        # dnf/yum: exit 100 = ci sono update, 0 = nessuno
        if rc == 0:
            return [self.ok(f"Sistema {tool} aggiornato", "Nessun update in sospeso.")]
        if rc == 100:
            lines = [l for l in so.splitlines() if l.strip() and not l.startswith(" ")]
            return [self.finding(
                "Aggiornamenti in sospeso",
                Severity.MEDIUM,
                f"~{len(lines)} pacchetti aggiornabili.",
                f"Applica: '{tool} upgrade --security' per le sole patch di sicurezza.",
            )]
        return [self.finding(
            "Stato update non determinabile",
            Severity.INFO,
            f"{tool} check-update ha risposto rc={rc}.",
            "Verifica manualmente gli aggiornamenti disponibili.",
        )]

    def _unattended(self) -> list[Finding]:
        # Debian/Ubuntu: unattended-upgrades
        if os.path.isdir("/etc/apt"):
            cfg = read_text("/etc/apt/apt.conf.d/20auto-upgrades") or ""
            enabled = 'Update-Package-Lists "1"' in cfg or "Unattended-Upgrade \"1\"" in cfg
            if enabled:
                return [self.ok("Aggiornamenti automatici attivi",
                                "unattended-upgrades configurato.")]
            return [self.finding(
                "Aggiornamenti automatici di sicurezza non attivi",
                Severity.MEDIUM,
                "Non risulta configurato unattended-upgrades.",
                "Installa e abilita: 'apt install unattended-upgrades' e "
                "'dpkg-reconfigure -plow unattended-upgrades'.",
            )]
        # RHEL-like: dnf-automatic
        if os.path.exists("/etc/dnf/automatic.conf"):
            cfg = read_text("/etc/dnf/automatic.conf") or ""
            if "apply_updates = yes" in cfg:
                return [self.ok("Aggiornamenti automatici attivi",
                                "dnf-automatic in modalita' apply.")]
            return [self.finding(
                "dnf-automatic presente ma non applica gli update",
                Severity.LOW,
                "apply_updates non e' impostato a yes.",
                "Imposta 'apply_updates = yes' e abilita dnf-automatic.timer.",
            )]
        return []
