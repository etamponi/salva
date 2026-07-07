"""Audit della configurazione del server SSH (/etc/ssh/sshd_config)."""
from __future__ import annotations

import glob
import os

from .base import Check, Finding, Severity, read_text


def _parse_sshd_config() -> dict[str, str]:
    """Restituisce le direttive effettive (prima occorrenza vince, come OpenSSH).

    Segue in modo semplice le direttive Include. Ignora i blocchi Match:
    per l'audit ci basta la configurazione globale.
    """
    values: dict[str, str] = {}
    seen_files: set[str] = set()

    def load(path: str) -> None:
        if path in seen_files:
            return
        seen_files.add(path)
        text = read_text(path)
        if text is None:
            return
        in_match = False
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            key = parts[0].lower()
            val = parts[1].strip() if len(parts) > 1 else ""
            if key == "match":
                in_match = val.lower() != "all"
                continue
            if in_match:
                continue
            if key == "include":
                for pattern in val.split():
                    if not os.path.isabs(pattern):
                        pattern = os.path.join("/etc/ssh", pattern)
                    for inc in sorted(glob.glob(pattern)):
                        load(inc)
                continue
            values.setdefault(key, val)

    load("/etc/ssh/sshd_config")
    return values


class SSHCheck(Check):
    id = "ssh"
    title = "Hardening del server SSH"

    def applicable(self) -> bool:
        return os.path.exists("/etc/ssh/sshd_config")

    def run(self) -> list[Finding]:
        cfg = _parse_sshd_config()
        if not cfg:
            return [
                self.finding(
                    "sshd_config non leggibile",
                    Severity.INFO,
                    "Impossibile leggere /etc/ssh/sshd_config (permessi?).",
                    "Riesegui come root per un audit SSH completo.",
                )
            ]

        out: list[Finding] = []

        # PermitRootLogin: default moderno = prohibit-password
        root_login = cfg.get("permitrootlogin", "prohibit-password").lower()
        if root_login == "yes":
            out.append(self.finding(
                "Login di root via SSH abilitato",
                Severity.HIGH,
                "PermitRootLogin yes: root e' raggiungibile direttamente, "
                "obiettivo primario per attacchi a forza bruta.",
                "Imposta 'PermitRootLogin no' (o 'prohibit-password' se serve "
                "l'accesso root solo a chiave) e usa un utente + sudo.",
            ))
        else:
            out.append(self.ok(
                f"PermitRootLogin = {root_login}",
                "Login diretto di root con password non consentito.",
            ))

        # PasswordAuthentication: default = yes
        pw_auth = cfg.get("passwordauthentication", "yes").lower()
        if pw_auth == "yes":
            out.append(self.finding(
                "Autenticazione con password abilitata",
                Severity.MEDIUM,
                "PasswordAuthentication yes espone il server ad attacchi a "
                "dizionario/forza bruta.",
                "Passa alle chiavi: distribuisci le chiavi pubbliche, poi "
                "imposta 'PasswordAuthentication no' e 'KbdInteractiveAuthentication no'.",
            ))
        else:
            out.append(self.ok(
                "Autenticazione a sola chiave",
                "PasswordAuthentication no.",
            ))

        # PermitEmptyPasswords: default = no
        if cfg.get("permitemptypasswords", "no").lower() == "yes":
            out.append(self.finding(
                "Password vuote ammesse",
                Severity.CRITICAL,
                "PermitEmptyPasswords yes consente il login ad account senza password.",
                "Imposta 'PermitEmptyPasswords no'.",
            ))

        # Protocol 1 (obsoleto e insicuro)
        if cfg.get("protocol", "2") not in ("2", ""):
            out.append(self.finding(
                "Protocollo SSH obsoleto configurato",
                Severity.HIGH,
                f"Protocol = {cfg.get('protocol')}: SSHv1 e' crittograficamente rotto.",
                "Rimuovi la direttiva Protocol o imposta 'Protocol 2'.",
            ))

        # X11Forwarding
        if cfg.get("x11forwarding", "no").lower() == "yes":
            out.append(self.finding(
                "X11Forwarding abilitato",
                Severity.LOW,
                "L'inoltro X11 amplia la superficie d'attacco; utile solo se serve davvero.",
                "Imposta 'X11Forwarding no' se non usi applicazioni grafiche remote.",
            ))

        # MaxAuthTries: default = 6
        try:
            tries = int(cfg.get("maxauthtries", "6"))
            if tries > 4:
                out.append(self.finding(
                    f"MaxAuthTries alto ({tries})",
                    Severity.LOW,
                    "Piu' tentativi per connessione facilitano il brute force.",
                    "Imposta 'MaxAuthTries 3'.",
                ))
        except ValueError:
            pass

        # LoginGraceTime: default = 120
        grace_raw = cfg.get("logingracetime", "120")
        try:
            if int(grace_raw.rstrip("smh")) > 60:
                out.append(self.finding(
                    f"LoginGraceTime lungo ({grace_raw})",
                    Severity.LOW,
                    "Una finestra di login ampia tiene aperte connessioni non autenticate.",
                    "Imposta 'LoginGraceTime 30'.",
                ))
        except ValueError:
            pass

        # Porta di ascolto (informativo)
        port = cfg.get("port", "22")
        out.append(self.finding(
            f"SSH in ascolto sulla porta {port}",
            Severity.INFO,
            "Cambiare porta non e' sicurezza vera, ma riduce il rumore dei bot.",
            "" if port != "22" else
            "Facoltativo: sposta su una porta non standard per ridurre il rumore nei log.",
        ))

        return out
