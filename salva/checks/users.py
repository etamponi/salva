"""Audit di account, privilegi e password."""
from __future__ import annotations

import os

from .base import Check, Finding, Severity, is_root, read_text


class UsersCheck(Check):
    id = "users"
    title = "Account e privilegi"

    def applicable(self) -> bool:
        # /etc/passwd esiste su Linux e Mac; assente su Windows.
        return os.path.exists("/etc/passwd")

    def run(self) -> list[Finding]:
        out: list[Finding] = []
        passwd = read_text("/etc/passwd")
        if passwd is None:
            return [self.finding("Impossibile leggere /etc/passwd", Severity.INFO)]

        login_shells = {"/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/bash",
                        "/usr/bin/zsh", "/bin/ksh", "/usr/bin/fish"}

        uid0 = []
        interactive = []
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            name, _, uid, _, _, _, shell = parts[:7]
            try:
                uid_n = int(uid)
            except ValueError:
                continue
            if uid_n == 0 and name != "root":
                uid0.append(name)
            if shell in login_shells and uid_n >= 1000:
                interactive.append(name)

        # Account UID 0 diversi da root = backdoor classica
        if uid0:
            out.append(self.finding(
                "Account con privilegi di root (UID 0)",
                Severity.CRITICAL,
                "Oltre a root hanno UID 0: " + ", ".join(uid0)
                + ". Un account UID 0 e' root a tutti gli effetti.",
                "Verifica che siano legittimi; altrimenti rimuovili o assegna un UID normale.",
            ))
        else:
            out.append(self.ok("Nessun UID 0 anomalo", "Solo root ha UID 0."))

        # Password vuote (richiede /etc/shadow leggibile => root)
        shadow = read_text("/etc/shadow")
        if shadow is not None:
            empty = []
            for line in shadow.splitlines():
                p = line.split(":")
                if len(p) >= 2 and p[1] == "":
                    empty.append(p[0])
            if empty:
                out.append(self.finding(
                    "Account con password vuota",
                    Severity.CRITICAL,
                    "Login senza password per: " + ", ".join(empty),
                    "Imposta una password ('passwd <utente>') o blocca l'account "
                    "('passwd -l <utente>').",
                ))
            else:
                out.append(self.ok("Nessuna password vuota",
                                   "Tutti gli account hanno password o sono bloccati."))
        elif not is_root():
            out.append(self.finding(
                "Password non verificabili senza root",
                Severity.INFO,
                "/etc/shadow non leggibile con l'utente corrente.",
                "Riesegui come root per controllare le password vuote.",
            ))

        # Account interattivi (informativo: superficie di accesso)
        if interactive:
            out.append(self.finding(
                f"{len(interactive)} account umani con shell di login",
                Severity.INFO,
                "Account con shell interattiva: " + ", ".join(interactive),
                "Rimuovi/blocca gli account non piu' usati; principio del minimo privilegio.",
            ))

        return out
