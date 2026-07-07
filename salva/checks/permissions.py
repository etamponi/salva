"""Permessi di file sensibili e ricerca di file world-writable."""
from __future__ import annotations

import os
import stat

from .base import IS_LINUX, Check, Finding, Severity


class PermissionsCheck(Check):
    id = "permissions"
    title = "Permessi dei file sensibili"

    def applicable(self) -> bool:
        # Modello shadow + permessi POSIX su /etc: specifico di Linux.
        return IS_LINUX

    # file: (mode massimo consentito, gravita' se piu' permissivo)
    SENSITIVE = {
        "/etc/shadow": (0o640, Severity.HIGH),
        "/etc/gshadow": (0o640, Severity.HIGH),
        "/etc/passwd": (0o644, Severity.MEDIUM),
        "/etc/group": (0o644, Severity.MEDIUM),
        "/etc/ssh/sshd_config": (0o644, Severity.MEDIUM),
    }

    def run(self) -> list[Finding]:
        out: list[Finding] = []

        for path, (max_mode, sev) in self.SENSITIVE.items():
            try:
                st = os.stat(path)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            mode = stat.S_IMODE(st.st_mode)
            # bit extra rispetto al massimo consentito?
            if mode & ~max_mode:
                out.append(self.finding(
                    f"Permessi troppo aperti su {path}",
                    sev,
                    f"Modo attuale {oct(mode)}, atteso al massimo {oct(max_mode)}.",
                    f"Correggi: 'chmod {oct(max_mode)[2:]} {path}'.",
                ))
            if st.st_mode & stat.S_IWOTH:
                out.append(self.finding(
                    f"{path} scrivibile da tutti",
                    Severity.CRITICAL,
                    "Un file di sistema scrivibile da chiunque e' compromissione immediata.",
                    f"Correggi subito: 'chmod o-w {path}'.",
                ))

        # Chiavi private SSH del sistema: devono essere 600/640
        self._ssh_host_keys(out)

        # Ricerca mirata di file world-writable in directory di sistema
        self._world_writable(out)

        if not out:
            out.append(self.ok("Permessi dei file sensibili corretti",
                               "Nessun problema rilevato su shadow/passwd/ssh."))
        return out

    def _ssh_host_keys(self, out: list[Finding]) -> None:
        keydir = "/etc/ssh"
        try:
            names = os.listdir(keydir)
        except (FileNotFoundError, PermissionError, OSError):
            return
        for name in names:
            if not name.startswith("ssh_host_") or name.endswith(".pub"):
                continue
            path = os.path.join(keydir, name)
            try:
                mode = stat.S_IMODE(os.stat(path).st_mode)
            except OSError:
                continue
            if mode & 0o077:
                out.append(self.finding(
                    f"Chiave host SSH con permessi larghi ({name})",
                    Severity.HIGH,
                    f"{path} ha modo {oct(mode)}; le chiavi private vanno protette.",
                    f"Correggi: 'chmod 600 {path}'.",
                ))

    def _world_writable(self, out: list[Finding]) -> None:
        # Scansione limitata a directory di configurazione (rapida e significativa)
        roots = ["/etc"]
        hits: list[str] = []
        for root in roots:
            for dirpath, dirnames, filenames in os.walk(root):
                # niente symlink loop, niente attraversamenti costosi
                dirnames[:] = [d for d in dirnames
                               if not os.path.islink(os.path.join(dirpath, d))]
                for fn in filenames:
                    fp = os.path.join(dirpath, fn)
                    try:
                        st = os.lstat(fp)
                    except OSError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    if st.st_mode & stat.S_IWOTH and not (st.st_mode & stat.S_ISVTX):
                        hits.append(fp)
                        if len(hits) >= 20:
                            break
                if len(hits) >= 20:
                    break
        if hits:
            shown = ", ".join(hits[:8])
            more = f" (+{len(hits) - 8} altri)" if len(hits) > 8 else ""
            out.append(self.finding(
                f"{len(hits)} file scrivibili da tutti in /etc",
                Severity.HIGH,
                f"Esempi: {shown}{more}",
                "Rimuovi il permesso di scrittura globale: 'chmod o-w <file>'.",
            ))
