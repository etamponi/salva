"""Tipi di base condivisi da tutti i controlli."""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from enum import IntEnum

# Molti controlli leggono file/interfacce specifici di Linux (/proc, /etc/shadow,
# apt, ...). Su Windows/Mac quei controlli si dichiarano non applicabili.
IS_LINUX = sys.platform.startswith("linux")


class Severity(IntEnum):
    OK = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class Finding:
    """Un singolo esito prodotto da un controllo."""

    check_id: str
    title: str
    severity: Severity
    detail: str = ""
    remediation: str = ""

    def as_dict(self) -> dict:
        return {
            "check": self.check_id,
            "title": self.title,
            "severity": self.severity.name,
            "detail": self.detail,
            "remediation": self.remediation,
        }


class Check:
    """Classe base di un controllo. Le sottoclassi implementano ``run``."""

    id: str = "base"
    title: str = "Controllo base"

    def applicable(self) -> bool:
        """False per saltare il controllo su piattaforme non pertinenti."""
        return True

    def run(self) -> list[Finding]:
        raise NotImplementedError

    # ---- utility condivise -------------------------------------------------

    def ok(self, title: str, detail: str = "") -> Finding:
        return Finding(self.id, title, Severity.OK, detail)

    def finding(
        self,
        title: str,
        severity: Severity,
        detail: str = "",
        remediation: str = "",
    ) -> Finding:
        return Finding(self.id, title, severity, detail, remediation)


# --- helper di sistema, riusati dai vari controlli -------------------------

def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def read_text(path: str) -> str | None:
    """Legge un file di testo; None se assente o non leggibile."""
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        return None


def run_cmd(args: list[str], timeout: int = 15) -> tuple[int, str, str]:
    """Esegue un comando esterno. Ritorna (returncode, stdout, stderr).

    returncode 127 se l'eseguibile non esiste, 124 su timeout.
    """
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "eseguibile non trovato"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


def has_cmd(name: str) -> bool:
    from shutil import which

    return which(name) is not None
