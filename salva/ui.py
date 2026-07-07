"""Formattazione del terminale: colori, simboli, a capo.

I colori si disattivano da soli se l'output non e' un terminale o se e'
impostata la variabile d'ambiente NO_COLOR (https://no-color.org).
"""
from __future__ import annotations

import os
import shutil
import sys
import textwrap

from .checks.base import Severity


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        # Prova ad abilitare le sequenze ANSI sulla console di Windows 10+.
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            # -11 = STD_OUTPUT_HANDLE, 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
        except Exception:
            return False
    return True


_ENABLED = _supports_color()

_CODES = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
    "red_bold": "\033[1;31m",
}


def c(text: str, *styles: str) -> str:
    if not _ENABLED or not styles:
        return text
    prefix = "".join(_CODES.get(s, "") for s in styles)
    return f"{prefix}{text}{_CODES['reset']}"


# Aspetto per livello di gravita': (colore, simbolo, etichetta)
_SEV_STYLE = {
    Severity.OK:       ("green",    "✔", "OK"),
    Severity.INFO:     ("blue",     "•", "INFO"),
    Severity.LOW:      ("cyan",     "▲", "BASSA"),
    Severity.MEDIUM:   ("yellow",   "▲", "MEDIA"),
    Severity.HIGH:     ("red",      "✖", "ALTA"),
    Severity.CRITICAL: ("red_bold", "✖", "CRITICA"),
}


def sev_color(sev: Severity) -> str:
    return _SEV_STYLE[sev][0]


def sev_symbol(sev: Severity) -> str:
    return _SEV_STYLE[sev][1]


def sev_label(sev: Severity) -> str:
    return _SEV_STYLE[sev][2]


def sev_badge(sev: Severity) -> str:
    color = sev_color(sev)
    return c(f"{sev_symbol(sev)} {sev_label(sev):<7}", color, "bold")


def width() -> int:
    return min(shutil.get_terminal_size((80, 24)).columns, 100)


def wrap(text: str, indent: str = "") -> str:
    out = []
    for para in text.split("\n"):
        if not para.strip():
            out.append("")
            continue
        out.append(
            textwrap.fill(
                para,
                width=width(),
                initial_indent=indent,
                subsequent_indent=indent,
            )
        )
    return "\n".join(out)


def rule(char: str = "─") -> str:
    return c(char * width(), "dim")


def header(title: str, subtitle: str = "") -> str:
    line = c(f"  {title}", "bold", "cyan")
    if subtitle:
        line += "  " + c(subtitle, "dim")
    return f"\n{line}\n{rule()}"


def banner() -> str:
    art = c("salva", "bold", "cyan")
    tag = c("audit di sicurezza per infrastrutture Linux", "dim")
    return f"\n  {art}  —  {tag}"
