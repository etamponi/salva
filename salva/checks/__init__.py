"""Registro dei controlli disponibili."""
from __future__ import annotations

from .base import Check, Finding, Severity
from .firewall import FirewallCheck
from .kernel import KernelCheck
from .permissions import PermissionsCheck
from .services import ServicesCheck
from .ssh import SSHCheck
from .updates import UpdatesCheck
from .users import UsersCheck

# Ordine di esecuzione / visualizzazione
ALL_CHECKS: list[type[Check]] = [
    SSHCheck,
    FirewallCheck,
    UpdatesCheck,
    UsersCheck,
    PermissionsCheck,
    ServicesCheck,
    KernelCheck,
]


def registry() -> dict[str, type[Check]]:
    return {cls.id: cls for cls in ALL_CHECKS}


__all__ = ["Check", "Finding", "Severity", "ALL_CHECKS", "registry"]
