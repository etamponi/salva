"""Parametri di hardening del kernel (sysctl di rete e memoria)."""
from __future__ import annotations

import os

from .base import Check, Finding, Severity, read_text


class KernelCheck(Check):
    id = "kernel"
    title = "Hardening del kernel (sysctl)"

    def applicable(self) -> bool:
        return os.path.isdir("/proc/sys")

    # parametro -> (valori accettati, gravita', descrizione)
    # Il primo valore della tupla e' quello "preferito" usato nel rimedio.
    PARAMS = {
        "net.ipv4.tcp_syncookies": (("1",), Severity.MEDIUM,
            "protegge dai SYN flood"),
        "net.ipv4.conf.all.rp_filter": (("1", "2"), Severity.LOW,
            "reverse path filtering, anti IP spoofing (1=strict, 2=loose)"),
        "net.ipv4.conf.all.accept_redirects": (("0",), Severity.LOW,
            "ignora gli ICMP redirect (MITM)"),
        "net.ipv4.conf.all.send_redirects": (("0",), Severity.LOW,
            "non inviare ICMP redirect"),
        "net.ipv4.conf.all.accept_source_route": (("0",), Severity.LOW,
            "rifiuta il source routing"),
        "net.ipv4.icmp_echo_ignore_broadcasts": (("1",), Severity.LOW,
            "evita l'amplificazione smurf"),
        "kernel.randomize_va_space": (("2",), Severity.MEDIUM,
            "ASLR completo contro l'exploit di memoria"),
    }

    def _sysctl(self, key: str) -> str | None:
        path = "/proc/sys/" + key.replace(".", "/")
        text = read_text(path)
        if text is None:
            return None
        return text.split()[0] if text.split() else None

    def run(self) -> list[Finding]:
        out: list[Finding] = []
        problems = 0

        for key, (accepted, sev, desc) in self.PARAMS.items():
            cur = self._sysctl(key)
            if cur is None:
                continue
            if cur not in accepted:
                problems += 1
                preferred = accepted[0]
                out.append(self.finding(
                    f"{key} = {cur} (atteso {'/'.join(accepted)})",
                    sev,
                    f"{desc.capitalize()}.",
                    f"Imposta '{key} = {preferred}' in /etc/sysctl.d/99-hardening.conf "
                    "e applica con 'sysctl --system'.",
                ))

        # ip_forward acceso su un host che non e' un router = spesso indesiderato
        fwd = self._sysctl("net.ipv4.ip_forward")
        if fwd == "1":
            out.append(self.finding(
                "IP forwarding attivo",
                Severity.INFO,
                "net.ipv4.ip_forward = 1: normale su router/gateway/host container, "
                "sospetto su un server applicativo.",
                "Se la macchina non instrada traffico, imposta "
                "'net.ipv4.ip_forward = 0'.",
            ))

        if problems == 0:
            out.insert(0, self.ok("Parametri sysctl di rete conformi",
                                  "syncookies, ASLR, rp_filter e redirect a posto."))
        return out
