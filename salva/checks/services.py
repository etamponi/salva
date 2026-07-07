"""Superficie d'attacco di rete: porte in ascolto verso l'esterno."""
from __future__ import annotations

import os
import socket

from .base import Check, Finding, Severity, read_text

# Porte in chiaro / rischiose se esposte pubblicamente
RISKY = {
    23: ("Telnet", "protocollo in chiaro, sostituiscilo con SSH"),
    21: ("FTP", "credenziali in chiaro, preferisci SFTP/FTPS"),
    3306: ("MySQL/MariaDB", "un DB non dovrebbe ascoltare su IP pubblici"),
    5432: ("PostgreSQL", "un DB non dovrebbe ascoltare su IP pubblici"),
    6379: ("Redis", "spesso senza auth: non esporlo mai"),
    27017: ("MongoDB", "storicamente esposto senza auth"),
    9200: ("Elasticsearch", "nessuna auth di default: non esporlo"),
    11211: ("Memcached", "usato per amplificazione DDoS se esposto"),
    5900: ("VNC", "desktop remoto spesso debole, tunnellalo in SSH"),
    3389: ("RDP", "bersaglio frequente di brute force"),
}


def _decode_v4(hexaddr: str) -> tuple[str, int]:
    ip_hex, port_hex = hexaddr.split(":")
    port = int(port_hex, 16)
    b = bytes.fromhex(ip_hex)
    ip = ".".join(str(x) for x in reversed(b))
    return ip, port


def _decode_v6(hexaddr: str) -> tuple[str, int]:
    ip_hex, port_hex = hexaddr.split(":")
    port = int(port_hex, 16)
    b = bytes.fromhex(ip_hex)
    out = bytearray()
    for i in range(0, 16, 4):
        out += b[i:i + 4][::-1]
    try:
        ip = socket.inet_ntop(socket.AF_INET6, bytes(out))
    except OSError:
        ip = "::?"
    return ip, port


def _listening(path: str, decoder) -> list[tuple[str, int]]:
    text = read_text(path)
    if text is None:
        return []
    result = []
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4:
            continue
        # st == 0A => TCP LISTEN
        if cols[3] != "0A":
            continue
        try:
            ip, port = decoder(cols[1])
        except (ValueError, IndexError):
            continue
        result.append((ip, port))
    return result


def _is_public(ip: str) -> bool:
    if ip.startswith("127.") or ip == "::1":
        return False
    if ip in ("0.0.0.0", "::", "::0"):
        return True
    # link-local / uniche locali: le trattiamo comunque come "non loopback"
    return True


class ServicesCheck(Check):
    id = "services"
    title = "Porte in ascolto (superficie d'attacco)"

    def applicable(self) -> bool:
        return os.path.exists("/proc/net/tcp")

    def run(self) -> list[Finding]:
        sockets = (
            _listening("/proc/net/tcp", _decode_v4)
            + _listening("/proc/net/tcp6", _decode_v6)
        )
        if not sockets:
            return [self.finding(
                "Nessuna porta TCP in ascolto rilevata",
                Severity.INFO,
                "Impossibile leggere /proc/net/tcp oppure nessun servizio in ascolto.",
            )]

        public_ports = sorted({p for ip, p in sockets if _is_public(ip)})
        out: list[Finding] = []

        # Servizi rischiosi esposti pubblicamente
        for port in public_ports:
            if port in RISKY:
                name, why = RISKY[port]
                out.append(self.finding(
                    f"{name} esposto pubblicamente (porta {port})",
                    Severity.HIGH,
                    f"Porta {port} in ascolto su un indirizzo raggiungibile dalla rete: {why}.",
                    "Vincola il servizio a 127.0.0.1, mettilo dietro VPN/SSH tunnel, "
                    "o blocca la porta col firewall.",
                ))

        risky_set = set(RISKY)
        other = [p for p in public_ports if p not in risky_set]
        if other:
            out.append(self.finding(
                f"{len(public_ports)} porte pubbliche in ascolto",
                Severity.INFO,
                "Porte raggiungibili dalla rete: "
                + ", ".join(str(p) for p in public_ports),
                "Ogni porta e' superficie d'attacco: chiudi cio' che non serve e "
                "filtra il resto col firewall.",
            ))
        elif not out:
            out.append(self.ok(
                "Superficie di rete contenuta",
                "Solo servizi su loopback o porte note e sotto controllo.",
            ))
        return out
