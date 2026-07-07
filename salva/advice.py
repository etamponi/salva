"""Consigli curati di best practice, organizzati per area."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Topic:
    key: str
    title: str
    tips: list[str]


TOPICS: list[Topic] = [
    Topic("accessi", "Accessi e SSH", [
        "Disabilita il login diretto di root via SSH: usa un utente normale + sudo.",
        "Autenticazione a chiave, non a password: distribuisci le chiavi pubbliche, "
        "poi 'PasswordAuthentication no'.",
        "Proteggi le chiavi private con passphrase e tienile solo sui client, "
        "mai sui server.",
        "Installa fail2ban (o crowdsec) per bloccare i tentativi di brute force.",
        "MFA dove puoi: 2FA su SSH (chiave + TOTP) e sui pannelli di amministrazione.",
        "Rimuovi gli account inutilizzati e revoca le chiavi di chi lascia il team.",
    ]),
    Topic("rete", "Rete e firewall", [
        "Default deny in ingresso: apri solo le porte che servono davvero.",
        "Non esporre i database (MySQL, Postgres, Redis, Mongo) su IP pubblici: "
        "vincolali a 127.0.0.1 o dietro VPN.",
        "Metti l'amministrazione (SSH, pannelli) dietro VPN o IP allow-list.",
        "Segmenta la rete: separa DMZ, backend e management in subnet distinte.",
        "Usa TLS ovunque; disabilita protocolli e cifrari deboli (SSLv3, TLS 1.0/1.1).",
    ]),
    Topic("patching", "Aggiornamenti e patching", [
        "Abilita gli aggiornamenti automatici di sicurezza (unattended-upgrades / "
        "dnf-automatic).",
        "Pianifica le finestre di riavvio: le patch del kernel valgono solo dopo reboot "
        "(o usa live patching).",
        "Tieni un inventario del software e monitora i CVE dei componenti che usi.",
        "Rimuovi pacchetti e servizi che non usi: meno codice, meno superficie d'attacco.",
    ]),
    Topic("privilegi", "Privilegi e account", [
        "Principio del minimo privilegio: ognuno ha solo i permessi che gli servono.",
        "Niente lavoro quotidiano da root; usa sudo con regole mirate e log.",
        "Verifica che nessun account oltre root abbia UID 0.",
        "Blocca gli account di servizio ('nologin') e nega loro la shell.",
        "Rivedi periodicamente sudoers e i gruppi privilegiati (wheel/sudo/adm).",
    ]),
    Topic("dati", "Dati, backup e cifratura", [
        "Regola 3-2-1: 3 copie, 2 supporti, 1 off-site (e idealmente offline/immutabile).",
        "TESTA i restore: un backup non verificato non e' un backup.",
        "Cifra i dati a riposo (LUKS, cifratura dei volumi) e in transito (TLS).",
        "Proteggi i backup dal ransomware: copie immutabili o write-once.",
        "Gestisci i segreti con un vault (Vault, sops, secret manager), mai in chiaro nei repo.",
    ]),
    Topic("monitoraggio", "Log e monitoraggio", [
        "Centralizza i log su un host separato: chi ti attacca non deve poterli cancellare.",
        "Abilita l'audit (auditd) sulle azioni sensibili e sui file critici.",
        "Allarmi su eventi chiave: nuovi utenti, sudo falliti, modifiche a /etc, login inattesi.",
        "Sincronizza l'ora (NTP/chrony): senza timestamp coerenti l'analisi forense e' inutile.",
        "Fai controlli di integrita' dei file (AIDE/Tripwire) sui binari e le config.",
    ]),
    Topic("hardening", "Hardening del sistema", [
        "Riduci i servizi in esecuzione: disabilita ('systemctl disable') cio' che non serve.",
        "Tieni attivi MAC come SELinux o AppArmor invece di disattivarli.",
        "Applica l'hardening sysctl: syncookies, ASLR, rp_filter, no ICMP redirect.",
        "Monta /tmp, /var e le partizioni dati con noexec,nosuid,nodev dove possibile.",
        "Segui una baseline riconosciuta (CIS Benchmark, DISA STIG) per la tua distro.",
    ]),
    Topic("processo", "Processo e persone", [
        "Documenta un piano di incident response e provalo prima che serva.",
        "Inventario aggiornato di asset, servizi e responsabili: non proteggi cio' che non conosci.",
        "Formazione anti-phishing: l'anello umano e' spesso il piu' debole.",
        "Rivedi periodicamente gli accessi (chi puo' cosa) e revoca il superfluo.",
        "Automatizza i controlli ricorrenti (come 'salva check' via cron) e archivia i report.",
    ]),
]


def by_key(key: str) -> Topic | None:
    key = key.lower()
    for t in TOPICS:
        if t.key == key:
            return t
    return None
