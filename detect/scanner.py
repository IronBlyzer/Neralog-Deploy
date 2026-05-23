#!/usr/bin/env python3
"""
scanner.py — Moteur de détection d'appareils (bibliothèque réutilisable).

Utilisé par discover.py (CLI) et par l'interface web (webapp/app.py).

Classement de l'OS :
    - WinRM (5985/5986)            -> windows
    - RDP seul (3389)              -> windows
    - SSH (22) + bannière FreeBSD  -> freebsd  (pfSense / OPNsense / serveur BSD)
    - SSH (22) + bannière Windows  -> windows
    - SSH (22) autre               -> linux
    - rien d'identifiable          -> unknown

Pur Python : ping système + scan TCP + lecture de bannière SSH.
Pas de root, pas de nmap requis.
"""
from __future__ import annotations

import ipaddress
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

PROBE_PORTS = {
    22: "ssh",
    5985: "winrm_http",
    5986: "winrm_https",
    3389: "rdp",
    80: "http",
    443: "https",
}


def is_alive(host: str, timeout: float = 1.0) -> bool:
    """Ping ICMP via la commande système (portable)."""
    win = platform.system().lower() == "windows"
    count_flag = "-n" if win else "-c"
    wait_flag = "-w" if win else "-W"
    wait_val = str(int(timeout * 1000)) if win else str(int(timeout))
    try:
        res = subprocess.run(
            ["ping", count_flag, "1", wait_flag, wait_val, host],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return res.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def probe_port(host: str, port: int, timeout: float = 0.6) -> bool:
    """Connexion TCP : True si le port accepte."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def grab_ssh_banner(host: str, timeout: float = 1.0) -> str:
    """Lit la bannière SSH (ex: 'SSH-2.0-OpenSSH_8.8 FreeBSD-20211221')."""
    try:
        with socket.create_connection((host, 22), timeout=timeout) as sock:
            sock.settimeout(timeout)
            return sock.recv(256).decode("utf-8", errors="ignore").strip()
    except (OSError, socket.timeout):
        return ""


def classify(host: str, open_ports: set[int], port_timeout: float) -> tuple[str, str | None, dict]:
    """Retourne (os_family, ansible_connection, extra)."""
    extra: dict = {}

    if 5986 in open_ports:
        return "windows", "winrm", {"winrm_port": 5986}
    if 5985 in open_ports:
        return "windows", "winrm", {"winrm_port": 5985}

    if 22 in open_ports:
        banner = grab_ssh_banner(host, port_timeout + 0.4).lower()
        extra["ssh_banner"] = banner
        if "opnsense" in banner:
            return "freebsd", "ssh", {**extra, "appliance": "opnsense"}
        if "pfsense" in banner:
            return "freebsd", "ssh", {**extra, "appliance": "pfsense"}
        if "freebsd" in banner:
            return "freebsd", "ssh", extra
        if "windows" in banner:
            return "windows", "winrm", extra
        return "linux", "ssh", extra

    if 3389 in open_ports:  # RDP seul : Windows mais WinRM fermé
        return "windows", "winrm", {"winrm_port": None}

    return "unknown", None, extra


def scan_host(host: str, do_ping: bool, port_timeout: float) -> dict | None:
    """Scanne un hôte unique. Retourne un dict descriptif ou None si l'hôte est absent.

    Un hôte vivant au ping mais sans port de gestion ouvert est tout de même listé
    (services vides, OS « unknown ») : visible dans l'inventaire, mais non déployable
    tant qu'aucun accès (SSH/WinRM) n'est ouvert dessus.
    """
    alive = is_alive(host) if do_ping else False
    if not alive:
        # Pas de réponse au ping : on ne garde l'hôte que s'il a un port de gestion.
        # Pré-filtre rapide pour ne pas scanner intégralement un /24 majoritairement vide.
        if not any(probe_port(host, p, port_timeout) for p in (22, 5985, 3389)):
            return None

    open_ports = {p for p in PROBE_PORTS if probe_port(host, p, port_timeout)}
    if not open_ports and not alive:
        return None

    if open_ports:
        os_family, connection, extra = classify(host, open_ports, port_timeout)
    else:
        # Vivant au ping mais aucun port ouvert : visibilité seule, non déployable.
        os_family, connection, extra = "unknown", None, {}

    try:
        hostname = socket.gethostbyaddr(host)[0]
    except (socket.herror, socket.gaierror, OSError):
        hostname = host

    return {
        "ip": host,
        "hostname": hostname,
        "open_ports": sorted(open_ports),
        "services": sorted(PROBE_PORTS[p] for p in open_ports),
        "os_family": os_family,
        "ansible_connection": connection,
        "appliance": extra.get("appliance"),
        "winrm_port": extra.get("winrm_port"),
    }


def scan_network(
    cidrs: list[str],
    workers: int = 128,
    do_ping: bool = True,
    port_timeout: float = 0.6,
    progress=None,
) -> list[dict]:
    """
    Scanne tous les hôtes des CIDR fournis, en parallèle.
    `progress(done, total, result|None)` est appelé à chaque hôte terminé (optionnel).
    """
    targets: list[str] = []
    for cidr in cidrs:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        targets.extend(str(h) for h in hosts)

    total = len(targets)
    found: list[dict] = []
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_host, ip, do_ping, port_timeout): ip for ip in targets}
        for fut in as_completed(futures):
            result = fut.result()
            done += 1
            if result:
                found.append(result)
            if progress:
                progress(done, total, result)

    found.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return found
