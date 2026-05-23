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

Deux moteurs :
    - nmap (préféré) si présent + privilèges raw : découverte ARP (trouve les
      machines silencieuses), détection d'OS fiable (Linux/Windows/BSD/macOS/Android...).
    - repli pur Python (ping + scan TCP + bannière SSH) si nmap absent : pas de
      root requis, mais détection d'OS plus limitée.
"""
from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
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
        "os_name": None,            # le chemin Python ne fait pas de fingerprint OS détaillé
        "ansible_connection": connection,
        "appliance": extra.get("appliance"),
        "winrm_port": extra.get("winrm_port"),
    }


def scan_network_python(
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


# ===========================================================================
# Moteur nmap (préféré si disponible + privilèges raw socket)
# ===========================================================================
# nmap apporte : découverte ARP (trouve les machines silencieuses, même sans
# port ouvert), détection d'OS (-O) bien plus fiable que la bannière, et la
# détection de tout type d'OS (macOS, Android, équipements réseau...).
# Repli automatique sur le moteur Python si nmap absent ou sans privilèges.

NMAP_PORTS = "22,80,443,3389,5985,5986"


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def _can_raw() -> bool:
    """nmap -O / ARP exigent des sockets raw (root, ou CAP_NET_RAW dans le conteneur)."""
    try:
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except OSError:
        return False


def _map_os(osfamily: str | None, os_name: str | None, open_ports: set[int]) -> tuple[str, str | None]:
    """nmap osfamily -> (os_family déployable parmi linux/freebsd/windows/unknown, appliance)."""
    name = (os_name or "").lower()
    if "opnsense" in name:
        return "freebsd", "opnsense"
    if "pfsense" in name:
        return "freebsd", "pfsense"
    fam = (osfamily or "").lower()
    if fam == "linux":
        return "linux", None
    if fam == "windows":
        return "windows", None
    if fam == "freebsd":
        return "freebsd", None
    if fam in ("mac os x", "macos", "darwin"):
        return "macos", None
    if fam:
        # OS reconnu mais non déployable (macOS, Android, iOS, embarqué...) :
        # visible via os_name, mais traité "unknown" côté déploiement.
        return "unknown", None
    # nmap n'a pas conclu sur l'OS : on déduit des ports.
    if {5985, 5986, 3389} & open_ports:
        return "windows", None
    if 22 in open_ports:
        return "linux", None
    return "unknown", None


def _parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    results: list[dict] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        ip = next((a.get("addr") for a in host.findall("address")
                   if a.get("addrtype") == "ipv4"), None)
        if not ip:
            continue

        hn = host.find("hostnames/hostname")
        hostname = hn.get("name") if (hn is not None and hn.get("name")) else ip

        open_ports = {
            int(p.get("portid"))
            for p in host.findall("ports/port")
            if (p.find("state") is not None and p.find("state").get("state") == "open")
        }

        os_name = None
        osfamily = None
        osm = host.find("os/osmatch")
        if osm is not None:
            os_name = osm.get("name")
            oc = osm.find("osclass")
            if oc is not None:
                osfamily = oc.get("osfamily")

        os_family, appliance = _map_os(osfamily, os_name, open_ports)

        if 22 in open_ports:
            connection = "ssh"
        elif {5985, 5986} & open_ports:
            connection = "winrm"
        else:
            connection = None

        winrm_port = 5986 if 5986 in open_ports else (5985 if 5985 in open_ports else None)

        results.append({
            "ip": ip,
            "hostname": hostname,
            "open_ports": sorted(open_ports),
            "services": sorted(PROBE_PORTS[p] for p in open_ports if p in PROBE_PORTS),
            "os_family": os_family,
            "os_name": os_name,
            "ansible_connection": connection,
            "appliance": appliance,
            "winrm_port": winrm_port,
        })
    return results


def scan_network_nmap(cidrs: list[str], do_ping: bool = True, port_timeout: float = 0.6) -> list[dict]:
    """Scan via nmap : découverte + ports + détection d'OS, sortie XML parsée."""
    cmd = ["nmap", "-O", "--osscan-guess", "-p", NMAP_PORTS, "-T4", "-oX", "-"]
    if not do_ping:
        cmd.append("-Pn")   # ne pas faire la découverte, traiter tout comme actif
    cmd += [c.strip() for c in cidrs if c.strip()]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"nmap a échoué (rc={proc.returncode}): {proc.stderr.strip()[:200]}")

    hosts = _parse_nmap_xml(proc.stdout)
    hosts.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return hosts


def scan_network(
    cidrs: list[str],
    workers: int = 128,
    do_ping: bool = True,
    port_timeout: float = 0.6,
    progress=None,
) -> list[dict]:
    """Point d'entrée : nmap si dispo + privilèges, sinon repli sur le moteur Python."""
    if nmap_available() and _can_raw():
        try:
            return scan_network_nmap(cidrs, do_ping, port_timeout)
        except Exception:
            # nmap a planté (privilèges, réseau...) -> on retombe sur le moteur Python.
            pass
    return scan_network_python(cidrs, workers, do_ping, port_timeout, progress)
