#!/usr/bin/env python3
"""
discover.py — CLI de détection + génération d'inventaire Ansible.
S'appuie sur scanner.py (même moteur que l'interface web).

Exemples :
    python3 discover.py --cidr 192.168.1.0/24
    python3 discover.py --cidr 10.0.0.0/24 10.0.1.0/24 --out ../inventory/hosts.yml
    python3 discover.py --cidr 192.168.1.0/24 --no-ping
"""
from __future__ import annotations

import argparse
import ipaddress
import sys
from datetime import datetime, timezone

import scanner


def build_inventory(hosts: list[dict], logstash_host: str) -> dict:
    inventory: dict = {
        "all": {
            "vars": {"filebeat_output_host": logstash_host},
            "children": {
                "linux": {"hosts": {}},
                "windows": {"hosts": {}},
                "freebsd": {"hosts": {}},
                "unknown": {"hosts": {}},
            },
        }
    }
    for h in hosts:
        group = h["os_family"] if h["os_family"] in ("linux", "windows", "freebsd") else "unknown"
        host_vars: dict = {"ansible_host": h["ip"], "detected_services": h["services"]}
        if h["ansible_connection"]:
            host_vars["ansible_connection"] = h["ansible_connection"]
        if h["os_family"] == "windows" and h.get("winrm_port"):
            host_vars["ansible_port"] = h["winrm_port"]
        if h.get("appliance"):
            host_vars["appliance"] = h["appliance"]
        name = h["hostname"] if h["hostname"] != h["ip"] else f"host_{h['ip'].replace('.', '_')}"
        inventory["all"]["children"][group]["hosts"][name] = host_vars
    return inventory


def to_yaml(data: dict, indent: int = 0) -> str:
    lines: list[str] = []
    pad = "  " * indent
    for key, value in data.items():
        if isinstance(value, dict):
            if value:
                lines.append(f"{pad}{key}:")
                lines.append(to_yaml(value, indent + 1))
            else:
                lines.append(f"{pad}{key}: {{}}")
        elif isinstance(value, list):
            lines.append(f"{pad}{key}: [{', '.join(str(v) for v in value)}]")
        else:
            lines.append(f"{pad}{key}: {value}")
    return "\n".join(line for line in lines if line)


def main() -> int:
    parser = argparse.ArgumentParser(description="Détection d'appareils + inventaire Ansible.")
    parser.add_argument("--cidr", nargs="+", required=True, help="Sous-réseaux, ex: 192.168.1.0/24")
    parser.add_argument("--out", default="inventory/hosts.yml", help="Fichier de sortie")
    parser.add_argument("--logstash", default="logstash.local:5044", help="Hôte:port Logstash/ELK")
    parser.add_argument("--workers", type=int, default=128)
    parser.add_argument("--timeout", type=float, default=0.6)
    parser.add_argument("--no-ping", action="store_true")
    args = parser.parse_args()

    print(f"[*] Scan de {', '.join(args.cidr)}...", file=sys.stderr)

    def show(done, total, result):
        if result:
            print(f"    [+] {result['ip']:<15} {result['os_family'].upper():<8} {result['services']}", file=sys.stderr)

    hosts = scanner.scan_network(args.cidr, args.workers, not args.no_ping, args.timeout, progress=show)
    if not hosts:
        print("[!] Aucun hôte détecté.", file=sys.stderr)
        return 1

    inventory = build_inventory(hosts, args.logstash)
    header = (
        f"# Inventaire généré par discover.py\n"
        f"# Date : {datetime.now(timezone.utc).isoformat()}\n"
        f"# Sous-réseaux : {', '.join(args.cidr)} — {len(hosts)} hôte(s)\n"
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(header + to_yaml(inventory) + "\n")

    c = inventory["all"]["children"]
    print(f"\n[\u2713] {args.out} — linux={len(c['linux']['hosts'])} "
          f"windows={len(c['windows']['hosts'])} freebsd={len(c['freebsd']['hosts'])} "
          f"unknown={len(c['unknown']['hosts'])}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
