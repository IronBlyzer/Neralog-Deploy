#!/usr/bin/env python3
"""
store.py — Inventaire de parc persistant (stockage JSON).

L'inventaire survit aux scans et aux redémarrages : chaque machine garde sa date
de première/dernière détection, l'OS corrigé par l'admin, et son état de
déploiement Filebeat. Un re-scan met à jour les machines vues et ajoute les
nouvelles, sans effacer celles qui étaient absentes (elles passent "hors-ligne").

Structure du fichier :
{
  "last_scan_at": "2026-... | null",
  "hosts": {
    "<ip>": {
      "ip", "hostname", "os_detected", "os_override",
      "services", "open_ports", "appliance", "winrm_port",
      "first_seen", "last_seen", "deployed", "last_deploy"
    }
  }
}
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class InventoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # --- I/O bas niveau ---------------------------------------------------
    def _load(self) -> dict:
        if not self.path.exists():
            return {"last_scan_at": None, "hosts": {}}
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {"last_scan_at": None, "hosts": {}}

    def _save(self, data: dict):
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # écriture atomique

    # --- opérations -------------------------------------------------------
    def merge_scan(self, scanned: list[dict]) -> dict:
        """Fusionne un résultat de scan dans l'inventaire (update + ajout)."""
        with _LOCK:
            data = self._load()
            now = _now()
            data["last_scan_at"] = now
            for h in scanned:
                ip = h["ip"]
                rec = data["hosts"].get(ip, {})
                rec.update({
                    "ip": ip,
                    "hostname": h.get("hostname") or ip,
                    "os_detected": h.get("os_family", "unknown"),
                    "services": h.get("services", []),
                    "open_ports": h.get("open_ports", []),
                    "appliance": h.get("appliance"),
                    "winrm_port": h.get("winrm_port"),
                    "last_seen": now,
                })
                rec.setdefault("os_override", None)
                rec.setdefault("first_seen", now)
                rec.setdefault("deployed", False)
                rec.setdefault("last_deploy", None)
                rec.setdefault("access", "none")   # none | password | key
                data["hosts"][ip] = rec
            self._save(data)
            return data

    def set_override(self, ip: str, os_family: str | None):
        with _LOCK:
            data = self._load()
            if ip in data["hosts"]:
                data["hosts"][ip]["os_override"] = os_family
                self._save(data)

    def mark_deployed(self, ips: list[str]):
        with _LOCK:
            data = self._load()
            now = _now()
            for ip in ips:
                if ip in data["hosts"]:
                    data["hosts"][ip]["deployed"] = True
                    data["hosts"][ip]["last_deploy"] = now
            self._save(data)

    def mark_access(self, ips: list[str], state: str):
        """state: 'key' (clé en place) | 'password' | 'none'."""
        with _LOCK:
            data = self._load()
            for ip in ips:
                if ip in data["hosts"]:
                    data["hosts"][ip]["access"] = state
            self._save(data)

    def remove_host(self, ip: str):
        with _LOCK:
            data = self._load()
            data["hosts"].pop(ip, None)
            self._save(data)

    def view(self) -> dict:
        """Vue prête pour l'UI : liste à plat, OS effectif, état en ligne, compteurs."""
        with _LOCK:
            data = self._load()
        last_scan = data.get("last_scan_at")
        hosts = []
        counts = {"linux": 0, "windows": 0, "freebsd": 0, "unknown": 0}
        for rec in data["hosts"].values():
            eff = rec.get("os_override") or rec.get("os_detected", "unknown")
            counts[eff] = counts.get(eff, 0) + 1
            hosts.append({
                "ip": rec["ip"],
                "hostname": rec.get("hostname", rec["ip"]),
                "os_family": eff,
                "os_detected": rec.get("os_detected", "unknown"),
                "services": rec.get("services", []),
                "open_ports": rec.get("open_ports", []),
                "appliance": rec.get("appliance"),
                "winrm_port": rec.get("winrm_port"),
                "last_seen": rec.get("last_seen"),
                "online": rec.get("last_seen") == last_scan and last_scan is not None,
                "deployed": rec.get("deployed", False),
                "last_deploy": rec.get("last_deploy"),
                "access": rec.get("access", "none"),
            })
        hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")) if h["ip"].count(".") == 3 else (0,))
        return {"last_scan_at": last_scan, "hosts": hosts, "counts": counts, "total": len(hosts)}
