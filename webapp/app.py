#!/usr/bin/env python3
"""
app.py — Console web de déploiement Filebeat (configurable via .env, conteneurisable).

Flux :
    1. /api/scan    : scanne le(s) réseau(x), renvoie la liste des machines.
    2. (UI)         : l'admin coche les machines, peut corriger l'OS détecté.
    3. /api/deploy  : génère un inventaire limité aux machines cochées,
                      lance ansible-playbook en arrière-plan.
    4. /api/deploy/<job_id> : suivi en direct (log + statut).
    /api/config     : valeurs par défaut issues du .env (pré-remplissage de l'UI).

Toute la configuration vit dans le .env (voir .env.example).
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import uuid
from pathlib import Path

import yaml
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DETECT_DIR = PROJECT_ROOT / "detect"
sys.path.insert(0, str(DETECT_DIR))

load_dotenv(PROJECT_ROOT / ".env")  # charge la config

import scanner  # noqa: E402
from store import InventoryStore, PresetStore  # noqa: E402

app = Flask(__name__, static_folder=str(BASE_DIR / "static"), static_url_path="/static")

INVENTORY_FILE = os.environ.get("INVENTORY_FILE", str(PROJECT_ROOT / "data" / "inventory.json"))
store = InventoryStore(INVENTORY_FILE)
presets = PresetStore(str(Path(INVENTORY_FILE).parent / "fb_presets.json"))


def env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def env_bool(key: str, default: bool = False) -> bool:
    return env(key, str(default)).strip().lower() in ("1", "true", "yes", "on")


# Config dérivée du .env
CONFIG = {
    "output_type": env("FILEBEAT_OUTPUT_TYPE", "logstash"),
    "output_host": env("FILEBEAT_OUTPUT_HOST", "elk:5044"),
    "tls_enabled": env_bool("FILEBEAT_TLS_ENABLED", False),
    "default_cidrs": [c.strip() for c in env("DEFAULT_CIDRS", "").split(",") if c.strip()],
    "default_ssh_user": env("DEFAULT_SSH_USER", ""),
    "bootstrap_user": env("BOOTSTRAP_USER", ""),
    "bootstrap_password": env("BOOTSTRAP_PASSWORD", ""),
    "scan_timeout": float(env("SCAN_TIMEOUT", "0.6")),
}

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

# Compte d'automation créé sur les machines lors du seeding
SVC_USER = "filebeat-deploy"
KEY_PRIV = str(Path(INVENTORY_FILE).parent / "console_id_ed25519")
KEY_PUB = KEY_PRIV + ".pub"


def ensure_keypair() -> str:
    """Génère la paire de clés de la console si absente. Retourne la clé publique."""
    Path(KEY_PRIV).parent.mkdir(parents=True, exist_ok=True)
    if not os.path.exists(KEY_PRIV):
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "filebeat-console", "-f", KEY_PRIV],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        os.chmod(KEY_PRIV, 0o600)
    with open(KEY_PUB, encoding="utf-8") as f:
        return f.read().strip()


# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    return send_from_directory(BASE_DIR / "templates", "index.html")


@app.route("/api/config")
def api_config():
    """Valeurs par défaut pour pré-remplir l'UI (l'ELK est connu d'avance)."""
    return jsonify({
        "output_type": CONFIG["output_type"],
        "output_host": CONFIG["output_host"],
        "default_cidrs": CONFIG["default_cidrs"],
        "default_ssh_user": CONFIG["default_ssh_user"],
        "bootstrap_user": CONFIG["bootstrap_user"],
        "scan_timeout": CONFIG["scan_timeout"],
    })


# --------------------------------------------------------------------------- #
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    cidrs = [c.strip() for c in data.get("cidrs", []) if c.strip()]
    if not cidrs:
        return jsonify({"error": "Aucun sous-réseau fourni."}), 400

    no_ping = bool(data.get("no_ping", False))
    timeout = float(data.get("timeout", CONFIG["scan_timeout"]))

    try:
        hosts = scanner.scan_network(cidrs, workers=128, do_ping=not no_ping, port_timeout=timeout)
    except ValueError as exc:
        return jsonify({"error": f"CIDR invalide : {exc}"}), 400

    store.merge_scan(hosts)          # persiste / fusionne dans l'inventaire
    return jsonify(store.view())     # renvoie l'inventaire complet à jour


@app.route("/api/inventory")
def api_inventory():
    """Inventaire de parc persistant (chargé à l'ouverture, sans rescanner)."""
    return jsonify(store.view())


@app.route("/api/os_override", methods=["POST"])
def api_os_override():
    data = request.get_json(force=True)
    ip = data.get("ip")
    os_family = data.get("os_family")
    if not ip:
        return jsonify({"error": "ip manquante"}), 400
    store.set_override(ip, os_family)
    return jsonify({"ok": True})


@app.route("/api/host/<ip>", methods=["DELETE"])
def api_remove_host(ip: str):
    store.remove_host(ip)
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
def host_name(h: dict) -> str:
    return h.get("hostname") or f"host_{h['ip'].replace('.', '_')}"


def build_inventory(selected: list[dict]) -> dict:
    """Inventaire de déploiement : clé pour les machines semées, sinon creds par machine (partie 2)."""
    groups = {g: {"hosts": {}} for g in ("linux", "freebsd", "macos", "windows", "unknown")}
    for h in selected:
        osf = h.get("os_family", "unknown")
        if osf not in groups:
            osf = "unknown"
        name = host_name(h)
        keyed = h.get("access") == "key"
        cred_user = (h.get("cred_user") or "").strip()
        cred_pw = h.get("cred_password") or ""
        hv: dict = {"ansible_host": h["ip"]}
        if osf in ("linux", "freebsd", "macos"):
            hv["ansible_connection"] = "ssh"
            if keyed:
                hv["ansible_user"] = SVC_USER
                hv["ansible_ssh_private_key_file"] = KEY_PRIV
                if osf == "freebsd":
                    hv["ansible_become_method"] = "doas"
            else:
                user = cred_user or CONFIG["default_ssh_user"]
                if user:
                    hv["ansible_user"] = user
                if cred_pw:
                    hv["ansible_become_password"] = cred_pw
        elif osf == "windows":
            if keyed:  # Windows via OpenSSH + clé
                hv["ansible_connection"] = "ssh"
                hv["ansible_user"] = SVC_USER
                hv["ansible_ssh_private_key_file"] = KEY_PRIV
                hv["ansible_shell_type"] = "powershell"
            else:       # repli WinRM + creds par machine
                hv["ansible_connection"] = "winrm"
                hv["ansible_port"] = h.get("winrm_port") or 5985
                hv["ansible_winrm_server_cert_validation"] = "ignore"
                if cred_user:
                    hv["ansible_user"] = cred_user
                if cred_pw:
                    hv["ansible_password"] = cred_pw
        if h.get("appliance"):
            hv["appliance"] = h["appliance"]
        groups[osf]["hosts"][name] = hv
    return {"all": {"children": groups}}


def build_bootstrap_inventory(selected: list[dict]) -> dict:
    """Inventaire de seeding : chaque hôte porte ses creds résolus (_buser/_bpass)."""
    groups = {g: {"hosts": {}} for g in ("linux", "freebsd", "macos", "windows", "unknown")}
    for h in selected:
        osf = h.get("os_family", "unknown")
        if osf not in groups or osf == "unknown":
            continue
        name = host_name(h)
        hv: dict = {"ansible_host": h["ip"], "ansible_user": h["_buser"], "ansible_password": h["_bpass"]}
        if osf in ("linux", "freebsd", "macos"):
            hv["ansible_connection"] = "ssh"
            hv["ansible_become_password"] = h["_bpass"]
            if osf == "freebsd":
                hv["ansible_become_method"] = "sudo"  # bascule en doas si besoin
        elif osf == "windows":
            hv["ansible_connection"] = "ssh"          # OpenSSH activé au préalable
            hv["ansible_shell_type"] = "powershell"
        groups[osf]["hosts"][name] = hv
    return {"all": {"children": groups}}


# PLAY RECAP : "nom : ok=3 changed=1 unreachable=0 failed=0 ..."
RECAP_RE = re.compile(
    r"^(?P<name>\S+)\s*:\s*ok=\d+\s+changed=\d+\s+unreachable=(?P<unr>\d+)\s+failed=(?P<failed>\d+)"
)


def compute_results(job: dict):
    """Parse le PLAY RECAP pour donner un statut par machine."""
    stats: dict[str, dict] = {}
    for line in job["log"]:
        m = RECAP_RE.match(line.strip())
        if m:
            stats[m.group("name")] = {"unreachable": int(m.group("unr")), "failed": int(m.group("failed"))}

    results = []
    for meta in job.get("hosts_meta", []):
        s = stats.get(meta["name"])
        if s is None:
            status = "skipped"          # non ciblé (ex: OS "unknown") ou jamais atteint
        elif s["unreachable"] > 0:
            status = "unreachable"      # connexion impossible (SSH/WinRM)
        elif s["failed"] > 0:
            status = "failed"           # une tâche a échoué
        else:
            status = "ok"               # déployé
        results.append({**meta, "status": status})
    job["results"] = results


def run_playbook(job_id: str, inv_path: str, extra_vars: dict, check: bool, playbooks: list[str], kind: str = "deploy"):
    job = JOBS[job_id]
    if shutil.which("ansible-playbook") is None:
        job["status"] = "error"
        job["log"].append("ansible-playbook introuvable. Installe-le : pip install ansible")
        compute_results(job)
        return
    if not playbooks:
        job["status"] = "done"
        job["log"].append("Aucune machine éligible sélectionnée.")
        compute_results(job)
        return

    env_vars = {**os.environ, "ANSIBLE_HOST_KEY_CHECKING": "False", "ANSIBLE_FORCE_COLOR": "0"}
    rc_total = 0
    try:
        for pb in playbooks:
            cmd = [
                "ansible-playbook", "-i", inv_path, pb,
                "-e", yaml.safe_dump(extra_vars, default_flow_style=True).strip(),
            ]
            if check:
                cmd.append("--check")
            job["log"].append(f"$ ansible-playbook {pb}" + (" --check" if check else ""))
            proc = subprocess.Popen(
                cmd, cwd=str(PROJECT_ROOT), env=env_vars,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
            )
            for line in proc.stdout:
                job["log"].append(line.rstrip("\n"))
            proc.wait()
            rc_total |= proc.returncode
        job["returncode"] = rc_total
        job["status"] = "done" if rc_total == 0 else "failed"
    except Exception as exc:  # noqa: BLE001
        job["status"] = "error"
        job["log"].append(f"Erreur d'exécution : {exc}")
    finally:
        compute_results(job)
        if not check:
            ok_ips = [r["ip"] for r in job.get("results", []) if r["status"] == "ok"]
            if ok_ips and kind == "deploy":
                store.mark_deployed(ok_ips)
            elif ok_ips and kind == "seed":
                store.mark_access(ok_ips, "key")
        try:
            os.unlink(inv_path)
        except OSError:
            pass


@app.route("/api/deploy", methods=["POST"])
def api_deploy():
    data = request.get_json(force=True)
    selected = data.get("hosts", [])
    if not selected:
        return jsonify({"error": "Aucune machine sélectionnée."}), 400

    # Un seul type d'OS par déploiement : la config Filebeat diffère selon l'OS
    # (modules/chemins Linux vs canaux d'événements Windows). Éviter de mélanger.
    _bucket = {"linux": "Linux/BSD", "freebsd": "Linux/BSD", "macos": "macOS", "windows": "Windows"}
    deploy_buckets = {_bucket[osf] for h in selected if (osf := h.get("os_family")) in _bucket}
    if len(deploy_buckets) > 1:
        return jsonify({"error": f"Déploie un seul type d'OS à la fois ({' + '.join(sorted(deploy_buckets))} mélangés). Sépare Linux/BSD, macOS et Windows."}), 400

    # La sortie vient du .env (ELK connu) ; le client peut surcharger si besoin.
    output = data.get("output", {})

    # Config Filebeat personnalisée depuis l'UI (modules / chemins / champ client).
    cfg = data.get("config", {}) or {}
    modules = [str(m).strip() for m in (cfg.get("modules") or []) if str(m).strip()] or ["system"]
    log_paths = [str(p).strip() for p in (cfg.get("log_paths") or []) if str(p).strip()] or ["/var/log/*.log"]
    extra_fields = {"managed_by": "ansible"}
    client = (cfg.get("client") or "").strip()
    if client:
        extra_fields["client"] = client

    extra_vars = {
        "filebeat_output_type": output.get("type") or CONFIG["output_type"],
        "filebeat_output_host": output.get("host") or CONFIG["output_host"],
        "filebeat_tls_enabled": CONFIG["tls_enabled"],
        "filebeat_modules": modules,
        "filebeat_log_paths": log_paths,
        "filebeat_extra_fields": extra_fields,
    }
    check = bool(data.get("dry_run", False))

    # Ne lancer que les playbooks nécessaires (un parc Linux n'exige pas la collection Windows).
    families = {h.get("os_family") for h in selected}
    playbooks: list[str] = []
    if families & {"linux", "freebsd", "macos"}:
        playbooks.append("deploy-unix.yml")
    if "windows" in families:
        playbooks.append("deploy-windows.yml")

    inventory = build_inventory(selected)
    fd, inv_path = tempfile.mkstemp(prefix="fb_inv_", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)
    os.chmod(inv_path, 0o600)

    job_id = uuid.uuid4().hex[:12]
    hosts_meta = [
        {"name": host_name(h), "ip": h["ip"], "hostname": h.get("hostname"), "os_family": h.get("os_family")}
        for h in selected
    ]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "running", "log": [], "returncode": None,
                        "targets": [h["ip"] for h in selected], "check": check,
                        "hosts_meta": hosts_meta, "results": []}
    threading.Thread(target=run_playbook, args=(job_id, inv_path, extra_vars, check, playbooks, "deploy"), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/presets", methods=["GET"])
def api_presets_list():
    return jsonify({"presets": presets.list()})


@app.route("/api/presets", methods=["POST"])
def api_presets_save():
    data = request.get_json(force=True)
    try:
        out = presets.save(data.get("name", ""), data.get("config", {}) or {})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify({"presets": out})


@app.route("/api/presets/<path:name>", methods=["DELETE"])
def api_presets_delete(name: str):
    return jsonify({"presets": presets.delete(name)})


@app.route("/api/key")
def api_key():
    """Clé publique de la console (générée à la première demande)."""
    try:
        pub = ensure_keypair()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"génération de clé impossible : {exc}"}), 500
    return jsonify({"public_key": pub, "user": SVC_USER})


@app.route("/api/seed", methods=["POST"])
def api_seed():
    """Sème la clé de la console sur les machines sélectionnées (compte dédié)."""
    data = request.get_json(force=True)
    selected = [h for h in data.get("hosts", []) if h.get("os_family") in ("linux", "freebsd", "macos", "windows")]
    if not selected:
        return jsonify({"error": "Aucune machine éligible (Linux/FreeBSD/Windows) sélectionnée."}), 400
    boot_user = (data.get("boot_user") or "").strip()
    boot_password = data.get("boot_password") or ""
    # défauts depuis le .env si non fournis dans l'UI
    gen_user = boot_user or CONFIG["bootstrap_user"]
    gen_pass = boot_password or CONFIG["bootstrap_password"]

    # creds résolus par machine : surcharge perso > général/.env
    for h in selected:
        h["_buser"] = (h.get("cred_user") or "").strip() or gen_user
        h["_bpass"] = h.get("cred_password") or gen_pass
    if any(not h["_buser"] for h in selected):
        return jsonify({"error": "Identifiant admin manquant (général ou par machine)."}), 400

    try:
        pubkey = ensure_keypair()
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"clé console indisponible : {exc}"}), 500

    extra_vars = {"console_pubkey": pubkey, "svc_user": SVC_USER,
                  "lock_bootstrap": bool(data.get("lock_bootstrap", False))}

    families = {h["os_family"] for h in selected}
    playbooks: list[str] = []
    if families & {"linux", "freebsd", "macos"}:
        playbooks.append("seed-unix.yml")
    if "windows" in families:
        playbooks.append("seed-windows.yml")

    inventory = build_bootstrap_inventory(selected)
    fd, inv_path = tempfile.mkstemp(prefix="fb_seed_", suffix=".yml")
    with os.fdopen(fd, "w") as f:
        yaml.safe_dump(inventory, f, default_flow_style=False, sort_keys=False)
    os.chmod(inv_path, 0o600)

    job_id = uuid.uuid4().hex[:12]
    hosts_meta = [
        {"name": host_name(h), "ip": h["ip"], "hostname": h.get("hostname"), "os_family": h.get("os_family")}
        for h in selected
    ]
    with JOBS_LOCK:
        JOBS[job_id] = {"status": "running", "log": [], "returncode": None,
                        "targets": [h["ip"] for h in selected], "check": False,
                        "hosts_meta": hosts_meta, "results": []}
    threading.Thread(target=run_playbook, args=(job_id, inv_path, extra_vars, False, playbooks, "seed"), daemon=True).start()
    return jsonify({"job_id": job_id})


@app.route("/api/deploy/<job_id>")
def api_deploy_status(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "job inconnu"}), 404
    return jsonify({
        "status": job["status"], "returncode": job["returncode"],
        "log": job["log"], "targets": job["targets"], "check": job["check"],
        "results": job.get("results", []),
    })


if __name__ == "__main__":
    host = env("FLASK_HOST", "127.0.0.1")
    port = int(env("FLASK_PORT", "5000"))
    print(f"Console Filebeat : http://{host}:{port}")
    app.run(host=host, port=port, debug=False, threaded=True)
