"use strict";

// État local
let HOSTS = [];                 // inventaire courant (issu du store)
let LAST_SCAN = null;
const selected = new Set();     // IPs cochées
const credOverride = {};        // ip -> {user, password} : creds perso (non persistés)

const $ = (id) => document.getElementById(id);
const OS_ORDER = ["linux", "windows", "macos", "freebsd", "unknown"];

// ------------------------------------------------------------------ INIT
(async function init() {
  try {
    const cfg = await (await fetch("/api/config")).json();
    if (cfg.default_cidrs && cfg.default_cidrs.length) $("cidrs").value = cfg.default_cidrs.join("\n");
    if (cfg.scan_timeout) $("timeout").value = cfg.scan_timeout;
    if (cfg.output_type) $("out-type-badge").textContent = cfg.output_type;
    if (cfg.output_host) $("out-host-text").textContent = cfg.output_host;
    if (cfg.bootstrap_user) $("boot-user").value = cfg.bootstrap_user;
  } catch (e) { /* défauts HTML */ }

  renderFbConfig();

  // Inventaire de parc persistant : on l'affiche dès l'ouverture, sans rescanner.
  await loadInventory(true);
})();

async function loadInventory(silent) {
  try {
    const data = await (await fetch("/api/inventory")).json();
    applyInventory(data);
    if (data.total > 0) {
      $("select-panel").hidden = false;
      $("access-panel").hidden = false;
      $("deploy-panel").hidden = false;
      if (silent) setScanStatus(`inventaire chargé · ${data.total} machine(s)` + scanDateLabel());
    }
  } catch (e) { /* pas d'inventaire encore */ }
  loadKey();
}

async function loadKey() {
  try {
    const k = await (await fetch("/api/key")).json();
    if (k.public_key) $("pubkey").textContent = k.public_key;
  } catch (e) { $("pubkey").textContent = "(clé indisponible)"; }
}

function applyInventory(data) {
  HOSTS = data.hosts || [];
  LAST_SCAN = data.last_scan_at;
  // purge des sélections devenues invalides
  [...selected].forEach((ip) => { if (!HOSTS.find((h) => h.ip === ip)) selected.delete(ip); });
  renderCounts(data.counts || {});
  renderTable();
}

function scanDateLabel() {
  if (!LAST_SCAN) return "";
  const d = new Date(LAST_SCAN);
  return ` · dernier scan ${d.toLocaleString("fr-FR", { dateStyle: "short", timeStyle: "short" })}`;
}

// ------------------------------------------------------------------ SCAN
$("scan-btn").addEventListener("click", async () => {
  const cidrs = $("cidrs").value.split("\n").map((s) => s.trim()).filter(Boolean);
  if (!cidrs.length) { setScanStatus("⚠ indique au moins un sous-réseau", true); return; }

  $("scan-btn").disabled = true;
  setScanStatus('<span class="spin">▮</span> scan en cours…');
  $("status-dot").style.background = "var(--linux)";

  try {
    const res = await fetch("/api/scan", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ cidrs, no_ping: $("no-ping").checked, timeout: parseFloat($("timeout").value) }),
    });
    const data = await res.json();
    if (!res.ok) { setScanStatus("⚠ " + (data.error || "erreur"), true); return; }
    applyInventory(data);
    $("select-panel").hidden = false;
    $("access-panel").hidden = false;
    $("deploy-panel").hidden = false;
    setScanStatus(`✓ ${data.total} machine(s) dans l'inventaire` + scanDateLabel());
  } catch (e) {
    setScanStatus("⚠ " + e.message, true);
  } finally {
    $("scan-btn").disabled = false;
    $("status-dot").style.background = "var(--accent)";
  }
});

function setScanStatus(html, isErr) {
  const el = $("scan-status");
  el.innerHTML = html;
  el.style.color = isErr ? "var(--err)" : "var(--accent)";
}

// ------------------------------------------------------------------ TABLE
function renderCounts(counts) {
  $("counts").innerHTML = OS_ORDER
    .filter((o) => counts[o])
    .map((o) => `<span class="chip ${o}">${o} ${counts[o]}</span>`)
    .join("");
}

function renderTable() {
  const filter = $("filter").value.toLowerCase();
  const tbody = $("hosts-table").querySelector("tbody");
  tbody.innerHTML = "";

  HOSTS.filter((h) =>
    !filter || h.ip.includes(filter) || (h.hostname || "").toLowerCase().includes(filter)
      || h.os_family.includes(filter) || (h.os_name || "").toLowerCase().includes(filter)
  ).forEach((h) => {
    const os = h.os_family;
    const tr = document.createElement("tr");
    if (selected.has(h.ip)) tr.classList.add("selected");
    if (!h.online) tr.classList.add("offline");

    const appliance = h.appliance ? `<span class="appliance-tag">${h.appliance}</span>` : "";
    const sshOpen = (h.open_ports || []).includes(22);
    const sshBadge = `<span class="svc ssh ${sshOpen ? "ok" : "no"}" title="${sshOpen ? "SSH ouvert — déployable" : "SSH fermé — non déployable"}">ssh</span>`;
    const others = (h.services || []).filter((s) => s !== "ssh").map((s) => `<span class="svc">${s}</span>`).join("");
    const svcs = sshBadge + others;
    const picker = OS_ORDER.map((o) => `<option value="${o}" ${o === os ? "selected" : ""}>${o}</option>`).join("");
    const onlineDot = `<span class="state-dot ${h.online ? "on" : "off"}" title="${h.online ? "vu au dernier scan" : "absent du dernier scan"}"></span>`;
    const deployed = h.deployed ? `<span class="fb-badge" title="Filebeat déployé">✓ FB</span>` : "";
    const keyed = h.access === "key" ? `<span class="key-badge" title="accès par clé en place">🔑</span>` : "";
    const hasCred = credOverride[h.ip] && (credOverride[h.ip].user || credOverride[h.ip].password);

    tr.innerHTML = `
      <td class="cb"><input type="checkbox" ${selected.has(h.ip) ? "checked" : ""} data-ip="${h.ip}"></td>
      <td class="state">${onlineDot}${keyed}${deployed}</td>
      <td class="hostname">${esc(h.hostname || "—")}${appliance}</td>
      <td class="ip">${h.ip}</td>
      <td><select class="os-pick ${os}" data-ip="${h.ip}">${picker}</select>${h.os_name ? `<div class="os-detected" title="OS détecté par nmap">${esc(h.os_name)}</div>` : ""}</td>
      <td title="ports: ${h.open_ports.join(" ")}">${svcs}</td>
      <td class="act">
        <button class="creds ${hasCred ? "set" : ""}" data-ip="${h.ip}" title="identifiants spécifiques à cette machine">creds</button>
        <button class="rm" data-ip="${h.ip}" title="retirer de l'inventaire">×</button>
      </td>`;
    tbody.appendChild(tr);

    if (h.ip in credOverride) {
      const ed = document.createElement("tr");
      ed.className = "cred-edit";
      const c = credOverride[h.ip];
      ed.innerHTML = `<td></td><td colspan="6">
        <span class="cred-label">creds perso ${h.ip} :</span>
        <input type="text" class="cred-u" data-ip="${h.ip}" placeholder="utilisateur" value="${esc(c.user || "")}">
        <input type="password" class="cred-p" data-ip="${h.ip}" placeholder="mot de passe" value="${esc(c.password || "")}">
        <button class="btn ghost cred-clear" data-ip="${h.ip}">retirer</button>
      </td>`;
      tbody.appendChild(ed);
    }
  });

  tbody.querySelectorAll('input[type=checkbox]').forEach((cb) => {
    cb.addEventListener("change", () => {
      cb.checked ? selected.add(cb.dataset.ip) : selected.delete(cb.dataset.ip);
      cb.closest("tr").classList.toggle("selected", cb.checked);
      updateSelCount();
    });
  });
  tbody.querySelectorAll("select.os-pick").forEach((sel) => {
    sel.addEventListener("change", async () => {
      sel.className = "os-pick " + sel.value;
      const h = HOSTS.find((x) => x.ip === sel.dataset.ip);
      if (h) h.os_family = sel.value;
      // override persistant côté serveur
      fetch("/api/os_override", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: sel.dataset.ip, os_family: sel.value }),
      });
    });
  });
  tbody.querySelectorAll("button.rm").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ip = btn.dataset.ip;
      await fetch("/api/host/" + ip, { method: "DELETE" });
      HOSTS = HOSTS.filter((h) => h.ip !== ip);
      selected.delete(ip); delete credOverride[ip];
      renderTable(); updateSelCount();
    });
  });
  tbody.querySelectorAll("button.creds").forEach((btn) => {
    btn.addEventListener("click", () => {
      const ip = btn.dataset.ip;
      if (ip in credOverride) delete credOverride[ip];
      else credOverride[ip] = { user: "", password: "" };
      renderTable();
    });
  });
  tbody.querySelectorAll(".cred-u").forEach((i) =>
    i.addEventListener("input", () => { credOverride[i.dataset.ip].user = i.value; }));
  tbody.querySelectorAll(".cred-p").forEach((i) =>
    i.addEventListener("input", () => { credOverride[i.dataset.ip].password = i.value; }));
  tbody.querySelectorAll(".cred-clear").forEach((b) =>
    b.addEventListener("click", () => { delete credOverride[b.dataset.ip]; renderTable(); }));
  updateSelCount();
}

$("filter").addEventListener("input", renderTable);
$("check-all").addEventListener("change", (e) => applySelection(e.target.checked ? "all" : "none"));
document.querySelectorAll(".bulk .btn").forEach((b) =>
  b.addEventListener("click", () => applySelection(b.dataset.sel))
);

function applySelection(mode) {
  if (mode === "none") selected.clear();
  else if (mode === "all") HOSTS.forEach((h) => selected.add(h.ip));
  else HOSTS.filter((h) => h.os_family === mode).forEach((h) => selected.add(h.ip));
  renderTable();
}

// Type de déploiement (config Filebeat taillée par type d'OS).
const DEPLOY_BUCKETS = { linux: "Linux/BSD", freebsd: "Linux/BSD", macos: "macOS", windows: "Windows" };
function deployBucket(os) { return DEPLOY_BUCKETS[os] || null; }

function updateSelCount() {
  $("sel-count").textContent = selected.size;
  $("seed-count").textContent = selected.size;
  $("seed-btn").disabled = selected.size === 0;

  const sel = HOSTS.filter((h) => selected.has(h.ip));
  const keyed = sel.filter((h) => h.access === "key").length;
  const nokey = sel.length - keyed;

  // Un seul type d'OS par déploiement (config propre + log lisible).
  const buckets = [...new Set(sel.map((h) => deployBucket(h.os_family)).filter(Boolean))];
  const mixed = buckets.length > 1;
  $("deploy-btn").disabled = selected.size === 0 || mixed;

  const hint = $("ssh-hint");
  if (hint) {
    if (sel.length === 0) hint.textContent = "Sélectionne des machines pour déployer.";
    else if (mixed) hint.innerHTML = `⚠️ Tu mélanges plusieurs types d'OS (${buckets.join(" + ")}). Déploie <strong>un seul type à la fois</strong> — la config Filebeat diffère selon l'OS.`;
    else if (nokey === 0) hint.innerHTML = `✓ ${keyed} machine(s) 🔑 — déploiement par clé.`;
    else hint.innerHTML = `🔑 ${keyed} par clé · <strong>${nokey}</strong> sans clé : sème-les via l'onglet Accès, ou renseigne leur identifiant avec « creds » en partie 2.`;
  }
}

// Hôtes sélectionnés + leurs creds perso éventuels (helper commun seed/deploy)
function chosenHosts() {
  return HOSTS.filter((h) => selected.has(h.ip)).map((h) => {
    const c = credOverride[h.ip] || {};
    return {
      ip: h.ip, hostname: h.hostname, os_family: h.os_family,
      winrm_port: h.winrm_port, appliance: h.appliance, access: h.access,
      cred_user: c.user || "", cred_password: c.password || "",
    };
  });
}

// ------------------------------------------------------------------ DEPLOY
// Modules Filebeat — bloc « avancé » (replié par défaut).
// `system` coché par défaut : il pose event.module=system, ce que beaucoup
// de pipelines Logstash attendent comme condition de routage vers Elasticsearch.
const FB_MODULES = [
  ["system", true], ["auditd", false], ["nginx", false], ["apache", false],
  ["mysql", false], ["postgresql", false], ["redis", false],
  ["traefik", false], ["haproxy", false], ["iptables", false],
];

function addPathRow(value = "") {
  const row = document.createElement("div");
  row.className = "path-row";
  const inp = document.createElement("input");
  inp.type = "text"; inp.value = value; inp.placeholder = "/var/log/monapp/*.log";
  const rm = document.createElement("button");
  rm.type = "button"; rm.className = "rm"; rm.textContent = "×";
  rm.onclick = () => row.remove();
  row.append(inp, rm);
  $("path-list").appendChild(row);
}

function renderFbConfig() {
  const grid = $("module-grid");
  if (grid && !grid.dataset.ready) {
    grid.dataset.ready = "1";
    FB_MODULES.forEach(([val, on]) => {
      const lab = document.createElement("label");
      lab.className = "check";
      lab.innerHTML = `<input type="checkbox" value="${val}" ${on ? "checked" : ""}> ${val}`;
      grid.appendChild(lab);
    });
  }
  const pl = $("path-list");
  if (pl && !pl.dataset.ready) {
    pl.dataset.ready = "1";
    // Liste vide par défaut : syslog/auth.log/messages/secure sont déjà
    // posés par modules.d/system.yml côté Ansible. L'utilisateur ajoute ici
    // uniquement les chemins applicatifs spécifiques (ex: /var/log/mysql/...).
  }
  const addBtn = $("add-path");
  if (addBtn) addBtn.addEventListener("click", () => addPathRow());

  // Presets : charger / enregistrer / supprimer
  $("preset-select").addEventListener("change", (e) => {
    const name = e.target.value;
    if (name && PRESETS[name]) { applyConfig(PRESETS[name]); $("preset-name").value = name; }
  });
  $("preset-save").addEventListener("click", async () => {
    const name = ($("preset-name").value || "").trim();
    if (!name) { $("preset-name").focus(); return; }
    await fetch("/api/presets", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, config: gatherConfig() }),
    });
    await loadPresets();
    $("preset-select").value = name;
  });
  $("preset-del").addEventListener("click", async () => {
    const name = $("preset-select").value;
    if (!name) return;
    await fetch("/api/presets/" + encodeURIComponent(name), { method: "DELETE" });
    $("preset-name").value = "";
    await loadPresets();
  });
  loadPresets();
}

let PRESETS = {};

async function loadPresets() {
  try {
    const data = await (await fetch("/api/presets")).json();
    PRESETS = {};
    (data.presets || []).forEach((p) => { PRESETS[p.name] = p.config; });
    const sel = $("preset-select");
    const current = sel.value;
    sel.innerHTML = `<option value="">— charger un preset —</option>` +
      Object.keys(PRESETS).map((n) => `<option value="${esc(n)}">${esc(n)}</option>`).join("");
    if (PRESETS[current]) sel.value = current;
  } catch (e) { /* pas de presets */ }
}

// Applique une config (preset) aux contrôles de l'UI.
function applyConfig(cfg) {
  cfg = cfg || {};
  const mods = cfg.modules || [];
  document.querySelectorAll("#module-grid input").forEach((c) => { c.checked = mods.includes(c.value); });
  const pl = $("path-list");
  pl.innerHTML = "";
  (cfg.log_paths || []).forEach((p) => addPathRow(p));
  $("client-field").value = cfg.client || "";
}

function gatherConfig() {
  const modules = [...document.querySelectorAll("#module-grid input:checked")].map((c) => c.value);
  const log_paths = [...document.querySelectorAll("#path-list input")]
    .map((i) => i.value.trim()).filter(Boolean);
  const client = ($("client-field").value || "").trim();
  return { modules, log_paths, client };
}

$("deploy-btn").addEventListener("click", async () => {
  const payload = {
    hosts: chosenHosts(),       // identifiants par machine gérés en partie 2 (« creds »)
    config: gatherConfig(),     // modules / chemins / champ client choisis ci-dessus
    dry_run: $("dry-run").checked,
  };
  await launch("/api/deploy", payload, {
    btn: "deploy-btn", console: "console", state: "job-state",
    targets: "job-targets", results: "results", log: "log", running: "déploiement en cours…",
  });
});

// ------------------------------------------------------------------ SEED (clé)
$("seed-btn").addEventListener("click", async () => {
  const payload = {
    hosts: chosenHosts(),
    boot_user: $("boot-user").value, boot_password: $("boot-pass").value,
    lock_bootstrap: $("lock-boot").checked,
  };
  await launch("/api/seed", payload, {
    btn: "seed-btn", console: "seed-console", state: "seed-state",
    targets: "seed-targets", results: "seed-results", log: "seed-log", running: "dépôt de la clé en cours…",
  });
});

$("copy-key").addEventListener("click", () => {
  navigator.clipboard?.writeText($("pubkey").textContent);
  $("copy-key").textContent = "copié ✓";
  setTimeout(() => ($("copy-key").textContent = "copier"), 1500);
});

// Lance un job (deploy ou seed) et branche le suivi sur les éléments fournis.
async function launch(url, payload, ui) {
  $(ui.btn).disabled = true;
  $(ui.console).hidden = false;
  setState(ui.state, "running", "lancement…");
  $(ui.log).textContent = "";
  try {
    const res = await fetch(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) { setState(ui.state, "error", data.error || "erreur"); $(ui.btn).disabled = false; return; }
    pollJob(data.job_id, ui);
  } catch (e) {
    setState(ui.state, "error", e.message);
    $(ui.btn).disabled = false;
  }
}

function pollJob(jobId, ui) {
  const tick = async () => {
    const job = await (await fetch("/api/deploy/" + jobId)).json();
    $(ui.log).textContent = job.log.join("\n");
    $(ui.log).scrollTop = $(ui.log).scrollHeight;
    $(ui.targets).textContent = (job.check ? "[SIMULATION] " : "") + job.targets.length + " cible(s)";
    renderResults(job, ui.results);
    if (job.status === "running") {
      setState(ui.state, "running", ui.running);
      setTimeout(tick, 1200);
    } else {
      setState(ui.state, job.status, summaryLabel(job));
      $(ui.btn).disabled = false;
      loadInventory(false);   // rafraîchit les badges (🔑 / ✓ FB)
    }
  };
  tick();
}

const STATUS_META = {
  ok:          { icon: "✓", cls: "ok",   text: "ok" },
  failed:      { icon: "✗", cls: "err",  text: "échec" },
  unreachable: { icon: "⚠", cls: "err",  text: "injoignable" },
  skipped:     { icon: "–", cls: "skip", text: "ignoré" },
  pending:     { icon: "•", cls: "run",  text: "en cours…" },
};

function renderResults(job, boxId) {
  const box = $(boxId);
  const rows = (job.results && job.results.length)
    ? job.results
    : job.targets.map((ip) => ({ ip, hostname: ip, os_family: "", status: "pending" }));
  box.innerHTML = rows.map((r) => {
    const m = STATUS_META[r.status] || STATUS_META.pending;
    const os = r.os_family ? `<span class="r-os ${r.os_family}">${r.os_family}</span>` : "";
    const host = r.hostname && r.hostname !== r.ip ? r.hostname : "";
    return `<div class="r-row ${m.cls}">
      <span class="r-icon">${m.icon}</span>
      <span class="r-host">${esc(host)}</span>
      <span class="r-ip">${r.ip}</span>
      ${os}
      <span class="r-status">${m.text}</span>
    </div>`;
  }).join("");
}

function summaryLabel(job) {
  const r = job.results || [];
  const ok = r.filter((x) => x.status === "ok").length;
  const ko = r.filter((x) => x.status === "failed" || x.status === "unreachable").length;
  const tag = job.check ? "simulation · " : "";
  if (job.status === "error") return "✗ erreur";
  return `${tag}${ok} ✓ / ${ko} ✗ sur ${r.length}`;
}

function setState(elId, state, text) { const el = $(elId); el.className = state; el.textContent = text; }
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }
