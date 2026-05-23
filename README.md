# filebeat-deploy

Outil d'administration pour **détecter les machines** d'un réseau puis **déployer
Filebeat de façon centralisée**, en choisissant les cibles depuis une **interface web**.

Cible : **Linux** (Debian/RHEL), **Windows** (WinRM/MSI) et **FreeBSD** (pfSense/OPNsense/serveurs BSD).

## Deux façons de l'utiliser

- **Interface web** (`webapp/`) — scan → liste cochable (tout ou à la main) → déploiement, avec log en direct.
- **Ligne de commande** (`detect/discover.py`) — scan → génération d'inventaire → `ansible-playbook`.

## Arborescence

```
filebeat-deploy/
├── ansible.cfg
├── deploy.yml                 # playbook (linux+freebsd, windows)
├── requirements.txt           # deps Python (flask, pyyaml, ansible)
├── requirements.yml           # collections Ansible (community.general, ansible.windows)
├── detect/
│   ├── scanner.py             # moteur de détection (réutilisable)
│   └── discover.py            # CLI scan -> inventaire
├── webapp/
│   ├── app.py                 # backend Flask (API scan/deploy)
│   ├── templates/index.html
│   └── static/{style.css, app.js}
├── inventory/hosts.yml        # généré par le CLI
├── group_vars/all.yml         # destination centrale des logs
└── roles/
    ├── filebeat/              # Linux + FreeBSD
    └── filebeat_windows/      # Windows (MSI + WinRM)
```

## Configuration (.env)

Toute la config vit dans un `.env` (le seul fichier que l'admin renseigne) :

```bash
cp .env.example .env      # puis adapter
```

Variables clés : `FILEBEAT_OUTPUT_HOST` / `FILEBEAT_OUTPUT_TYPE` (votre ELK, connu
d'avance — l'UI le pré-remplit), `FILEBEAT_TLS_ENABLED`, `DEFAULT_CIDRS`,
`DEFAULT_SSH_USER`, `FLASK_HOST` / `FLASK_PORT`. Le `.env` n'est jamais committé
(voir `.gitignore`).

## Lancement en conteneur (recommandé)

```bash
cp .env.example .env
docker compose up -d --build
# -> http://<ip-de-la-box>:5000
```

Le conteneur tourne en **`network_mode: host`** : c'est indispensable pour scanner
le LAN et joindre les hôtes en SSH (un réseau bridge isolerait le conteneur du
réseau local). Les clés SSH de l'admin sont montées en lecture seule (`~/.ssh`) ;
sinon l'auth par mot de passe se fait via l'interface.

### Sous Portainer (stack)

Le compose **n'exige pas** de fichier `.env` (qui est gitignoré, donc absent du
repo). Déploie la stack depuis le repo Git, puis renseigne la config dans la
section **« Environment variables »** de Portainer — au minimum
`FILEBEAT_OUTPUT_HOST` et `BOOTSTRAP_USER`. Les variables non fournies prennent
leurs valeurs par défaut. Inutile de créer un `.env` à la main.

> Le build exécute `ansible-galaxy collection install` : un accès à
> galaxy.ansible.com est requis au moment du build.

## Inventaire de parc persistant

Le résultat des scans est conservé dans un fichier JSON (`INVENTORY_FILE`,
monté en volume `./data`). L'admin retrouve donc **tout son matériel à chaque
ouverture**, sans rescanner. Chaque machine garde :

- son état **en ligne / hors-ligne** (vue ou non au dernier scan — une machine
  éteinte reste dans l'inventaire, elle passe juste hors-ligne) ;
- l'**OS corrigé** à la main (l'override est persistant) ;
- l'indicateur **Filebeat déployé** (coché après un déploiement réussi).

Un re-scan met à jour les machines vues et ajoute les nouvelles. Le bouton `×`
retire une machine décommissionnée de l'inventaire.

## Accès par clé SSH (panneau « Accès »)

Plutôt qu'un mot de passe commun à tout le parc (faille notable), l'accès se fait
par **clé SSH** :

1. La console génère **une paire de clés** (stockée dans le volume `data/`).
2. Le panneau « Accès » dépose la clé publique sur les machines cochées via leur
   **compte admin existant** (mot de passe saisi **une fois**, jamais stocké),
   en créant un **compte d'automation dédié** (`filebeat-deploy`) à login par clé.
3. Ensuite, tous les déploiements se font **à la clé, sans mot de passe**.

Pourquoi une seule clé console et pas une par machine : une clé SSH est asymétrique
— la **clé privée ne quitte jamais la console**, les machines ne stockent que la
clé publique. Compromettre une machine ne permet donc pas de rebondir sur les
autres (contrairement à un mot de passe partagé). Une clé par machine n'apporterait
quasi rien pour beaucoup d'overhead.

L'inventaire affiche **🔑** quand l'accès par clé est en place. Option
« verrouiller le compte bootstrap » pour fermer la porte d'origine après seeding.

**Identifiants : un général, des exceptions.** Le compte admin commun au parc est
défini dans le `.env` (`BOOTSTRAP_USER` / `BOOTSTRAP_PASSWORD`) et pré-rempli dans
l'UI. Pour les machines qui n'ont pas ce compte, le bouton **« creds »** sur la
ligne permet de saisir un identifiant spécifique à cette machine (utilisé en
priorité). Pratique pour le workflow « je sème tout le parc d'un coup, puis je
reprends à la main les 2-3 postes qui ont échoué ». Les mots de passe perso ne
sont **jamais persistés** (saisis au runtime, en mémoire navigateur uniquement).

> **Linux / FreeBSD** : natif. **Windows** : nécessite d'activer le serveur OpenSSH
> intégré (étape documentée à part) ; on retombe alors sur le même flux clé.
> Limite assumée : Ansible `become` s'exécute en root, donc le `sudo`/`doas` du
> compte dédié est en NOPASSWD — le durcissement repose sur le login par clé, le
> compte dédié et le verrouillage du compte bootstrap.

## Installation manuelle (sans Docker)

```bash
pip install -r requirements.txt
ansible-galaxy collection install -r requirements.yml
cp .env.example .env
```

## Interface web

```bash
cd webapp
python3 app.py
# -> http://127.0.0.1:5000
```

Workflow :
1. **01 Détection** — saisis tes CIDR (un par ligne), lance le scan.
2. **02 Sélection** — coche les machines : boutons *tout / aucun / linux / windows / freebsd*,
   ou case par case. L'OS détecté peut être **corrigé à la main** (menu déroulant par ligne).
3. **03 Déploiement** — règle la sortie (Logstash/ES + hôte:port), l'utilisateur SSH
   (et les identifiants Windows si besoin), coche éventuellement *simulation (--check)*,
   puis **Déployer**. Le log Ansible s'affiche en direct.

## Ligne de commande

```bash
cd detect
python3 discover.py --cidr 192.168.1.0/24 --logstash 10.0.0.10:5044 --out ../inventory/hosts.yml
cd ..
ansible-playbook deploy.yml --check     # dry-run
ansible-playbook deploy.yml
```

## Détection des OS

| Signal réseau                         | OS détecté | Connexion Ansible |
|---------------------------------------|------------|-------------------|
| WinRM (5985/5986)                     | windows    | winrm             |
| RDP seul (3389)                       | windows    | winrm             |
| SSH (22) + bannière `FreeBSD/OPNsense`| freebsd    | ssh               |
| SSH (22) autre                        | linux      | ssh               |
| rien d'identifiable                   | unknown    | (non déployé)     |

La détection FreeBSD lit la **bannière SSH** (ex. `SSH-2.0-OpenSSH_8.8 FreeBSD-...`),
ce qui permet de repérer pfSense/OPNsense.

## ⚠️ Pare-feu pfSense / OPNsense (appliances)

Installer Filebeat via `pkg` sur une appliance n'est **pas** recommandé (système verrouillé,
système de plugins propre). Pour ces équipements, la bonne pratique est de configurer leur
**syslog distant** vers Logstash/ELK plutôt que d'y pousser un agent. Le rôle FreeBSD
**refuse volontairement** l'installation quand il détecte une appliance pfSense/OPNsense
(voir `roles/filebeat/tasks/install-freebsd.yml`). Sur du **FreeBSD serveur** classique,
l'installation via `pkgng` fonctionne normalement.

## Prérequis par cible

- **Linux** : accès SSH, `sudo` (mot de passe demandé dans l'UI si nécessaire).
- **FreeBSD** : accès SSH, dépôt `pkg` joignable. Collection `community.general`.
- **Windows** : WinRM activé, `pip install pywinrm` sur le contrôleur, collection `ansible.windows`.

## Sécurité

- Outil **local** : `app.py` écoute sur `127.0.0.1` uniquement. Ne l'expose pas sur un réseau
  ouvert (il scanne et lance Ansible).
- Les identifiants saisis servent à générer un inventaire temporaire en `0600`, **supprimé**
  après le déploiement. En usage régulier, préfère un **Ansible Vault** + clés SSH.
