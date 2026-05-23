# Console de déploiement Filebeat — image conteneur.
FROM python:3.12-slim

# Outils requis pour qu'Ansible joigne les machines :
#   openssh-client : connexions SSH (Linux/FreeBSD)
#   sshpass        : auth SSH par mot de passe (si pas de clé)
#   iputils-ping   : ping ICMP pour le scan (sinon fallback TCP)
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client sshpass iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dépendances Python + collections Ansible
COPY requirements.txt requirements.yml ./
RUN pip install --no-cache-dir -r requirements.txt
# Collections : community.general (FreeBSD/pkgng) + ansible.windows (WinRM)
# Nécessite un accès à galaxy.ansible.com au moment du build.
RUN ansible-galaxy collection install -r requirements.yml

# Code de l'appli
COPY . .

EXPOSE 5000
WORKDIR /app/webapp
CMD ["python", "app.py"]
