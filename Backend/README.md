# Backend - Ma Plateforme (FastAPI)

## Présentation du projet

Ce projet a été réalisé dans le cadre de mes études pour apprendre
à construire une API professionnelle avec FastAPI.

J'ai choisi d'implémenter une **Clean Architecture** pour bien séparer
les responsabilités et produire un code maintenable et organisé.

## Technologies utilisées

**FastAPI**      : Framework API rapide et moderne
**Python 3.12**  : Langage principal
**Pydantic**     : Validation des données entrantes
**SQLAlchemy**   : ORM pour la base de données
**MySQL**        : Base de données relationnelle
**Uvicorn**      : Serveur ASGI pour lancer l'API
**Pytest**       : Tests unitaires et d'intégration
**JWT + OTP**    : Authentification sécurisée

## Prérequis

**Python**         : 3.12+ : `python3 --version`
**Docker**         : 29.3+ : `docker --version`
**Docker Compose** : v5.1+ : `docker compose version`
**Git**            : 2.53+ : `git --version`

## Variables d'environnement requises

- Créer un fichier `.env` à la racine du projet Backend :

- Base de données:
DATABASE_URL=mysql+mysqlconnector://user:password@localhost:3306/db_name
MYSQL_ROOT_PASSWORD=ton_root_password
MYSQL_DATABASE=nom_de_ta_db
MYSQL_USER=ton_user
MYSQL_PASSWORD=ton_password
PHPMYADMIN_PORT=port
BACKEND_PORT=port_de_backend
FRONTEND_PORT=port_de_frontend

- Sécurité JWT:
SECRET_KEY=une_cle_secrete_longue_et_aleatoire

- Email SMTP (Gmail):
SMTP_EMAIL=ton.email@gmail.com
SMTP_PASSWORD=mot_de_passe_application_gmail

- Redis:
REDIS_URL=redis//urlderedis/port

- Outils de scan:
VIRUSTOTAL_KEY=api_de_virustotal
GOOGLE_SAFE_BROWSING_KEY=api_de_google_safe_browsing
URLSCAN__KEY=api_de_urlscan.io
ZAP_API_KEY=api_de_owspzap
ZAP_BASE_URL=url_de_owaspzap
ZAP_PORT=port_de_owaspzap



** Remarque :

> `SMTP_PASSWORD` n'est pas ton mot de passe Gmail normal.:
1- Il faut générer un **mot de passe d'application** depuis :

2- `Google Account → Sécurité → Mots de passe des applications`

> Générer une SECRET_KEY: openssl rand -hex 32 (dans cmd)

> Pour clé API de Virustotal : depuis le site officiel → https://www.virustotal.com/gui/home/upload (aprés s'inscrire)

> Google safe browsing clé API : suivre ces étapes:
 1-sur console.cloud.google.com: Connecte avec ton compte Google

 2- Clique sur "Nouveau projet" → "Créer"

 3- Activer l'API Safe Browsing: Dans le panneau gauche, va dans "APIs & Services" → "Bibliothèque",
 recherche "Safe Browsing API", clique dessus puis sur "Activer".

 4- Créer la clé API: dans "APIs & Services" → "Identifiants", clique sur "Créer des identifiants" et sélectionne "Clé API".

 5- dans credentiels à gauche pour afficher clé .

> Urlscan  clé API: dans sur officiel :https://urlscan.io/ (aprés inscription)
  - clique sur nom_utilisateur → settings & API → afficher le clé

> OWASPZAP clé API générer avec la commende : openssl rand -hex 32

> Pour nuclei il faut cloner les templates :
 1- git clone --depth=1 https://github.com/projectdiscovery/nuclei-templates.git
 2- aprés lancement de docker compose vérifer existance des templates:
  docker exec ma-plateforme-worker-1 ls /home/celeryuser/nuclei-templates
!! vérifier nom de contenaire par : docker ps
!! dans mon cas c'esr ma-plateforme-worker-1

## Architecture du projet
J'ai structuré le backend selon les principes de la **Clean Architecture**
pour séparer clairement chaque responsabilité :

Backend/
├── app/
│   ├── core/                  # Configuration et sécurité (JWT, hash)
│   ├── domain/
│   │   └── use_cases/         # Logique métier (register, login, analyse...)
│   ├── infrastructure/
│   │   ├── db/                # Connexion base de données
│   │   └── repositories/      # Requêtes SQL (User, Analysis)
│   ├── interface/
│   │   └── routes/            # Endpoints API (auth, profil, analyse)
│   ├── application/
│   │   ├── dto/               # Schémas de validation (Pydantic)
│   │   └── services/          # Services (email, OTP, scanner)
           └── tools/          # Tools de scanne (security-headers,ssllabs,virustotal,google-safe-browsing,urlscan.io,Shodan internet DB,wappalyzer,owaspzap et nuclei)
│   └── middleware/            # Protection des routes (token JWT)
├── conftest.py                # Configuration des tests
├── pytest.ini                 # Paramètres pytest
├── requirements.txt           # Dépendances Python
└── dockerfile                 # Image Docker du backend

* REMARQUE: On utilise .venv (environement virtuel pour fastapi ) :Pour isoler les dépendances du projet (FastAPI, uvicorn, etc.) du Python système, évitant ainsi les conflits entre différents projets sur la même machine.

##  Détail des couches

### Core

Contient la configuration globale (`config.py`) et la sécurité
(`security.py`) — hash des mots de passe, création et décodage
des tokens JWT.

### Domain — Logique métier

C'est le cœur de l'application. Contient les règles métier
indépendantes de la base de données ou du framework :
- `auth_cases.py` → register, login, reset mot de passe
- `analysis_cases.py` → lancer un scan d'URL

### Infrastructure — Accès aux données

Gère toutes les interactions avec MySQL via SQLAlchemy :
- `session.py`        → Connexion au base de données
- `user_repo.py`      → opérations sur les utilisateurs
- `analysis_repo.py`  → sauvegarde et récupération des analyses

### Interface — Routes API

Définit tous les endpoints HTTP appelés par le frontend :
- `auth.py` → authentification et gestion des mots de passe
- `profile.py` → consultation et modification du profil
- `analysis.py` → analyse d'URL et historique


### Application — Services

- `email.py`   → envoi des codes OTP par email (Gmail SMTP)
- `otp.py`     → génération et vérification des codes à 6 chiffres
- `scanner.py` → intégration des outils de sécurité externes

### Application — Tools

- `security_headers.py` →analyse les entetes HTTP (x_frame,CSP..)

- `ssl_labs.py` → analyse qualité SSL/Tls (certificat,chiffrement)

- `virustotal.py` → vérifie si domaine/url/ip est malveillant

- `safe_browsing.py` → vérifie l'url si existe dans listes noirs de google

- `urlscan.py` → analyse le comportemant en navigation

- `shodan.py` → sanne l'infrastructure du serveur qui héberge le site

- `wappalyzer.py` → détecte les technologies utilisées par le site

- `zap_scan.py` → détecte les vulnérabilités web

-`nuclei.py` → détecte les failles (+3000 templates CVE)


### Middleware

- `auth_middleware.py` → Protection des routes sensibles — vérifie le cookie JWT
à chaque requête entrante.


## Installation locale

- Cloner le projet
git clone https://github.com/Ghofranez/ma-plateforme
cd Backend

-  Créer l'environnement virtuel
python -m venv .venv
source .venv/bin/activate

- Installer les dépendances
pip install -r requirements.txt

- Configurer les variables d'environnement
cp .env.example .env

- Remplir les valeurs dans .env


##  Lancer le serveur

uvicorn app.main:app --reload

Accès :

* API principale → http://127.0.0.1:8000
* Documentation Swagger  → http://127.0.0.1:8000/docs

##   Docker

- créer .env.docker comme env.docker.exemple:

── MySQL ──────────────────────────────────────
MYSQL_ROOT_PASSWORD=your_root_password
MYSQL_DATABASE=your_db_name
MYSQL_USER=your_db_user
MYSQL_PASSWORD=your_db_password

 ── Ports ──────────────────────────────────────
BACKEND_PORT=port_backend
FRONTEND_PORT=port_frontend
PHPMYADMIN_HOST_BINDING=Port_phpmyadmin
ZAP_PORT=Port_zap

 ── Sécurité ───────────────────────────────────
Générer avec : openssl rand -hex 32
SECRET_KEY=ton_jwt_secret_key
ZAP_API_KEY=ton_zap_api_key

── SMTP ───────────────────────────────────────
SMTP_EMAIL=ton@email.com
SMTP_PASSWORD=ton_smtp_password

── APIs de sécurité ───────────────────────────

VIRUSTOTAL_KEY=ton_virustotal_api_key
GOOGLE_SAFE_BROWSING_KEY=ton_google_safe_browsing_key
URLSCAN_API_KEY=ton_urlscan_api_key

── Redis / Celery ─────────────────────────────
REDIS_URL=redis://redis:6379/0

> cp .env.docker.example .env.docker

- Lancer avec Docker Compose (sous dossier ma-plateforme)

 docker compose --env-file .env.docker up --build

** Remarque:
 - .env c'est pour local et .env.docker c'est pour docker il ya des variables différents comme (redis_url,)
- Services disponibles:

 Frontend   → http://localhost:3000
 Backend    → http://localhost:8000
 phpMyAdmin → http://localhost:8080


## Tests

pytest app/tests/ -v

- Structure des tests :

app/tests/
├── unit/
│   ├── test_security.py    # tests hash + JWT
│   └── test_otp.py         # tests génération codes OTP
└── integration/
└── test_auth.py           # tests endpoints register/login

## Fonctionnalités

* Authentification avec **2FA par email** (code OTP)
* Gestion des tokens **JWT stockés en cookie HttpOnly**
* Gestion du profil utilisateur
* Réinitialisation du mot de passe par email
* Analyse d'URLs avec outils de sécurité
* Historique des analyses par utilisateur
* Envoi d'emails automatique via Gmail SMTP

## Conclusion

Ce projet m'a permis de découvrir et pratiquer :

- La **Clean Architecture** et la séparation des responsabilités
- La conception d'**APIs REST professionnelles** avec FastAPI
- La sécurité applicative : **JWT, bcrypt, 2FA, cookies HttpOnly**
- Les **tests automatisés** avec pytest
