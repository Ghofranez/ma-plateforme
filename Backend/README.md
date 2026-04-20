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

- Sécurité JWT:
SECRET_KEY=une_cle_secrete_longue_et_aleatoire
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

- Email SMTP (Gmail):
SMTP_EMAIL=ton.email@gmail.com
SMTP_PASSWORD=mot_de_passe_application_gmail

** Remarque :
> `SMTP_PASSWORD` n'est pas ton mot de passe Gmail normal.
> Il faut générer un **mot de passe d'application** depuis :
> `Google Account → Sécurité → Mots de passe des applications`
> Générer une SECRET_KEY: openssl rand -hex 32 (dans cmd)


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

##  Docker

-  Lancer avec Docker Compose (dev local):

docker compose up --build

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
- La **conteneurisation** avec Docker et Docker Compose
- Le **pipeline CI/CD** avec GitHub Actions