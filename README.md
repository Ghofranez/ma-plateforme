# Mon projet : pipeline DevSecOps
Ce projet est une application web composée d’un frontend React, d’un backend FastAPI, et d’une base de données MySQL, entièrement containerisés avec Docker.

J’ai intégré un pipeline CI/CD complet avec GitHub Actions, incluant de nombreux outils de sécurité pour automatiser l'analyse, le build et le déploiement.

# Sommaire
 1- Objectifs du projet

 2- Technologies utilisées

 3- Outils DevSecOps intégrés

 4- Structure du projet

 5- Prérequis

 6- Lancer le pojet en local

 7- Pipelie CI/CD

 8- Configuration des outils DevSecOps

 9- Secrets GitHub requis

 10- Infrastructure de déploiment

1. Objectif du projet:
- Ce projet vise à mettre en place un pipeline DevSecOps complet comprenant :

* Une application web containerisée :
React (frontend) + FastAPI (backend) + MySQL
* Un pipeline CI avec :
analyses de sécurité, qualité, SBOM, signatures d’images
* Un pipeline CD pour déployer automatiquement l’application sur un runner self-hosted
* Intégration d’outils spécialisés :
Gitleaks, Checkov, Conftest, SonarCloud, Trivy, ZAP, Falco, Snyk, Cosign…

2. Technologie utilisées
* Application:
 - Fronend: React (react@19.2.4)
 - Backend: FastAPI (Python 3.12.3)
 - Base de données: MySQL (Ver 8.0.45)
* Infrastructure:
 - Docker (version 29.3.0)
 -  Docker Compose (v5.1.0)
 - Github Actions
 - Nginx (reverse proxy)

3. Outils DevSecOps intégrés
* CI (analyse avant exécution):
 - Gitleaks — détection de secrets
 - Checkov — analyse de sécurité des configurations
 - Conftest — règles Rego personnalisées
 - SonarCloud — qualité + sécurité du code
 - Syft (Anchore) — génération SBOM
 - Cosign — signature cryptographique des images
 - Snyk — scan des dépendances
 - Trivy — scan des images Docker
* CD (analyse en environnement réel):
 - Cosign — vérification des signatures d’images
 - OWASP ZAP — scan DAST
 - Falco — détection comportementale en temps réel

4. Structure de projet:
devsecops-react/

├── .github/

│   └── workflows/

│       ├── CI.yml              # Pipeline de tests et sécurité

│       └── CD.yml              # Pipeline de déploiement

├── backend/

|   ├── tests/

│   ├── dockerfile

│   ├── requirements.txt

│   └── main.py

├── frontend/

│   ├── tests/

│   ├── Dockerfile

│   ├── package.json

│   └── src/

├── policy/                     # Règles Conftest (Rego)

├── .checkov.yaml               # Configuration Checkov

├── .gitleaks.toml              # Configuration Gitleaks

├── sonar-project.properties    # Configuration SonarCloud

├── docker-compose.yml

├── .env.example

└── README.md

5. Prerequis
Avant de lancer le projet en local, les outils suivants doivent etre installes sur la machine :
* Git — pour cloner le depot
* Docker Desktop (Windows / macOS) ou Docker Engine + Docker Compose plugin (Linux)
* Un compte GitHub — pour utiliser GitHub Actions et GHCR


6. Lancer le projet en local
1- Cloner le dépot:
- git clone https://github.com/Ghofranez/pipeline-test.git
- cd pipeline-test
2- Créer le fichier .env
- Copier le contenu de .env.example puis ajuster.

3- Lancer Docker Compose:

docker compose up --build

4- Accès à l'application

> Frontend      -> http://localhost:3000

> Backend (API) -> http://localhost:8000

6- Pour arreter :

docker compose down

7. Pipeline CI/CD
- CI — Continuous Integration:

Déclenché à chaque push sur master.
Étapes exécutées dans l’ordre :

1- Scan de secrets — Gitleaks
2- Analyse sécurité config — Checkov
3- Règles Rego — Conftest
4- Qualité du code — SonarCloud
5- Build & push des images Docker vers GHCR
6- Géneration du SBOM (Software Bill of Materials) avec Anchore Syft
7- Signature cryptographique des images — Cosign
8- Scan dépendances — Snyk
9- Scan images — Trivy

- CD — Continuous Deployment:

Étapes :

1- Checkout du code
2- Vérification des signatures Cosign
3- Déploiement via Docker Compose
4- Health check de l’API
5- Scan DAST — OWASP ZAP
6- Analyse des alertes Falco
7- Vérification des conteneurs
8- Rollback automatique en cas d’erreur
9- Notification finale
Il suffit d'ajouter ce step dans le fichier CI.yml

8. Configurations des outils
Cette section décrit la configuration nécessaire pour chaque outil utilisé dans les pipelines CI/CD.

- Checkov — Sécurité des fichiers Docker et de configuration:

Checkov analyse les Dockerfiles et fichiers de configuration pour détecter des mauvaises pratiques (ex. : conteneur exécuté en root, ports sensibles exposés).

Configuration:

* Créer un fichier .checkov.yaml à la racine du projet.  # Ce fichier définit les chemins à scanner et les règles activées/désactivées.

Pipleline:

* Ajouter le step Checkov dans le fichier CI.yml.


- Conftest — Règles de sécurité personnalisées

Conftest permet de valider les Dockerfiles et autres fichiers via des règles personnalisées écrites en Rego (ex. : interdire l’usage de latest, exiger un HEALTHCHECK, etc.).

Configuration:

* Stocker les règles dans le dossier policy/ au format .rego.

Pipeline:

* Ajouter le step Conftest dans CI.yml

- SonarCloud — Qualité et sécurité du code source

SonarCloud analyse le code pour détecter bugs, vulnérabilités et problèmes de qualité.

Configuration :

1- Se connecter à https://sonarcloud.io
 via GitHub.

2- Aller dans Analyze new project → sélectionner le dépôt.

3- Créer manuellement le projet.

4- Désactiver Automatic Analysis dans Administration → Analysis Method.

5- Copier le token généré et l’ajouter dans GitHub Secrets sous SONAR_TOKEN.

6- Créer le fichier sonar-project.properties à la racine du projet.

> Remarque: Le projet doit exister sur SonarCloud avant d'exécuter le pipeline.

Pipeline:

 * Ajouter le step Sonar dans CI.yml.

- GHCR (GitHub Container Registry) — Stockage des images Docker

Le pipeline construit et pousse les images Docker vers GHCR.

Configuration:

* Ajouter la permission :
 permissions:
  packages: write

* Utiliser les noms d’images en minuscules (obligatoire pour GHCR).

Pipeline:

* Ajouter les steps de build et push dans CI.yml.

- SBOM (Software Bill of Materials) — Inventaire des composants

Généré avec Anchore Syft, le SBOM liste toutes les dépendances présentes dans l’application.

Pipeline:

* Ajouter le step Syft dans CI.yml.

- Cosign — Signature des images Docker

Cosign signe les images Docker pour garantir leur intégrité.

Configuration locale (à faire une seule fois) : cosign generate-key-pair

> Cela génère :
> - cosign.key → clé privée (signature)
> - cosign.pub → clé publique (vérification)

Secrets GitHub à ajouter :

COSIGN_KEY → contenu de cosign.key

COSIGN_PUBLIC_KEY → contenu de cosign.pub

Pipeline:

* Ajouter:
  un step Cosign sign dans CI.yml

  un step Cosign verify dans CD.yml

- Snyk — Analyse des dépendances

Snyk détecte les vulnérabilités présentes dans les dépendances du projet.

Configuration :

1- Se connecter sur https://app.snyk.io

2- Récupérer l’Auth Token dans Account Settings

3- Ajouter le token dans GitHub Secrets → SNYK_TOKEN

> Remarques:

> - Toujours spécifier --file= pour cibler le fichier dépendances.
> - Pour Python, ajouter --skip-unresolved si les dépendances ne sont pas installées sur le runner

Pipeline:

* Ajouter le step Snyk dans CI.yml.

- Cosign (CD) — Signature (CI) & Vérification (CD)

L’utilisation de Cosign dans la pipeline permet de garantir que seules les images construites et signées en CI peuvent être déployées en CD.

Configuration :

* La clé privé Cosign (cosign.key) dot etre ajoutée dans: COSIGN_KEY (GitHub Secrets)

* La clé publique Cosign (cosign.pub) doit être ajoutée dans : COSIGN_PUBLIC_KEY (GitHub Secrets)

Pipeline :

* ntégrer une étape Cosign sign dans CI.yml pour signer l’image publiée.

* Intégrer une étape Cosign verify dans CD.yml pour valider la signature avant le déploiement.

- OWASP ZAP — Analyse DAST

OWASP ZAP analyse l'application déployée en simulant des attaques (injection, XSS, config HTTP faible, etc.).

Configuration :

* Aucune configuration locale ni secret.

* Utilise directement l’image Docker officielle.

Pipeline:

* Ajouter le step ZAP dans CD.yml.

- Falco — Surveillance comportementale du serveur

Falco surveille le comportement des conteneurs en temps réel (accès anormaux, commandes suspectes, etc.).

Configuration:

* Falco doit être installé manuellement sur la VM Ubuntu (il tourne en permanence).

* Il n’est pas exécuté par GitHub Actions : le pipeline ne fait que lire ses alertes.

Pipeline:

* Ajouter un step dans CD.yml qui récupère les alertes Falco récentes.

9. Secrets GitHub nécessaires

- Tous les secrets se configurent dans : GitHub → votre repo → Settings → Secrets and variables → Actions → New repository secret

* SONAR_TOKEN : généré sur SonarCloud → Account Settings → Security → Generate Token
> Utilisé dans le CI pour permettre à SonarCloud d'analyser la qualité et la sécurité du code.

* SNYK_TOKEN : disponible sur app.snyk.io → Account Settings → Auth Token
> Utilisé dans le CI pour permettre à Snyk de scanner les vulnérabilités des dépendances.

* COSIGN_KEY : contenu du fichier cosign.key généré avec cosign generate-key-pair
> Utilisée dans le CI pour signer les images Docker après leur création.

* COSIGN_PUBLIC_KEY : contenu du fichier cosign.pub généré avec cosign generate-key-pair.
> Utilisée dans le CD pour vérifier que les images Docker ont bien été signées pendant le CI avant de les déployer.

* GITHUB_TOKEN : fourni automatiquement par GitHub Actions, rien à faire
> Utilisé pour pousser les images Docker vers GHCR et accéder aux ressources du repo pendant le pipeline.

10. Lancement automatiques des pipelines (CI/CD):

- À chaque git push, les pipelines se déclenchent automatiquement. Vous pouvez suivre l'exécution dans l'onglet Actions du repo GitHub.

> git push → CI (tests + build) → CD (déploiement automatique):
- creation de repository sur GitHub (manuellement)

git  init

git add .                           #  sélectionne tous les fichiers modifiés pour les
préparer à être sauvegardés

git commit -m ""                    # sauvegarde les fichiers sélectionnés avec un message
qui décrit ce que tu as fait

git remote add origin https://github.com/Ghofranez/pipeline-test.git

git branch -M master

git branch                          # Vérifier le nom du branche

git push -u origin $nomdubranche    # envoie tes sauvegardes locales vers GitHub sur la branche choisie

11. Infrastructure de déploiement
Pour le déploiement, j'utilise une machine virtuelle Ubuntu Server sur VirtualBox sur laquelle tourne à la fois le runner GitHub Actions (self-hosted) et le serveur Nginx.

Pourquoi un runner self-hosted ?
Ma VM est en local sur VirtualBox, donc GitHub ne peut pas y accéder directement. Le runner est installé sur la VM pour qu'il écoute GitHub et exécute le déploiement de mon côté.

> Voici toutes les étapes que j'ai suivies pour tout configurer :

1- Préparer la VM Ubuntu:Mettre à jour le système et installer les outils de base (curl, git)

2- Installer Docker et docker compose:

Docker est nécessaire pour lancer les containers de l'application sur le serveur

3- Configurer le runnerself-hosted GitHub Actions et lancer le runner en tant que service:

Le runner self-hosted permet à GitHub Actions de lancer le déploiement directement sur ma VM .

> J'ai utilisé un runner self-hosted parce que ma VM est en local sur VirtualBox, donc GitHub ne peut pas y accéder directement. Le runner est installé sur la VM pour qu'il écoute GitHub et exécute le déploiement de mon côté.

4- Installer et configurer Nginx:

Nginx comme reverse proxy : il reçoit les requêtes et les redirige vers le bon service (React sur le port 3000 ou FastAPI sur le port 8000).

> Avec la redirection du port :
> Fronend: http://127.0.0.1:8080
> Backend: http://127.0.0.1:8000

5- Installer Falco : un outil qui surveille le comportement des containers en temps réel (accès fichiers suspects, commandes inhabituelles, etc.).

Schéma de flux :

git push → CI → CD → Déploiement sur VM → Application en ligne