# Ma Plateforme — Frontend (React + Vite)
## Présentation du projet

Ce frontend a été développé dans le cadre de mes études pour créer
une interface utilisateur moderne et sécurisée.

J'ai utilisé **React avec Vite** pour la rapidité de développement,
et **TypeScript** pour la robustesse du code.

## Technologies utilisées

**React**
**TypeScript**       : Typage statique pour plus de robustesse
**Vite**             : Bundler ultra-rapide
**Tailwind CSS**     : Styles utilitaires
**Axios**            : Appels API vers le backend
**React Router DOM** : Navigation entre les pages
**Framer Motion**    : Animations fluides
**Shadcn/UI**        : Composants UI réutilisables
**React Hot Toast**  : Notifications utilisateur
**Lucide React**     : Icônes modernes
**Vitest**           : Tests unitaires
**Nginx**            : Serveur web en production

## Prérequis

**Node.js** : 20.20.2  : `node --version`
**npm**     : 10.8.2   : `npm --version`
**Docker**  : 29.3.0   : `docker --version`
**Git**     : 2.53.0   : `git --version`

## Structure du projet

Frontend/
├── src/
│   ├── api/
│   │   └── api.ts                  # Configuration Axios + intercepteurs
│   ├── services/
│   │   └── auth.service.ts         # Appels API backend
│   ├── pages/
│   │   ├── Loginpage/              # Page de connexion
│   │   ├── Registerpage/           # Page d'inscription
│   │   ├── Vérificationemail/      # Page OTP 2FA
│   │   ├── Motdepasseoublie/       # Page mot de passe oublié
│   │   ├── Verificationmdp/        # Vérification code reset
│   │   ├── Réinitialisermdp/       # Nouveau mot de passe
│   │   ├── Accueilpage/            # Page principale analyse URL
│   │   ├── Historique/             # Historique des analyses
│   │   ├── Profil/                 # Profil utilisateur
│   │   └── Sidebar/                # Navigation latérale
│   ├── components/
│   │   └── ui/                     # Composants réutilisables
│   └── tests/
│       └── basic.test.ts           # Tests unitaires
├── public/                         # Assets statiques
├── vite.config.ts                  # Configuration Vite
├── vitest.config.ts                # Configuration Vitest
├── tailwind.config.ts              # Configuration Tailwind
├── tsconfig.json                   # Configuration TypeScript
├── package.json                    # Dépendances
└── Dockerfile                      # Image Docker production


## Pages de l'application

### Authentification
- **Login** → Connexion avec email + mot de passe
- **Register** → Création de compte avec validation
- **Vérification email** → Code OTP à 6 chiffres (2FA)

###  Mot de passe oublié
- **Mot de passe oublié** → Saisie de l'email
- **Vérification code** → Code OTP de reset
- **Réinitialisation** → Nouveau mot de passe

### Application principale
- **Accueil** → Analyse d'URL avec outils de sécurité
- **Historique** → Liste des analyses passées
- **Profil** → Modification des informations personnelles

## Fonctionnement
### Sécurité — Token JWT en Cookie HttpOnly

1- Login réussi
2- Backend génère un token JWT
3- Token stocké dans un cookie HttpOnly
4- JavaScript ne peut PAS lire le cookie
5- Protection contre les attaques XSS

### Appels API — Axios

```typescript
// api.ts — transporteur entre frontend et backend
export const api = axios.create({
  baseURL: "http://localhost:8000",
  withCredentials: true,  // envoie les cookies automatiquement
});
```

### Installation locale

- Cloner le projet
git clone https://github.com/Ghofranez/ma-plateforme
cd Frontend

- Installer les dépendances
npm install

- Lancer en développement
npm run dev

- Accées :

 Application React (dev): `http://localhost:5173`

 Docker


- Lancer avec Docker Compose (dev local)

cd ..

docker compose up --build -d

- Services disponibles:

 Frontend  → http://localhost:3000
 Backend   → http://localhost:8000
 phpMyAdmin → http://localhost:8080

### Tests

- Lancer les tests : npx vitest run

- Avec coverage : npx vitest run --coverage

### Fonctionnalités implémentées

- **Authentification 2FA** : avec code OTP par email
- **Cookie HttpOnly**      : pour sécuriser le token JWT
- **Gestion du profil**    : modifier nom, prénom, mot de passe
- **Analyse d'URL**        : soumettre des URLs à analyser
- **Historique**           : consulter les analyses passées
- **Reset mot de passe**   : par email
- **Interface responsive** : avec Tailwind CSS
- **Animations**           : avec Framer Motion

### Conclusion

Ce projet m'a permis de pratiquer :

- Le développement d'interfaces avec **React + TypeScript**
- La sécurisation des appels API avec **Axios + cookies HttpOnly**
- La gestion des **formulaires avec validation**
- L'intégration d'une **authentification 2FA**
- La **containerisation** avec Docker et Nginx
- Les **tests** avec Vitest
- Le **pipeline CI/CD** avec GitHub Actions