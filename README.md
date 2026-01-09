API d'Authentification Sécurisée - TP Node.js
Ce projet est une solution complète d'authentification et de gestion d'utilisateurs construite avec Node.js, Express, Prisma (SQLite) et JWT. Il implémente les meilleures pratiques de sécurité modernes.

🚀 Fonctionnalités Clés
Gestion du cycle de vie : Inscription, Confirmation de compte par jeton, Suppression de compte avec nettoyage en cascade.

Sécurité Avancée :

Authentification à deux facteurs (2FA) via TOTP.

Gestion des sessions multiples et révocation à distance.

Blacklistage des Refresh Tokens pour une déconnexion sécurisée.

Protection contre le brute-force via l'historique de connexion.

OAuth : Simulation de flux d'authentification sociale (Google/Github).

🛠️ Installation
Cloner le dépôt et installer les dépendances :

Bash

npm install
Configurer l'environnement : Créez un fichier .env à la racine et ajoutez vos secrets :

Extrait de code

DATABASE_URL="file:./dev.db"
JWT_SECRET="votre_secret_access_token"
REFRESH_SECRET="votre_secret_refresh_token"
Initialiser la base de données :

Bash

npx prisma db push
npx prisma generate
Lancer le serveur :

Bash

npm run dev
🧪 Guide de Test (Yaak)
Une collection complète de tests est fournie pour valider l'API. Voici l'ordre recommandé pour tester le flux complet :

01. Inscription : Crée l'utilisateur. Récupérez le verificationToken dans la réponse JSON.

02. Confirmation Compte : Utilisez le token pour activer le compte.

03. Connexion : Obtenez vos tokens JWT.

04. Profil : Accédez à vos données protégées.

05. 2FA (Optionnel) :

Générez le secret, validez-le pour l'activer.

Testez ensuite la désactivation pour vérifier le nettoyage en base.

06. Suppression : Utilisez la route DELETE /me pour tester la suppression en cascade (Sessions, Historique, User).

📂 Structure du Projet
src/services/ : Logique métier et interactions Prisma.

src/controllers/ : Gestion des requêtes et réponses HTTP.

src/routes/ : Définition des points d'entrée de l'API.

src/middlewares/ : Protections (Auth, Blacklist, Guards).

prisma/ : Schéma de la base de données SQLite.