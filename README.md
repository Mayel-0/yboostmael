# YCuisine 🍽️

Application web de découverte de recettes, avec authentification utilisateur, favoris, commentaires et gestion de liste de courses.

## 🎯 Présentation du projet

YCuisine permet à un utilisateur de :

- parcourir des recettes via l’API publique TheMealDB,
- consulter le détail d’un plat,
- ajouter des recettes en favoris,
- commenter des recettes,
- gérer une liste de courses personnelle avec total des prix.

Le projet est organisé en 2 parties :

- **Backend Go** : logique applicative, authentification, accès base de données, intégration API.
- **Frontend HTML/CSS** : rendu des pages via templates Go.

---

## 🧱 Stack technique

### Backend

- **Langage** : Go (`go1.25` dans le `go.mod`)
- **Framework HTTP** : `net/http` (standard library)
- **Templating** : `html/template`
- **ORM** : GORM (`gorm.io/gorm`)
- **Base de données** : PostgreSQL (Supabase)
- **Authentification** : Supabase Auth (signup/login + JWT)
- **Validation JWT** :
  - `github.com/golang-jwt/jwt/v5`
  - `github.com/MicahParks/keyfunc/v2` (JWKS)
- **ID unique / erreurs** : `github.com/google/uuid`
- **Email transactionnel (optionnel)** : API Resend (`RESEND_API_KEY`)

### Frontend

- **HTML5** (pages serveur)
- **CSS3** (fichier unique `frontend/CSS/style.css`)
- **JavaScript léger** côté client (animations/interactions simples)

### Services externes

- **Supabase** : base PostgreSQL + Auth
- **TheMealDB** : données recettes/catégories/recherche
- **Resend** (optionnel) : envoi d’emails

---

## 📁 Structure du projet

```text
backend/
	main.go              # Serveur HTTP, routes, handlers, auth, API calls
	models/models.go     # Modèles GORM + structures API
	go.mod               # Dépendances Go

frontend/
	CSS/style.css        # Styles globaux
	html/*.html          # Templates pages (login, home, meals, favoris, etc.)
```

---

## ⚙️ Fonctionnalités principales

- Authentification utilisateur (inscription/connexion) via Supabase
- Gestion de session via cookie `session_token`
- Page d’accueil avec :
  - catégories,
  - recettes aléatoires,
  - favoris utilisateur
- Navigation par catégorie
- Recherche de recettes
- Fiche recette détaillée (instructions, tags, vidéo YouTube)
- Commentaires par recette (ajout/suppression)
- Favoris (ajout/suppression)
- Liste de courses (ajout, suppression, statut terminé, total)
- Page d’erreur dédiée (`error.html`) avec identifiant d’incident

---

## 🔐 Variables d’environnement

Créer un fichier `.env` (ou configurer les variables dans votre environnement) :

```bash
# Serveur
PORT=8080

# Base de données Supabase/PostgreSQL
DATABASE_URL=postgres://USER:PASSWORD@HOST:PORT/DBNAME?sslmode=require

# Supabase Auth
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<supabase-anon-key>
SUPABASE_JWT_SECRET=<jwt-secret-si-hs256>

# TheMealDB
API_CAT=https://www.themealdb.com/api/json/v1/1/categories.php
API_FOOD=https://www.themealdb.com/api/json/v1/1/filter.php?c=
API_SEARCH=https://www.themealdb.com/api/json/v1/1/search.php?s=
API_BYID=https://www.themealdb.com/api/json/v1/1/lookup.php?i=
API_RANDOM=https://www.themealdb.com/api/json/v1/1/random.php

# Emails (optionnel)
RESEND_API_KEY=<clé_api_resend>

# Debug erreurs (optionnel)
SHOW_ERROR_DETAILS=0
```

> Note : certaines routes sont protégées et nécessitent une session valide.

---

## 🚀 Lancement en local

### 1) Prérequis

- Go installé
- Projet Supabase configuré
- Base PostgreSQL accessible via `DATABASE_URL`

### 2) Installer les dépendances Go

Depuis `backend/` :

```bash
go mod tidy
```

### 3) Démarrer l’application

Depuis `backend/` :

```bash
go run main.go
```

Le serveur démarre sur `http://localhost:8080` (ou le port défini par `PORT`).

---

## 🛣️ Routes principales

### Publiques

- `GET /` : page d’accueil publique
- `GET|POST /login` : connexion
- `GET|POST /register` : inscription
- `GET /search` : recherche de recettes

### Protégées (auth requise)

- `GET /home`
- `GET /categorie`
- `GET /meals`
- `POST /addfavoris`
- `GET /favoris`
- `POST /deletefavoris`
- `POST /addcommentaire`
- `POST /deletecommentaire`
- `GET /liste`
- `POST /liste/add`
- `POST /liste/update`
- `POST /liste/delete`
- `GET|POST /logout`

---

## 🗃️ Données principales

Le backend migre automatiquement les tables :

- `users`
- `favoris`
- `commentaire`
- `liste`

La structure associée se trouve dans `backend/models/models.go`.

---

## ✅ État actuel

- Architecture monolithique simple et lisible
- Frontend rendu côté serveur (templates)
- Auth externalisée à Supabase
- Persistance locale des données métier (favoris/commentaires/liste) en PostgreSQL

---

## 👤 Auteur

Projet développé par **Mayel**.
