# yboostmael

## Gestion des erreurs (UX + Debug)

- Les erreurs principales affichent maintenant une page dédiée `error.html` cohérente avec le style du site.
- Chaque erreur possède un **Incident ID** affiché à l'utilisateur et loggé côté serveur pour faciliter le diagnostic.
- Pour afficher les détails techniques dans la page (mode développeur), définir :

```bash
SHOW_ERROR_DETAILS=1
```

En production, laisser cette variable vide pour ne pas exposer les détails internes.

## Authentification Supabase

Le login/register backend utilise maintenant Supabase Auth en gardant les templates HTML et le cookie `session_token`.

Variables d'environnement requises :

```bash
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_ANON_KEY=<anon-public-key>
SUPABASE_JWT_SECRET=<jwt-secret-supabase>
```

- Login : appel `POST /auth/v1/token?grant_type=password`.
- Register : appel `POST /auth/v1/signup` + création du profil local.
- Middleware : validation locale du JWT via `SUPABASE_JWT_SECRET` (sans appel réseau à chaque page).
