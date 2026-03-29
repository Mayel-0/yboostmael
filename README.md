# yboostmael

## Gestion des erreurs (UX + Debug)

- Les erreurs principales affichent maintenant une page dédiée `error.html` cohérente avec le style du site.
- Chaque erreur possède un **Incident ID** affiché à l'utilisateur et loggé côté serveur pour faciliter le diagnostic.
- Pour afficher les détails techniques dans la page (mode développeur), définir :

```bash
SHOW_ERROR_DETAILS=1
```

En production, laisser cette variable vide pour ne pas exposer les détails internes.
