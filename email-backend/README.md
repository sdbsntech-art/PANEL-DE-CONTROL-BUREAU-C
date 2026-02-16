Email backend (minimal)

But: this README is in French below.

---

# Serveur d'envoi d'e-mails (développement)

Ce petit serveur Express fournit un endpoint POST `/send-email` qui accepte JSON :

{
  "to": ["a@example.com", "b@example.com"],
  "subject": "Objet du message",
  "message": "Texte du message (texte brut ou HTML simple)"
}

Installation rapide

1. Ouvrez un terminal dans `email-backend`.
2. Copiez `.env.example` en `.env` et remplissez les valeurs SMTP.
3. Installez les dépendances et lancez le serveur :

```bash
npm install
npm start
```

Configuration côté client

- Dans `config.js`, définissez :

```js
SECURITY_CONFIG.emailEndpoint = 'http://localhost:3000/send-email';
```

- Pour des raisons de sécurité, en production vous devez :
  - Héberger l'API derrière HTTPS.
  - Protéger l'endpoint (authentification, vérification de l'origine, rate-limiting).
  - Ne pas exposer de secrets dans le dépôt (utiliser des variables d'environnement sur le serveur).

Notes

- Pour des envois fiables et volumineux, préférez un service comme SendGrid, Mailgun, Sendinblue, etc.
- Lors du développement local, servez `index.html` via un petit serveur (ex: `npx http-server` ou l'extension Live Server) plutôt que d'ouvrir le fichier en `file://`.
