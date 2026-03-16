# Intégrer ReTiCh Auth dans une app Node.js (Express)

Guide pour connecter une application Express à **ReTiCh Auth** via validation JWT stateless (JWKS).

> Pour le flow OAuth générique (tous frameworks), voir [integration.md](./integration.md).

---

## Prérequis

- ReTiCh Auth qui tourne (dev : `http://localhost:8081`)
- Node.js 18+
- Un `client_id` et `client_secret` obtenus via la console admin

---

## 1. Enregistrer ton client OAuth

Ouvre la **console admin** (`http://localhost:3000`), connecte-toi avec l'Admin API Key, puis clique **+ Nouveau projet**.

Renseigne :
- **Nom** de l'app
- **Redirect URIs** : `http://localhost:3000/auth/callback`
- **Scopes** : `openid email profile`

**Sauvegarde le `client_secret`** — il ne sera plus jamais affiché.

---

## 2. Installer les dépendances

```bash
npm install express jose dotenv
```

---

## 3. Variables d'environnement

Créer `.env` :

```env
RETICH_AUTH_URL=http://localhost:8081
RETICH_CLIENT_ID=ton-client-id
PORT=3000
```

---

## 4. Middleware de validation JWT

```javascript
// middleware/auth.js
import { createRemoteJWKSet, jwtVerify } from "jose"

const JWKS = createRemoteJWKSet(
  new URL(`${process.env.RETICH_AUTH_URL}/.well-known/jwks.json`)
)

export async function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Token manquant" })
  }

  const token = authHeader.slice(7)

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: process.env.RETICH_AUTH_URL,
      audience: process.env.RETICH_CLIENT_ID,
    })
    req.user = payload // { user_id, email, exp, ... }
    next()
  } catch (err) {
    return res.status(401).json({ error: "Token invalide ou expiré" })
  }
}
```

> La clé publique est **mise en cache automatiquement** — pas d'appel réseau à chaque requête.

---

## 5. Protéger tes routes

```javascript
// app.js
import express from "express"
import { requireAuth } from "./middleware/auth.js"
import "dotenv/config"

const app = express()
app.use(express.json())

app.get("/api/profile", requireAuth, (req, res) => {
  res.json({ user: req.user }) // req.user.user_id, req.user.email
})

app.listen(process.env.PORT, () => {
  console.log(`App running on http://localhost:${process.env.PORT}`)
})
```

---

## 6. Côté React — envoyer le token

Après le login, React envoie l'`access_token` dans chaque requête :

```javascript
const res = await fetch("http://localhost:3000/api/profile", {
  headers: {
    Authorization: `Bearer ${accessToken}`,
  },
})
```

---

## 7. Rafraîchir le token (côté React)

L'`access_token` expire après **15 minutes**. React doit le rafraîchir via ReTiCh Auth :

```javascript
async function refreshTokens(refreshToken) {
  const res = await fetch(`${RETICH_AUTH_URL}/oauth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    }),
  })

  return res.json() // { access_token, refresh_token, expires_in }
}
```

---

## Structure du projet

```
my-app/
├── middleware/
│   └── auth.js      # Validation JWT via JWKS
├── app.js           # Express + routes
├── .env
└── package.json
```

---

## Variables d'env — récapitulatif

| Variable | Description |
|----------|-------------|
| `RETICH_AUTH_URL` | URL du service auth (`http://localhost:8081` en dev) |
| `RETICH_CLIENT_ID` | `client_id` obtenu à l'enregistrement — utilisé pour la vérification d'audience |

---

## Liens utiles

- JWKS (clé publique) : `http://localhost:8081/.well-known/jwks.json`
- Discovery OIDC : `http://localhost:8081/.well-known/openid-configuration`
- Playground OAuth : `http://localhost:8081/oauth/playground`
