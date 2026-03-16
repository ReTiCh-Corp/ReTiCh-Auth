# Intégrer ReTiCh Auth dans ton app

ReTiCh Auth fonctionne comme "Se connecter avec Google". Ton app ne gère aucun mot de passe — tout se passe sur ReTiCh Auth.

---

## Prérequis

- ReTiCh Auth qui tourne (voir [project.md](./project.md))
- Un `client_id` et `client_secret` obtenus via la console admin

---

## 1. Enregistrer ton app

Ouvre la **console admin** (`http://localhost:3000`), connecte-toi avec l'Admin API Key, puis clique **+ Nouveau projet**.

Renseigne le nom de l'app, les **Redirect URIs** (ex : `http://localhost:3000/callback`) et les scopes.

**Sauvegarde le `client_secret`** — il ne sera plus affiché.

---

## 2. Le flow OAuth (vue d'ensemble)

```
Utilisateur clique "Se connecter"
        ↓
Ton app redirige vers /oauth/authorize
        ↓
ReTiCh Auth gère : login, inscription, mot de passe oublié
        ↓
ReTiCh Auth redirige vers ton app
https://monapp.com/callback?code=abc123&state=xyz
        ↓
Ton app échange le code
POST /oauth/token → { access_token, refresh_token, id_token }
        ↓
Ton app connaît l'utilisateur
GET /oauth/userinfo → { sub, email, email_verified }
```

---

## 3. Rediriger vers ReTiCh Auth

Construire l'URL d'autorisation avec PKCE :

```
GET https://auth.mondomaine.com/oauth/authorize
  ?client_id=<CLIENT_ID>
  &redirect_uri=https://monapp.com/callback
  &response_type=code
  &scope=openid email
  &state=<valeur_aléatoire>
  &code_challenge=<S256_hash_du_verifier>
  &code_challenge_method=S256
```

**PKCE est obligatoire.** Génération du `code_verifier` et `code_challenge` :

```javascript
// Exemple JavaScript
const verifier = crypto.randomUUID() + crypto.randomUUID()
const challenge = btoa(
  String.fromCharCode(...new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))
  ))
).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
```

Stocker `verifier` et `state` en session côté serveur.

---

## 4. Gérer le callback

Ton app reçoit :

```
GET https://monapp.com/callback?code=abc123&state=xyz
```

Vérifier que `state` correspond à celui stocké, puis échanger le code :

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=abc123
&redirect_uri=https://monapp.com/callback
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
&code_verifier=<verifier>
```

Réponse :

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "...",
  "id_token": "eyJ..."
}
```

---

## 5. Récupérer les infos utilisateur

```http
GET /oauth/userinfo
Authorization: Bearer <access_token>
```

```json
{
  "sub": "uuid-de-l-utilisateur",
  "email": "user@exemple.com",
  "email_verified": true
}
```

---

## 6. Rafraîchir le token

L'`access_token` est valide **15 minutes**. Quand il expire :

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=<refresh_token>
&client_id=<CLIENT_ID>
&client_secret=<CLIENT_SECRET>
```

Réponse : nouveau `access_token` + nouveau `refresh_token` (rotation automatique).

---

## 7. Vérifier un JWT sans appel réseau

Les tokens sont signés RS256. Tu peux les vérifier avec la clé publique :

```
GET /.well-known/jwks.json
```

Ou utiliser la découverte OIDC :

```
GET /.well-known/openid-configuration
```

Lors de la vérification, valide toujours l'**audience** (`aud`) pour t'assurer que le token a bien été émis pour ton app et non pour une autre :

```javascript
const { payload } = await jwtVerify(token, JWKS, {
  issuer: "https://auth.mondomaine.com",
  audience: "<ton-client-id>",
})
```

Un token émis pour `app-a` sera rejeté par `app-b` si celle-ci vérifie l'audience.

---

## Endpoints de référence

| Endpoint | Description |
|----------|-------------|
| `GET /oauth/authorize` | Démarre le flow |
| `POST /oauth/token` | Échange code ou refresh token |
| `GET /oauth/userinfo` | Infos utilisateur |
| `GET /.well-known/jwks.json` | Clé publique RS256 |
| `GET /.well-known/openid-configuration` | Métadonnées OIDC |

---

## Guides par framework

| Framework | Guide |
|-----------|-------|
| Next.js (App Router + NextAuth v5) | [nextjs-integration.md](./nextjs-integration.md) |
