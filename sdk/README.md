# @retish/auth

SDK client pour [ReTiCh Auth](https://github.com/ReTiCh-Corp/ReTiCh-Auth) — similaire à Firebase Auth.

## Installation

```bash
npm i @retish/auth
```

## Usage

### 1. Initialiser le SDK

```tsx
// main.tsx
import { ReTiChAuth } from "@retish/auth"
import { AuthProvider } from "@retish/auth/react"

const auth = new ReTiChAuth({
  baseUrl: "https://auth.mondomaine.com",
  clientId: "ton-client-id",
  clientSecret: "ton-client-secret",
  redirectUri: "https://monapp.com/callback",
})

export default function Root() {
  return (
    <AuthProvider auth={auth}>
      <App />
    </AuthProvider>
  )
}
```

### 2. Utiliser dans un composant

```tsx
import { useAuth } from "@retish/auth/react"

export default function App() {
  const { user, loading, signIn, signOut } = useAuth()

  if (loading) return <p>Chargement...</p>

  if (!user) return <button onClick={signIn}>Se connecter</button>

  return (
    <div>
      <p>Connecté en tant que {user.email}</p>
      <button onClick={signOut}>Déconnexion</button>
    </div>
  )
}
```

### 3. Page de callback

```tsx
// pages/Callback.tsx
import { useEffect } from "react"
import { useAuth } from "@retish/auth/react"
import { useNavigate } from "react-router-dom"

export default function Callback() {
  const { handleRedirectResult } = useAuth()
  const navigate = useNavigate()

  useEffect(() => {
    handleRedirectResult()
      .then(() => navigate("/dashboard"))
      .catch(() => navigate("/"))
  }, [])

  return <p>Connexion en cours...</p>
}
```

### 4. Appels API authentifiés

```tsx
const { getAccessToken } = useAuth()

const token = await getAccessToken() // refresh automatique si expiré

const res = await fetch("https://api.mondomaine.com/profile", {
  headers: { Authorization: `Bearer ${token}` },
})
```

## API

### `new ReTiChAuth(config)`

| Paramètre | Type | Description |
|-----------|------|-------------|
| `baseUrl` | `string` | URL du service ReTiCh Auth |
| `clientId` | `string` | `client_id` obtenu via la console admin |
| `clientSecret` | `string` | `client_secret` obtenu via la console admin |
| `redirectUri` | `string` | URL de callback après login |

### `useAuth()`

| Propriété | Type | Description |
|-----------|------|-------------|
| `user` | `ReTiChUser \| null` | Utilisateur connecté ou `null` |
| `loading` | `boolean` | `true` pendant la restauration de session |
| `signIn()` | `() => void` | Redirige vers la page de login |
| `signOut()` | `() => Promise<void>` | Déconnecte et révoque les tokens |
| `handleRedirectResult()` | `() => Promise<ReTiChUser \| null>` | À appeler sur la page de callback |
| `getAccessToken()` | `() => Promise<string \| null>` | Retourne un token valide (refresh auto) |

### `auth.onAuthStateChanged(callback)`

```tsx
const unsubscribe = auth.onAuthStateChanged((user) => {
  console.log(user) // ReTiChUser | null
})

// Arrêter d'écouter
unsubscribe()
```

## Sécurité

### Ce que le SDK protège

#### Vol de code OAuth (PKCE)
Quand l'utilisateur se connecte, ReTiCh Auth retourne un `code` dans l'URL. Sans PKCE, un attaquant qui intercepte cette URL pourrait l'échanger contre des tokens.

Le SDK génère un `code_verifier` aléatoire stocké uniquement dans le browser, et envoie son hash (`code_challenge`) à ReTiCh Auth. Pour échanger le code, il faut présenter le `code_verifier` original — impossible à deviner ou intercepter.

```
Attaquant intercepte ?code=abc123
  → tente d'échanger le code
  → ReTiCh Auth exige le code_verifier
  → attaquant ne l'a pas → refusé
```

#### CSRF (Cross-Site Request Forgery)
Un site malveillant pourrait tenter de déclencher un callback OAuth sur ton app avec un faux code.

Le SDK génère un `state` aléatoire avant chaque login et vérifie qu'il correspond au retour du callback. Un callback forgé aura un `state` différent et sera rejeté.

```
Site malveillant envoie /callback?code=...&state=faux
  → SDK compare state reçu vs state stocké
  → différent → erreur, tokens jamais émis
```

#### Protection par client_secret + PKCE
Le `clientId` et `clientSecret` sont requis pour échanger un code OAuth contre des tokens. Même si quelqu'un intercepte le `code` dans l'URL de callback, il lui faut aussi le `code_verifier` PKCE (jamais envoyé sur le réseau) et le `clientSecret`.

```
Attaquant intercepte ?code=abc123
  → tente d'échanger le code
  → ReTiCh Auth exige le clientSecret ET le code_verifier
  → attaquant n'a ni l'un ni l'autre → refusé
```

> En production, mets le `clientSecret` dans une variable d'environnement (ex: `VITE_CLIENT_SECRET`) et ne le commite jamais dans git.

#### Redirect URI fixe
ReTiCh Auth refuse tout callback vers une URL non enregistrée dans la console admin. Même avec ton `clientId`, personne ne peut rediriger les tokens vers un autre domaine.

```
Attaquant modifie redirect_uri=https://evil.com
  → ReTiCh Auth compare avec les URIs enregistrées
  → non autorisé → flow annulé
```

#### Refresh token à usage unique
Chaque fois que le SDK renouvelle l'access token, l'ancien refresh token est révoqué et un nouveau est émis. Si un refresh token est volé et utilisé par un attaquant, l'utilisation légitime suivante le détectera (token déjà révoqué).

#### Signature RS256 vérifiée côté serveur
Les access tokens sont signés avec une clé RSA privée que seul ReTiCh Auth possède. Ton backend Node vérifie cette signature via la clé publique — un token forgé sera automatiquement rejeté même s'il contient les bonnes données.

```
Attaquant crée un faux token avec user_id=admin
  → Node vérifie la signature RS256
  → signature invalide → 401
```

### Ce que le SDK ne fait pas

| Responsabilité | Qui s'en charge |
|---|---|
| Vérifier la signature JWT | Ton backend Node (via JWKS) |
| Hasher les mots de passe | ReTiCh Auth |
| Protéger contre le brute force | ReTiCh Auth (lockout après 5 tentatives) |
| Révoquer les tokens à la déconnexion | ReTiCh Auth + `signOut()` |

### Fonctionnement général

- **Login** via OAuth 2.0 PKCE — aucun mot de passe ne transite par ton app
- **Tokens** stockés dans `localStorage`, restaurés automatiquement au rechargement
- **Refresh automatique** — l'access token est renouvelé 1 minute avant expiration

## Valider les tokens côté serveur (Node.js)

```bash
npm i jose
```

```js
import { createRemoteJWKSet, jwtVerify } from "jose"

const JWKS = createRemoteJWKSet(
  new URL("https://auth.mondomaine.com/.well-known/jwks.json")
)

async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.slice(7)
  if (!token) return res.status(401).json({ error: "Token manquant" })

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: "https://auth.mondomaine.com",
      audience: "ton-client-id", // client_id obtenu via la console admin
    })
    req.user = payload
    next()
  } catch {
    res.status(401).json({ error: "Token invalide ou expiré" })
  }
}
```
