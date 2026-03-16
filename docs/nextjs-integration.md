# Intégrer ReTiCh Auth dans une app Next.js

Guide pas-à-pas pour connecter une application Next.js à **ReTiCh Auth** via OAuth 2.0 / OIDC (PKCE).

> Pour le flow OAuth générique (tous frameworks), voir [integration.md](./integration.md).

---

## Prérequis

- ReTiCh Auth qui tourne (dev : `http://localhost:8081`)
- Node.js 18+
- Un `client_id` et `client_secret` obtenus via la console admin

---

## 1. Créer l'app Next.js

```bash
npx create-next-app@latest my-app --typescript --app
cd my-app
```

---

## 2. Enregistrer ton client OAuth

Ouvre la **console admin** (`http://localhost:3000`), connecte-toi avec l'Admin API Key, puis clique **+ Nouveau projet**.

Renseigne :
- **Nom** de l'app
- **Redirect URIs** : `http://localhost:3000/api/auth/callback/retich` (ajouter l'URL de prod en production)
- **Scopes** : `openid email profile`

**Sauvegarde le `client_secret`** — il ne sera plus jamais affiché.

---

## 3. Configurer les variables d'environnement

Créer `.env.local` à la racine de l'app Next.js :

```env
# URL du service ReTiCh Auth
RETICH_AUTH_URL=http://localhost:8081

# Identifiants OAuth obtenus à l'étape 2
RETICH_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
RETICH_CLIENT_SECRET=raw_secret_ici

# Secret NextAuth (générer avec: openssl rand -base64 32)
AUTH_SECRET=change-me-in-production

# URL de l'app Next.js (pour les callbacks)
NEXTAUTH_URL=http://localhost:3000
```

---

## 4. Installer Auth.js (NextAuth v5)

```bash
npm install next-auth@beta
```

---

## 5. Configurer Auth.js avec le provider custom

Créer `auth.ts` à la racine :

```typescript
// auth.ts
import NextAuth from "next-auth"

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    {
      id: "retich",
      name: "ReTiCh Auth",
      type: "oidc",
      issuer: process.env.RETICH_AUTH_URL,
      clientId: process.env.RETICH_CLIENT_ID,
      clientSecret: process.env.RETICH_CLIENT_SECRET,
      checks: ["pkce", "state", "nonce"],
      authorization: {
        params: {
          scope: "openid email",
        },
      },
    },
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Stocker le access_token OAuth dans le JWT NextAuth
      if (account) {
        token.accessToken = account.access_token
        token.refreshToken = account.refresh_token
        token.expiresAt = account.expires_at
      }
      return token
    },
    async session({ session, token }) {
      // Exposer le access_token à la session client
      session.accessToken = token.accessToken as string
      return session
    },
  },
})
```

Créer `app/api/auth/[...nextauth]/route.ts` :

```typescript
// app/api/auth/[...nextauth]/route.ts
import { handlers } from "@/auth"
export const { GET, POST } = handlers
```

Ajouter les types dans `types/next-auth.d.ts` :

```typescript
// types/next-auth.d.ts
import "next-auth"

declare module "next-auth" {
  interface Session {
    accessToken?: string
  }
}
```

---

## 6. Ajouter le middleware (protection de routes)

Créer `middleware.ts` à la racine :

```typescript
// middleware.ts
import { auth } from "@/auth"
import { NextResponse } from "next/server"

export default auth((req) => {
  if (!req.auth) {
    return NextResponse.redirect(new URL("/login", req.url))
  }
})

// Routes à protéger
export const config = {
  matcher: ["/dashboard/:path*", "/profile/:path*"],
}
```

---

## 7. Créer la page de login

```typescript
// app/login/page.tsx
import { signIn } from "@/auth"

export default function LoginPage() {
  return (
    <form
      action={async () => {
        "use server"
        await signIn("retich", { redirectTo: "/dashboard" })
      }}
    >
      <button type="submit">Se connecter avec ReTiCh Auth</button>
    </form>
  )
}
```

---

## 8. Utiliser la session dans un composant

**Côté serveur (Server Component) :**

```typescript
// app/dashboard/page.tsx
import { auth } from "@/auth"
import { redirect } from "next/navigation"

export default async function DashboardPage() {
  const session = await auth()
  if (!session) redirect("/login")

  return <h1>Bonjour {session.user?.email}</h1>
}
```

**Côté client (Client Component) :**

```typescript
// app/profile/page.tsx
"use client"
import { useSession } from "next-auth/react"

export default function ProfilePage() {
  const { data: session } = useSession()

  return <p>{session?.user?.email}</p>
}
```

Ne pas oublier d'entourer l'app du `SessionProvider` dans `app/layout.tsx` si tu utilises `useSession` :

```typescript
// app/layout.tsx
import { SessionProvider } from "next-auth/react"

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <SessionProvider>{children}</SessionProvider>
      </body>
    </html>
  )
}
```

---

## 9. Appeler l'API du service auth depuis Next.js

Avec l'`access_token` OAuth récupéré en session :

```typescript
// app/profile/page.tsx (Server Component)
import { auth } from "@/auth"

export default async function ProfilePage() {
  const session = await auth()

  const res = await fetch(`${process.env.RETICH_AUTH_URL}/oauth/userinfo`, {
    headers: {
      Authorization: `Bearer ${session?.accessToken}`,
    },
  })

  const user = await res.json()
  // { sub, email, email_verified }

  return <pre>{JSON.stringify(user, null, 2)}</pre>
}
```

---

## 10. Déconnexion

```typescript
import { signOut } from "@/auth"

<form action={async () => {
  "use server"
  await signOut({ redirectTo: "/" })
}}>
  <button type="submit">Se déconnecter</button>
</form>
```

---

## Structure finale du projet

```
my-app/
├── auth.ts                              # Config NextAuth
├── middleware.ts                        # Protection des routes
├── types/
│   └── next-auth.d.ts                  # Types session
├── app/
│   ├── layout.tsx
│   ├── login/
│   │   └── page.tsx
│   ├── dashboard/
│   │   └── page.tsx
│   └── api/
│       └── auth/
│           └── [...nextauth]/
│               └── route.ts
└── .env.local
```

---

## Variables d'env — récapitulatif

| Variable | Description |
|----------|-------------|
| `RETICH_AUTH_URL` | URL du service auth (`http://localhost:8081` en dev) |
| `RETICH_CLIENT_ID` | `client_id` obtenu à l'enregistrement |
| `RETICH_CLIENT_SECRET` | `client_secret` obtenu à l'enregistrement |
| `AUTH_SECRET` | Secret NextAuth (32+ bytes random) |
| `NEXTAUTH_URL` | URL de l'app Next.js |

---

## En production

1. Mettre à jour `RETICH_AUTH_URL` avec l'URL de prod du service auth
2. Ajouter l'URL de prod dans `redirect_uris` du client OAuth (via l'admin API)
3. Mettre à jour `ALLOWED_ORIGINS` et `ALLOWED_REDIRECT_URLS` dans le `.env` du service auth
4. Générer un vrai `AUTH_SECRET` : `openssl rand -base64 32`

---

## Liens utiles

- Discovery OIDC : `http://localhost:8081/.well-known/openid-configuration`
- JWKS (clé publique) : `http://localhost:8081/.well-known/jwks.json`
- Playground OAuth : `http://localhost:8081/oauth/playground`
- [Docs Auth.js](https://authjs.dev)
