/**
 * ReTiCh Auth — React hooks
 *
 * import { AuthProvider, useAuth } from "./sdk/react.js"
 *
 * // main.jsx
 * const auth = new ReTiChAuth({ baseUrl, clientId, redirectUri })
 * <AuthProvider auth={auth}><App /></AuthProvider>
 *
 * // Dans n'importe quel composant
 * const { user, loading, signIn, signOut, getAccessToken } = useAuth()
 */

import { createContext, useContext, useEffect, useState } from "react"

const AuthContext = createContext(null)

/**
 * Provider à mettre à la racine de l'app
 * @param {{ auth: import("./retich-auth.js").ReTiChAuth, children: React.ReactNode }} props
 */
export function AuthProvider({ auth, children }) {
  const [user, setUser] = useState(auth.currentUser)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((u) => {
      setUser(u)
      setLoading(false)
    })
    return unsubscribe
  }, [auth])

  const value = {
    user,
    loading,
    signIn: () => auth.signIn(),
    signOut: () => auth.signOut(),
    handleRedirectResult: () => auth.handleRedirectResult(),
    getAccessToken: () => auth.getAccessToken(),
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

/**
 * Hook principal — identique à useAuth de Firebase
 * @returns {{ user: object|null, loading: boolean, signIn: () => void, signOut: () => Promise<void>, getAccessToken: () => Promise<string|null>, handleRedirectResult: () => Promise<object|null> }}
 */
export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth doit être utilisé dans <AuthProvider>")
  return ctx
}
