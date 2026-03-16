import { createContext, useContext, useEffect, useState } from "react"
import type { ReTiChAuth, ReTiChUser } from "./retich-auth"

interface AuthContextValue {
  user: ReTiChUser | null
  loading: boolean
  signIn: () => Promise<void>
  signOut: () => Promise<void>
  handleRedirectResult: () => Promise<ReTiChUser | null>
  getAccessToken: () => Promise<string | null>
}

const AuthContext = createContext<AuthContextValue | null>(null)

interface AuthProviderProps {
  auth: ReTiChAuth
  children: React.ReactNode
}

export function AuthProvider({ auth, children }: AuthProviderProps) {
  const [user, setUser] = useState<ReTiChUser | null>(auth.currentUser)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((u) => {
      setUser(u)
      setLoading(false)
    })
    return unsubscribe
  }, [auth])

  const value: AuthContextValue = {
    user,
    loading,
    signIn: () => auth.signIn(),
    signOut: () => auth.signOut(),
    handleRedirectResult: () => auth.handleRedirectResult(),
    getAccessToken: () => auth.getAccessToken(),
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth doit être utilisé dans <AuthProvider>")
  return ctx
}
