// src/react.tsx
import { createContext, useContext, useEffect, useState } from "react";
import { jsx } from "react/jsx-runtime";
var AuthContext = createContext(null);
function AuthProvider({ auth, children }) {
  const [user, setUser] = useState(auth.currentUser);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const unsubscribe = auth.onAuthStateChanged((u) => {
      setUser(u);
      setLoading(false);
    });
    return unsubscribe;
  }, [auth]);
  const value = {
    user,
    loading,
    signIn: () => auth.signIn(),
    signOut: () => auth.signOut(),
    handleRedirectResult: () => auth.handleRedirectResult(),
    getAccessToken: () => auth.getAccessToken()
  };
  return /* @__PURE__ */ jsx(AuthContext.Provider, { value, children });
}
function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth doit \xEAtre utilis\xE9 dans <AuthProvider>");
  return ctx;
}
export {
  AuthProvider,
  useAuth
};
//# sourceMappingURL=react.mjs.map