"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/react.tsx
var react_exports = {};
__export(react_exports, {
  AuthProvider: () => AuthProvider,
  useAuth: () => useAuth
});
module.exports = __toCommonJS(react_exports);
var import_react = require("react");
var import_jsx_runtime = require("react/jsx-runtime");
var AuthContext = (0, import_react.createContext)(null);
function AuthProvider({ auth, children }) {
  const [user, setUser] = (0, import_react.useState)(auth.currentUser);
  const [loading, setLoading] = (0, import_react.useState)(true);
  (0, import_react.useEffect)(() => {
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
  return /* @__PURE__ */ (0, import_jsx_runtime.jsx)(AuthContext.Provider, { value, children });
}
function useAuth() {
  const ctx = (0, import_react.useContext)(AuthContext);
  if (!ctx) throw new Error("useAuth doit \xEAtre utilis\xE9 dans <AuthProvider>");
  return ctx;
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  AuthProvider,
  useAuth
});
//# sourceMappingURL=react.js.map