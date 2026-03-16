import * as react_jsx_runtime from 'react/jsx-runtime';
import { ReTiChAuth, ReTiChUser } from './retich-auth.mjs';

interface AuthContextValue {
    user: ReTiChUser | null;
    loading: boolean;
    signIn: () => Promise<void>;
    signOut: () => Promise<void>;
    handleRedirectResult: () => Promise<ReTiChUser | null>;
    getAccessToken: () => Promise<string | null>;
}
interface AuthProviderProps {
    auth: ReTiChAuth;
    children: React.ReactNode;
}
declare function AuthProvider({ auth, children }: AuthProviderProps): react_jsx_runtime.JSX.Element;
declare function useAuth(): AuthContextValue;

export { AuthProvider, useAuth };
