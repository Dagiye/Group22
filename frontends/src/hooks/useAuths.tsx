// frontends/src/app/hooks/useAuths.ts
"use client";

import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { getCurrentUser, logout as logoutService } from "@/services/authService";

type AuthContextProps = {
  user: any | null;
  loading: boolean;
  setUser: (u: any | null) => void;
  logout: () => Promise<void>;
};

const AuthContext = createContext<AuthContextProps | undefined>(undefined);

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [user, setUserState] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const init = async () => {
      const u = await getCurrentUser();
      if (u) setUserState(u);
      setLoading(false);
    };
    init();
  }, []);

  const setUser = (u: any | null) => {
    setUserState(u);
  };

  const logout = async () => {
    await logoutService();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, setUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
