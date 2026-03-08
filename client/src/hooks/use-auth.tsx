import { createContext, useContext, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest, getQueryFn } from "@/lib/queryClient";
import type { User } from "@shared/schema";

type AuthUser = Omit<User, "password">;

interface TwoFactorChallenge {
  twoFactorToken: string;
}

interface AuthContextType {
  user: AuthUser | null;
  isLoading: boolean;
  loginMutation: ReturnType<typeof useLoginMutation>;
  registerMutation: ReturnType<typeof useRegisterMutation>;
  logoutMutation: ReturnType<typeof useLogoutMutation>;
  twoFactorChallenge: TwoFactorChallenge | null;
  verifyTwoFactor: (code: string) => Promise<void>;
  clearTwoFactorChallenge: () => void;
}

function useLoginMutation(setTwoFactor: (challenge: TwoFactorChallenge | null) => void) {
  return useMutation({
    mutationFn: async (data: { username: string; password: string }) => {
      const res = await apiRequest("POST", "/api/login", data);
      return res.json();
    },
    onSuccess: (result: any) => {
      if (result.requiresTwoFactor) {
        setTwoFactor({ twoFactorToken: result.twoFactorToken });
      } else {
        queryClient.setQueryData(["/api/user"], result);
      }
    },
  });
}

function useRegisterMutation() {
  return useMutation({
    mutationFn: async (data: { username: string; password: string }) => {
      const res = await apiRequest("POST", "/api/register", data);
      return res.json();
    },
    onSuccess: (user: AuthUser) => {
      queryClient.setQueryData(["/api/user"], user);
    },
  });
}

function useLogoutMutation() {
  return useMutation({
    mutationFn: async () => {
      await apiRequest("POST", "/api/logout");
    },
    onSuccess: () => {
      queryClient.setQueryData(["/api/user"], null);
      queryClient.clear();
    },
  });
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [twoFactorChallenge, setTwoFactorChallenge] = useState<TwoFactorChallenge | null>(null);

  const { data: user, isLoading } = useQuery<AuthUser | null>({
    queryKey: ["/api/user"],
    queryFn: getQueryFn({ on401: "returnNull" }),
  });

  const loginMutation = useLoginMutation(setTwoFactorChallenge);
  const registerMutation = useRegisterMutation();
  const logoutMutation = useLogoutMutation();

  const verifyTwoFactor = async (code: string) => {
    if (!twoFactorChallenge) throw new Error("No two-factor challenge active");
    const res = await apiRequest("POST", "/api/auth/2fa/verify-login", {
      twoFactorToken: twoFactorChallenge.twoFactorToken,
      code,
    });
    const user = await res.json();
    setTwoFactorChallenge(null);
    queryClient.setQueryData(["/api/user"], user);
  };

  return (
    <AuthContext.Provider
      value={{
        user: user ?? null,
        isLoading,
        loginMutation,
        registerMutation,
        logoutMutation,
        twoFactorChallenge,
        verifyTwoFactor,
        clearTwoFactorChallenge: () => setTwoFactorChallenge(null),
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
