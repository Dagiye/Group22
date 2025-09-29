// frontends/src/app/services/authService.ts
import apiClient from "./client";

export async function login(email: string, password: string) {
  const res = await apiClient.post("/auth/login", { email, password });
  const data = res.data;

  const user = {
    email: data.user.email,
    token: data.access_token,
  };

  if (typeof window !== "undefined") {
    localStorage.setItem("user", JSON.stringify(user));
    localStorage.setItem("access_token", data.access_token);
  }

  return user;
}

export async function register(email: string, password: string) {
  // Register first
  await apiClient.post("/auth/register", { email, password });

  // Auto-login after successful registration
  return await login(email, password);
}

export async function getCurrentUser() {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("user");
    if (saved) return JSON.parse(saved);
  }
  return null;
}

export async function logout() {
  if (typeof window !== "undefined") {
    localStorage.removeItem("user");
    localStorage.removeItem("access_token");
  }
  return Promise.resolve();
}
