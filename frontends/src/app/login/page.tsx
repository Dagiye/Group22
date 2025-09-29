"use client";

import { useState } from "react";
import { login } from "@/services/authService";
import { useAuth } from "@/hooks/useAuths";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/use-toast";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { setUser } = useAuth();
  const router = useRouter();
  const { addToast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const user = await login(email, password);

      // ✅ Save user in context
      setUser(user);

      // ✅ Save token in cookie for middleware
      if (user?.token) {
        document.cookie = `access_token=${user.token}; path=/; secure; samesite=strict`;
      }

      addToast({ title: "✅ Logged in successfully" });

      // ✅ Redirect to dashboard
      router.push("/dashboard");
    } catch (err: any) {
      const message =
        err?.response?.data?.detail ?? err.message ?? "Login failed";
      addToast({ title: "❌ Login failed", description: message });
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <Card className="w-96 shadow-xl">
        <CardContent className="p-6">
          <h1 className="text-xl font-bold mb-4">🔐 Login</h1>
          <form onSubmit={handleSubmit} className="space-y-4">
            <Input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <Input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            <Button type="submit" className="w-full">
              Login
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
