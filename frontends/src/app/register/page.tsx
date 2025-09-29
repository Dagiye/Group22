"use client";

import { useState } from "react";
import { register } from "@/services/authService";
import { useAuth } from "@/hooks/useAuths";
import { useRouter } from "next/navigation";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/use-toast";

export default function RegisterPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const { setUser } = useAuth();
  const router = useRouter();
  const { addToast } = useToast();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const user = await register(email, password);
      setUser(user);
      addToast({ title: "✅ Registered & Logged in successfully" });
      router.push("/dashboard");
    } catch (err: any) {
      const message = err?.response?.data?.detail ?? err.message ?? "Registration failed";
      addToast({ title: "❌ Registration failed", description: message });
    }
  };

  return (
    <div className="flex items-center justify-center h-screen bg-gray-50">
      <Card className="w-96 shadow-xl">
        <CardContent className="p-6">
          <h1 className="text-xl font-bold mb-4">📝 Register</h1>
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
            <Button type="submit" className="w-full">Register</Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
