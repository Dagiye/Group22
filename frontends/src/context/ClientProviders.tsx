
"use client";
import React, { ReactNode } from "react";
import { AuthProvider } from "@/hooks/useAuths";
import { ToastProvider } from "@/components/ui/use-toast";

export default function ClientProviders({ children }: { children: ReactNode }) {
  return (
    <AuthProvider>
      <ToastProvider>{children}</ToastProvider>
    </AuthProvider>
  );
}