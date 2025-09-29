// app/page.tsx
"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

export default function HomePage() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/login"); // redirect root to login
  }, [router]);

  return <div className="flex items-center justify-center h-screen">Redirecting...</div>;
}