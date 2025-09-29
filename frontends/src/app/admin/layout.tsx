import "../globals.css";
import { AuthProvider } from "@/hooks/useAuths";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <div className="min-h-screen bg-white">{children}</div>
    </AuthProvider>
  );
}
