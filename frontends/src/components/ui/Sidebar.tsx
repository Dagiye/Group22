import Link from "next/link";
import { useAuth } from "@/hooks/useAuths";

export default function Sidebar() {
  const { user } = useAuth();

  return (
    <aside className="w-64 bg-white shadow-lg h-screen p-4">
      <nav className="space-y-2">
        <Link href="/dashboard">📊 Dashboard</Link>
        <Link href="/scans">🔍 Scans</Link>
        <Link href="/reports">📄 Reports</Link>

        {user?.role === "admin" && (
          <>
            <Link href="/admin/users">👤 User Management</Link>
            <Link href="/admin/settings">⚙️ System Settings</Link>
          </>
        )}
      </nav>
    </aside>
  );
}
