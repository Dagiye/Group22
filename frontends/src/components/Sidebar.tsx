"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/hooks/useAuths"; // assuming auth hook with role

const navItems = [
  { name: "Dashboard", path: "/dashboard" },
  { name: "Scans", path: "/dashboard/scans" },
  { name: "Reports", path: "/dashboard/reports" },
  { name: "Evidence", path: "/dashboard/evidence" },
];

const adminItems = [
  { name: "Users", path: "/dashboard/admin/users" },
  { name: "Settings", path: "/dashboard/admin/settings" },
  { name: "Notifications", path: "/dashboard/admin/notifications" },
];

export default function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth(); // contains {email, role}

  return (
    <div className="w-60 min-h-screen bg-gray-900 text-white flex flex-col">
      <div className="p-4 text-2xl font-bold border-b border-gray-700">
        🔒 VulnScanner
      </div>
      <nav className="flex-1 p-4 space-y-2">
        {navItems.map((item) => (
          <Link
            key={item.path}
            href={item.path}
            className={`block px-3 py-2 rounded ${
              pathname.startsWith(item.path)
                ? "bg-gray-700"
                : "hover:bg-gray-800"
            }`}
          >
            {item.name}
          </Link>
        ))}
        {user?.role === "admin" && (
          <div className="mt-6">
            <p className="px-3 text-sm text-gray-400 uppercase">Admin</p>
            {adminItems.map((item) => (
              <Link
                key={item.path}
                href={item.path}
                className={`block px-3 py-2 rounded ${
                  pathname.startsWith(item.path)
                    ? "bg-gray-700"
                    : "hover:bg-gray-800"
                }`}
              >
                {item.name}
              </Link>
            ))}
          </div>
        )}
      </nav>
      <div className="p-4 border-t border-gray-700 text-sm">
        Logged in as <b>{user?.email}</b>
      </div>
    </div>
  );
}
