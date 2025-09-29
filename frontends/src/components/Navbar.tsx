"use client";
import Link from "next/link";
import { useAuth } from "@/hooks/useAuths";

export default function Navbar() {
  const { user, logout } = useAuth();

  return (
    <nav className="bg-gray-800 text-white px-4 py-2 flex justify-between items-center">
      <div className="space-x-4">
        <Link href="/dashboard" className="hover:underline">
          Dashboard
        </Link>
        <Link href="/dashboard/reports" className="hover:underline">
          Reports
        </Link>
        <Link href="/scans" className="hover:underline">
          Scans
        </Link>
      </div>
      <div>
        {user ? (
          <button
            onClick={logout}
            className="bg-red-600 px-3 py-1 rounded hover:bg-red-700 transition"
          >
            Logout
          </button>
        ) : (
          <Link
            href="/login"
            className="bg-green-600 px-3 py-1 rounded hover:bg-green-700 transition"
          >
            Login
          </Link>
        )}
      </div>
    </nav>
  );
}