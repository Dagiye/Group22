"use client";
import { useEffect, useState } from "react";
import {
  listUsers,
  addUser,
  updateUserRole,
  deleteUser,
  User,
} from "@/services/userService";

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);

  // ✅ Typed form state
  const [form, setForm] = useState<{
    email: string;
    password: string;
    role: "admin" | "scanner" | "viewer";
  }>({
    email: "",
    password: "",
    role: "viewer",
  });

  async function loadUsers() {
    setLoading(true);
    try {
      const data = await listUsers();
      setUsers(data);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadUsers();
  }, []);

  async function handleAddUser(e: React.FormEvent) {
    e.preventDefault();
    await addUser(form);
    setForm({ email: "", password: "", role: "viewer" });
    await loadUsers();
  }

  async function handleRoleChange(id: string, role: User["role"]) {
    await updateUserRole(id, role);
    await loadUsers();
  }

  async function handleDelete(id: string) {
    if (confirm("Are you sure?")) {
      await deleteUser(id);
      await loadUsers();
    }
  }

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold mb-4">Manage Users</h1>

      {/* Add User Form */}
      <form onSubmit={handleAddUser} className="mb-6 space-y-2">
        <input
          type="email"
          placeholder="Email"
          value={form.email}
          onChange={(e) => setForm({ ...form, email: e.target.value })}
          className="border px-2 py-1 w-64"
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
          className="border px-2 py-1 w-64"
          required
        />
        <select
          value={form.role}
          onChange={(e) =>
            setForm({ ...form, role: e.target.value as User["role"] })
          }
          className="border px-2 py-1"
        >
          <option value="viewer">Viewer</option>
          <option value="scanner">Scanner</option>
          <option value="admin">Admin</option>
        </select>
        <button
          type="submit"
          className="bg-blue-600 text-white px-4 py-1 rounded"
        >
          Add User
        </button>
      </form>

      {/* Users Table */}
      {loading ? (
        <p>Loading users...</p>
      ) : (
        <table className="border-collapse border w-full">
          <thead>
            <tr className="bg-gray-200">
              <th className="border p-2">Email</th>
              <th className="border p-2">Role</th>
              <th className="border p-2">Created</th>
              <th className="border p-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td className="border p-2">{u.email}</td>
                <td className="border p-2">
                  <select
                    value={u.role}
                    onChange={(e) =>
                      handleRoleChange(u.id, e.target.value as User["role"])
                    }
                    className="border px-2 py-1"
                  >
                    <option value="viewer">Viewer</option>
                    <option value="scanner">Scanner</option>
                    <option value="admin">Admin</option>
                  </select>
                </td>
                <td className="border p-2">
                  {new Date(u.created_at).toLocaleString()}
                </td>
                <td className="border p-2">
                  <button
                    onClick={() => handleDelete(u.id)}
                    className="bg-red-600 text-white px-2 py-1 rounded"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
