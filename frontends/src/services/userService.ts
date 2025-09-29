// src/services/userService.ts
export type UserRole = "admin" | "scanner" | "viewer";

export interface User {
  id: string;
  email: string;
  role: UserRole;
  created_at: string;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ✅ Typed AddUser input
export interface AddUserPayload {
  email: string;
  password: string;
  role: UserRole;
}

export async function listUsers(): Promise<User[]> {
  const res = await fetch(`${API_URL}/users`);
  if (!res.ok) throw new Error("Failed to fetch users");
  return res.json();
}

export async function addUser(payload: AddUserPayload): Promise<User> {
  const res = await fetch(`${API_URL}/users`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error("Failed to add user");
  return res.json();
}

export async function updateUserRole(id: string, role: UserRole): Promise<User> {
  const res = await fetch(`${API_URL}/users/${id}/role`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  });
  if (!res.ok) throw new Error("Failed to update role");
  return res.json();
}

export async function deleteUser(id: string): Promise<void> {
  const res = await fetch(`${API_URL}/users/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error("Failed to delete user");
}
