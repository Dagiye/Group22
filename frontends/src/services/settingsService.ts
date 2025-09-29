import apiClient from "./client";

export type Settings = {
  scanner_timeout: number;
  max_concurrent_scans: number;
  notify_email: string;
};

export async function getSettings(): Promise<Settings> {
  const res = await apiClient.get("/admin/settings");
  return res.data;
}

export async function updateSettings(data: Partial<Settings>): Promise<Settings> {
  const res = await apiClient.patch("/admin/settings", data);
  return res.data;
}
