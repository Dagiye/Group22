import apiClient from "./client";

export type DashboardStats = {
  total_scans: number;
  completed_scans: number;
  vulnerabilities: number;
  avg_duration: number;
};

export type SeverityStats = {
  severity: string;
  count: number;
}[];

export async function getDashboardStats(): Promise<DashboardStats> {
  const res = await apiClient.get("/dashboard/stats");
  return res.data;
}

export async function getSeverityStats(): Promise<SeverityStats> {
  const res = await apiClient.get("/dashboard/severity");
  return res.data;
}

export async function getRecentScans() {
  const res = await apiClient.get("/dashboard/recent-scans");
  return res.data;
}
