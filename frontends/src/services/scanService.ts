// src/services/scanService.ts
import apiClient from "./client";

export interface Scan {
  scan_id: string;
  target: string;
  status: string;
  finished_at?: string | null;
}

// List all scans
export async function listScans(): Promise<Scan[]> {
  const res = await apiClient.get("/scan");
  return res.data ?? [];
}

// Start a new scan
export async function startScan(target: string): Promise<Scan> {
  const res = await apiClient.post("/scan/start", { target });
  return res.data;
}

// Get a single scan by ID
export async function getScan(id: string): Promise<Scan> {
  const res = await apiClient.get(`/scan/${id}`);
  return res.data;
}

// Cancel a running scan
export async function cancelScan(id: string): Promise<{ success: boolean }> {
  const res = await apiClient.post(`/scan/${id}/cancel`);
  return res.data;
}
