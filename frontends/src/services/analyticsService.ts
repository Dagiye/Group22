import apiClient from "./client";

export type AnalyticsData = {
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  last_scan: string | null;
  findings_by_severity: { severity: string; count: number }[];
  scans_over_time: { date: string; count: number }[];
  top_vulnerable_hosts: { host: string; count: number }[];
};

export async function getAnalytics(): Promise<AnalyticsData> {
  const res = await apiClient.get("/analytics");
  return res.data;
}
