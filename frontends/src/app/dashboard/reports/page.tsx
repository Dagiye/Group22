"use client";
import { useEffect, useState } from "react";
import { listScans, Scan } from "@/services/scanService";
import { exportReport } from "@/services/reportService";

export default function ReportsPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchScans() {
      try {
        const data = await listScans();
        setScans(data);
      } catch (err) {
        console.error("Failed to load scans", err);
      } finally {
        setLoading(false);
      }
    }
    fetchScans();
  }, []);

  if (loading) return <div className="p-4">Loading reports...</div>;
  if (scans.length === 0) return <div className="p-4">No scans available.</div>;

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold mb-4">📑 Reports</h1>
      <table className="w-full border border-gray-300">
        <thead>
          <tr className="bg-gray-100">
            <th className="p-2 border">Target</th>
            <th className="p-2 border">Status</th>
            <th className="p-2 border">Finished</th>
            <th className="p-2 border">Export</th>
          </tr>
        </thead>
        <tbody>
          {scans
            .filter((s) => s.status === "completed")
            .map((scan) => (
              <tr key={scan.scan_id}>
                <td className="p-2 border">{scan.target}</td>
                <td className="p-2 border">{scan.status}</td>
                <td className="p-2 border">
                  {scan.finished_at
                    ? new Date(String(scan.finished_at)).toLocaleString()
                    : "-"}
                </td>
                <td className="p-2 border space-x-2">
                  <button
                    onClick={() => exportReport(scan.scan_id, "pdf")}
                    className="bg-gray-700 text-white px-2 py-1 rounded"
                  >
                    PDF
                  </button>
                  <button
                    onClick={() => exportReport(scan.scan_id, "csv")}
                    className="bg-gray-500 text-white px-2 py-1 rounded"
                  >
                    CSV
                  </button>
                </td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}