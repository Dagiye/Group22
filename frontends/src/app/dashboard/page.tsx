"use client";

import { useEffect, useState } from "react";
import { listScans, startScan, Scan } from "@/services/scanService";
import { useAuth } from "@/hooks/useAuths";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export default function DashboardPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [target, setTarget] = useState("");
  const [loading, setLoading] = useState(true);
  const { user, loading: authLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!authLoading && !user) {
      router.replace("/login");
      return;
    }

    const fetchScans = async () => {
      setLoading(true);
      try {
        const data = await listScans();
        setScans(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Failed to load scans:", err);
      } finally {
        setLoading(false);
      }
    };

    if (user) fetchScans();
  }, [user, authLoading, router]);

  const handleStartScan = async () => {
    if (!target) return;
    try {
      const s = await startScan(target);
      setScans((prev) => [s, ...prev]);
      setTarget("");
    } catch (err) {
      console.error("Failed to start scan:", err);
    }
  };

  if (authLoading || loading) {
    return <div className="p-4 text-center">Loading dashboard...</div>;
  }

  if (!user) return null;

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">🛡 Dashboard</h1>
      <div className="mb-4 flex space-x-2">
        <Input
          placeholder="https://example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          className="flex-1"
        />
        <Button onClick={handleStartScan}>Start Scan</Button>
      </div>

      {scans.length === 0 ? (
        <div>No scans found.</div>
      ) : (
        <table className="w-full border-collapse border border-gray-300">
          <thead>
            <tr className="bg-gray-100">
              <th className="border px-2 py-1">Target</th>
              <th className="border px-2 py-1">Status</th>
              <th className="border px-2 py-1">Finished</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={`${scan.scan_id}-${scan.target}`}>
                <td className="border px-2 py-1">{scan.target}</td>
                <td className="border px-2 py-1">{scan.status}</td>
                <td className="border px-2 py-1">
                  {scan.finished_at ? new Date(String(scan.finished_at)).toLocaleString() : "-"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
