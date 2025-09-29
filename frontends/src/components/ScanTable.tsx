"use client";

import { useEffect, useState } from "react";
import { listScans, cancelScan } from "@/services/scanService";
import Link from "next/link";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/use-toast";

export default function ScanTable({ refresh }: { refresh: number }) {
  const [scans, setScans] = useState<any[]>([]);
  const { addToast } = useToast();

  useEffect(() => {
    (async () => {
      const data = await listScans();
      setScans(data);
    })();
  }, [refresh]);

  const handleCancel = async (id: string) => {
    try {
      await cancelScan(id);
      addToast({ title: "⛔ Scan cancelled" });
      setScans((prev) =>
        prev.map((s) => (s.id === id ? { ...s, status: "cancelled" } : s))
      );
    } catch (err: any) {
      addToast({ title: "❌ Cancel failed", description: err?.message });
    }
  };

  return (
    <table className="w-full border mt-4">
      <thead className="bg-gray-100">
        <tr>
          <th>ID</th>
          <th>Target</th>
          <th>Status</th>
          <th>Started</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((s) => (
          <tr key={s.id} className="border-t">
            <td>{s.id}</td>
            <td>{s.target}</td>
            <td>{s.status}</td>
            <td>{new Date(s.created_at).toLocaleString()}</td>
            <td className="space-x-2">
              <Link href={`/scans/${s.id}`}>
                <Button size="sm" className="bg-gray-600 hover:bg-gray-700">
                  View
                </Button>
              </Link>
              {s.status === "running" && (
                <Button
                  size="sm"
                  className="bg-red-600 hover:bg-red-700"
                  onClick={() => handleCancel(s.id)}
                >
                  Cancel
                </Button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
