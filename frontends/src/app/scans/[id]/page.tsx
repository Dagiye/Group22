"use client";

import { useEffect, useState } from "react";
import { getScan } from "@/services/scanService";
import { useParams } from "next/navigation";
import EvidenceViewer from "@/components/EvidenceViewer";
import ScanProgress from "@/components/ScanProgress";

export default function ScanDetailsPage() {
  const params = useParams();
  const scanId = params.id as string;
  const [scan, setScan] = useState<any>(null);

  useEffect(() => {
    const interval = setInterval(async () => {
      const data = await getScan(scanId);
      setScan(data);
    }, 3000);

    return () => clearInterval(interval);
  }, [scanId]);

  if (!scan) return <p className="p-6">Loading...</p>;

  return (
    <div className="p-6">
      <h1 className="text-xl font-bold">Scan {scan.id}</h1>
      <p>Target: {scan.target}</p>
      <p>Status: {scan.status}</p>
      <ScanProgress value={scan.progress} />

      <h2 className="text-lg font-bold mt-4">Findings</h2>
      {scan.findings?.map((f: any, i: number) => (
        <EvidenceViewer key={i} finding={f} />
      ))}
    </div>
  );
}
