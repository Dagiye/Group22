"use client";

import { useState } from "react";
import ScanForm from "@/components/ScanForm";
import ScanTable from "@/components/ScanTable";
import { Card, CardContent } from "@/components/ui/card";

export default function ScansPage() {
  const [refresh, setRefresh] = useState(0);

  const handleScanStarted = () => {
    setRefresh((prev) => prev + 1); // refresh scan table
  };

  return (
    <div className="p-6 space-y-6">
      <Card>
        <CardContent>
          <h1 className="text-xl font-bold mb-4">Start New Scan</h1>
          <ScanForm onScanStarted={handleScanStarted} />
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <h2 className="text-xl font-bold mb-4">All Scans</h2>
          <ScanTable refresh={refresh} />
        </CardContent>
      </Card>
    </div>
  );
}
