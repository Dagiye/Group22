"use client";

import { useState } from "react";
import { startScan } from "@/services/scanService";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/components/ui/use-toast";

export default function ScanForm({ onScanStarted }: { onScanStarted: () => void }) {
  const [target, setTarget] = useState("");
  const { addToast } = useToast(); // must use addToast

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await startScan(target);
      addToast({ title: "✅ Scan started" });
      setTarget("");
      onScanStarted();
    } catch (err: any) {
      addToast({ title: "❌ Failed to start scan", description: err.message });
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex gap-2">
      <Input
        placeholder="https://target.com"
        value={target}
        onChange={(e) => setTarget(e.target.value)}
        className="flex-1"
      />
      <Button type="submit" className="bg-blue-600 hover:bg-blue-700 transition">
        Start Scan
      </Button>
    </form>
  );
}
