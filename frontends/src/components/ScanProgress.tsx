"use client";
import { Progress } from "@/components/ui/progress";

export default function ScanProgress({ value }: { value: number }) {
  return (
    <div className="mt-2">
      <Progress value={value} />
      <p className="text-sm text-gray-600">{value}% complete</p>
    </div>
  );
}
