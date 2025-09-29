// src/components/DashboardCards.tsx
import React from "react";
import { Scan } from "../utils/types";

type Props = {
  scans: Scan[];
};

export default function DashboardCards({ scans }: Props) {
  const total = scans.length;
  const completed = scans.filter((s) => s.status === "completed").length;
  const running = scans.filter((s) => s.status === "running").length;
  const failed = scans.filter((s) => s.status === "failed").length;

  return (
    <div className="grid grid-cols-4 gap-4">
      <div className="card p-4 shadow rounded-2xl">Total: {total}</div>
      <div className="card p-4 shadow rounded-2xl text-green-600">
        Completed: {completed}
      </div>
      <div className="card p-4 shadow rounded-2xl text-blue-600">
        Running: {running}
      </div>
      <div className="card p-4 shadow rounded-2xl text-red-600">
        Failed: {failed}
      </div>
    </div>
  );
}
