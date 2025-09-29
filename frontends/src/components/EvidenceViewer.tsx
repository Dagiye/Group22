// src/components/EvidenceViewer.tsx
"use client";

interface EvidenceViewerProps {
  finding: any; // replace 'any' with a proper type if you know it
}

export default function EvidenceViewer({ finding }: EvidenceViewerProps) {
  return (
    <div className="border p-2 my-2 rounded">
      <pre>{JSON.stringify(finding, null, 2)}</pre>
    </div>
  );
}
