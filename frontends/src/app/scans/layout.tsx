// app/scans/layout.tsx
export default function ScansLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-gray-50 min-h-screen p-6">
      {children}
    </div>
  );
}
