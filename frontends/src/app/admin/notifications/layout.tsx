import "../../globals.css";

export default function NotificationsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="bg-gray-50">
        <div className="max-w-6xl mx-auto p-6">
          {children}
        </div>
      </body>
    </html>
  );
}
