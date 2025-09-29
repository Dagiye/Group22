// app/layout.tsx
import "./globals.css";
import { AuthProvider } from "@/hooks/useAuths";
import { ToastProvider } from "@/components/ui/use-toast";
import Navbar from "@/components/Navbar";

export const metadata = {
  title: "My App",
  description: "Next.js 15 App",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <ToastProvider>
            <Navbar />
            {children}
          </ToastProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
