import type { Metadata } from "next";
import "./globals.css";
import { DashProvider } from "./context/DashContext";
import Sidebar from "./components/Sidebar";

export const metadata: Metadata = {
  title: "Sauron — Admin Console",
  description: "Real-time analytics and compliance dashboard",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <DashProvider>
          <div className="flex min-h-screen">
            <Sidebar />
            <main className="flex-1 overflow-auto px-10 py-8 space-y-6">
              {children}
            </main>
          </div>
        </DashProvider>
      </body>
    </html>
  );
}
