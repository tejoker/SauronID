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
          <Sidebar />
          <main
            style={{ marginLeft: "var(--sw)", minHeight: "100vh", padding: "2rem" }}
          >
            {children}
          </main>
        </DashProvider>
      </body>
    </html>
  );
}
