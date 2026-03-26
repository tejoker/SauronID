import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { ClientProvider } from "./context/ClientContext";
import NavBar from "./components/NavBar";
import { ToastContainer } from "./components/Toast";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Sauron — Partner Portal",
  description: "Partner Portal — Zero-Knowledge KYC Infrastructure",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-white text-neutral-900`}
      >
        <ClientProvider>
          <NavBar />
          <main>{children}</main>
          <ToastContainer />
        </ClientProvider>
      </body>
    </html>
  );
}

