import { NextResponse } from "next/server";

/**
 * Server-side proxy for /admin/stats.
 * The SAURON_ADMIN_KEY secret never reaches the browser.
 */
export async function GET() {
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
  const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";

  try {
    const res = await fetch(`${apiUrl}/admin/stats`, {
      headers: { "x-admin-key": adminKey },
      next: { revalidate: 5 },
    });
    if (!res.ok) return NextResponse.json({ error: "upstream error" }, { status: res.status });
    const data = await res.json();
    return NextResponse.json(data);
  } catch {
    return NextResponse.json({ error: "backend unreachable" }, { status: 503 });
  }
}
