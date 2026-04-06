import { NextResponse, NextRequest } from "next/server";

/**
 * Server-side proxy for all /admin/* endpoints.
 * Injects SAURON_ADMIN_KEY — never exposed to the browser.
 */
export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
  const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";
  const upstream = `${apiUrl}/admin/${path.join("/")}`;

  try {
    const res = await fetch(upstream, { headers: { "x-admin-key": adminKey } });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: "upstream error" }, { status: 503 });
  }
}

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
  const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";
  const upstream = `${apiUrl}/admin/${path.join("/")}`;
  const body = await req.text();

  try {
    const res = await fetch(upstream, {
      method: "POST",
      headers: { "x-admin-key": adminKey, "content-type": "application/json" },
      body,
    });
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json({ error: "upstream error" }, { status: 503 });
  }
}
