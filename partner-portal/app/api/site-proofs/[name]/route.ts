import { NextResponse } from "next/server";

export async function GET(_req: Request, { params }: { params: Promise<{ name: string }> }) {
  const { name } = await params;
  const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";
  const adminKey = process.env.SAURON_ADMIN_KEY || "super_secret_hackathon_key";

  try {
    const res = await fetch(
      `${apiUrl}/admin/site/${encodeURIComponent(name)}/zkp_proofs`,
      { headers: { "x-admin-key": adminKey } }
    );
    if (!res.ok) return NextResponse.json([], { status: res.status });
    return NextResponse.json(await res.json());
  } catch {
    return NextResponse.json([], { status: 503 });
  }
}
