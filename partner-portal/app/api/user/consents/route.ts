import { NextRequest, NextResponse } from "next/server";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

export async function GET(req: NextRequest) {
  const session = req.headers.get("x-sauron-session") || "";
  const res = await fetch(`${API}/user/consents`, {
    headers: { "x-sauron-session": session },
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
