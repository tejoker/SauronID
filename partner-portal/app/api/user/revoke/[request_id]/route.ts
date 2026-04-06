import { NextRequest, NextResponse } from "next/server";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001";

export async function DELETE(
  req: NextRequest,
  { params }: { params: { request_id: string } }
) {
  const session = req.headers.get("x-sauron-session") || "";
  const res = await fetch(`${API}/user/consent/${params.request_id}`, {
    method: "DELETE",
    headers: { "x-sauron-session": session },
  });
  const data = await res.json();
  return NextResponse.json(data, { status: res.status });
}
