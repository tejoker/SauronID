// Sprint 19-20: dashboard proxy → core /v1/audit/reports.
//
// Same proxy style as the other /api/* routes — forwards GET +
// POST to `${CORE_INTERNAL_URL}/v1/audit/reports` with x-admin-key.

import { NextRequest } from "next/server";
import { proxyCoreV1 } from "../../_proxy";

export async function GET(req: NextRequest) {
  return proxyCoreV1("audit/reports", req, { method: "GET" });
}

export async function POST(req: NextRequest) {
  const body = await req.text();
  return proxyCoreV1("audit/reports", req, {
    method: "POST",
    body,
    extraHeaders: { "content-type": "application/json" },
    forwardQuery: false,
  });
}
