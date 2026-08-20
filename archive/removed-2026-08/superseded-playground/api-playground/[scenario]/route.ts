import { NextRequest } from "next/server";
import { proxyCore } from "../../_proxy";

// The "Try" page now runs REAL governance scenarios against the core:
//   normal | replay | scope  ->  POST /admin/demo/scenario/{scenario}
// The core returns { result: "allowed"|"stopped", status_code, detail } after
// exercising the live replay-protection store / tool-allowlist invariant.
const REAL = new Set(["normal", "replay", "scope"]);

export async function POST(
  req: NextRequest,
  { params }: { params: Promise<{ scenario: string }> }
) {
  const { scenario } = await params;

  if (REAL.has(scenario)) {
    return proxyCore(`demo/scenario/${encodeURIComponent(scenario)}`, req, {
      method: "POST",
      forwardQuery: false,
    });
  }

  // "custom" (and anything else) exercises the same governance path
  // conceptually but has no dedicated core scenario — report honestly.
  return Response.json({
    result: "stopped",
    status_code: 400,
    detail: {
      scenario,
      note: "custom scenarios use the same governance path; pick replay or scope for a live verdict",
    },
  });
}
