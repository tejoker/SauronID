"use client";

// Sprint 19-20: "Verify proof" button.
//
// Posts to `/api/proofs/action-log/verify` (proxied to the core
// `/v1/proofs/action-log/verify` endpoint). Surfaces success / error
// inline. Stateful only inside this component — no global mutation.

import { useState } from "react";
import { Button } from "../ui/Button";

interface ProofVerifyButtonProps {
  circuit: string;
  publicInputs: string[];
  expectedRootHex: string;
}

export function ProofVerifyButton({
  circuit,
  publicInputs,
  expectedRootHex,
}: ProofVerifyButtonProps) {
  const [status, setStatus] = useState<"idle" | "loading" | "ok" | "error">(
    "idle"
  );
  const [error, setError] = useState<string | null>(null);

  async function onClick() {
    setStatus("loading");
    setError(null);
    try {
      const res = await fetch("/api/proofs/action-log/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          circuit,
          public_inputs: publicInputs,
          expected_root_hex: expectedRootHex,
        }),
      });
      if (res.ok) {
        setStatus("ok");
        return;
      }
      const text = await res.text().catch(() => "");
      setStatus("error");
      setError(text || `HTTP ${res.status}`);
    } catch (err) {
      setStatus("error");
      setError(err instanceof Error ? err.message : "Network error");
    }
  }

  return (
    <div className="flex items-center gap-3" data-testid="proof-verify">
      <Button size="sm" variant="ghost" onClick={onClick} disabled={status === "loading"}>
        {status === "loading" ? "Verifying…" : "Verify proof"}
      </Button>
      {status === "ok" && (
        <span className="text-mono-sm text-[var(--status-ok)]">
          proof verified
        </span>
      )}
      {status === "error" && (
        <span className="text-mono-sm text-[var(--status-stopped)]">
          {error ?? "verification failed"}
        </span>
      )}
    </div>
  );
}
