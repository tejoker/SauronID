"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { deletePolicy } from "@/lib/api";

interface PolicyDeleteButtonProps {
  policyId: string;
  agent: string;
}

export function PolicyDeleteButton({ policyId, agent }: PolicyDeleteButtonProps) {
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [typed, setTyped] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  // Focus the confirmation field when the confirm step opens.
  //
  // `autoFocus` did this on mount, which is a focus steal: it moves the caret
  // without the user having asked, and a screen-reader user loses their place.
  // Focusing in response to `confirming` flipping is a move the user just
  // requested by pressing Delete, which is the case where it is welcome.
  useEffect(() => {
    if (confirming) confirmRef.current?.focus();
  }, [confirming]);

  async function onConfirm() {
    setPending(true);
    setError(null);
    try {
      const r = await deletePolicy(policyId);
      if (!r.ok) {
        setError(r.error);
        return;
      }
      router.push("/policies");
    } finally {
      setPending(false);
    }
  }

  if (!confirming) {
    return (
      <button
        type="button"
        onClick={() => setConfirming(true)}
        className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--status-stopped)] text-white hover:opacity-90"
      >
        Delete
      </button>
    );
  }

  const canConfirm = typed === agent && !pending;

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <input
        ref={confirmRef}
        value={typed}
        onChange={(e) => setTyped(e.target.value)}
        placeholder={`Type "${agent}" to confirm`}
        className="font-mono text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded px-3 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
      />
      <button
        type="button"
        onClick={onConfirm}
        disabled={!canConfirm}
        className="inline-flex items-center gap-1.5 rounded-full font-sans font-medium px-5 py-2 text-sm bg-[var(--status-stopped)] text-white hover:opacity-90 disabled:opacity-40"
      >
        {pending ? "Deleting…" : "Confirm delete"}
      </button>
      <button
        type="button"
        onClick={() => {
          setConfirming(false);
          setTyped("");
          setError(null);
        }}
        className="text-sm text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
      >
        Cancel
      </button>
      {error && (
        <span className="text-sm text-[var(--status-stopped)] font-mono">
          {error}
        </span>
      )}
    </div>
  );
}
