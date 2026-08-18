// Sprint 19-20: anchor-chain inline badge.
//
// Surfaces the Bitcoin OTS + Solana memo references for one
// `AnchorChain` section, linking out to mempool.space + Solana
// Explorer when a public ref exists.

import { Badge } from "../ui/Badge";

interface AnchorChainBadgeProps {
  btcRoot: string | null;
  btcBlock: number | null;
  solanaSig: string | null;
  solanaSlot: number | null;
}

function btcUrl(root: string | null): string | null {
  if (!root) return null;
  // OTS calendar attestations land in a real Bitcoin block when
  // upgraded — we link to the mempool.space search-by-OP_RETURN
  // surface so the auditor can resolve the commitment to a tx.
  return `https://mempool.space/search?q=${encodeURIComponent(root)}`;
}

function solUrl(sig: string | null): string | null {
  if (!sig) return null;
  return `https://explorer.solana.com/tx/${encodeURIComponent(sig)}`;
}

export function AnchorChainBadge({
  btcRoot,
  btcBlock,
  solanaSig,
  solanaSlot,
}: AnchorChainBadgeProps) {
  return (
    <div className="flex flex-col gap-2" data-testid="anchor-chain-badge">
      <div className="flex items-center gap-2">
        <Badge variant={btcRoot ? "ok" : "neutral"}>BTC</Badge>
        {btcRoot ? (
          <a
            className="text-mono-sm text-[var(--accent-text)] hover:underline truncate max-w-[28ch]"
            href={btcUrl(btcRoot)!}
            target="_blank"
            rel="noopener noreferrer"
          >
            {btcRoot.slice(0, 12)}…
          </a>
        ) : (
          <span className="text-mono-sm text-[var(--text-muted)]">no anchor</span>
        )}
        {btcBlock !== null && (
          <span className="text-mono-sm text-[var(--text-muted)]">
            block {btcBlock}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Badge variant={solanaSig ? "ok" : "neutral"}>SOL</Badge>
        {solanaSig ? (
          <a
            className="text-mono-sm text-[var(--accent-text)] hover:underline truncate max-w-[28ch]"
            href={solUrl(solanaSig)!}
            target="_blank"
            rel="noopener noreferrer"
          >
            {solanaSig.slice(0, 12)}…
          </a>
        ) : (
          <span className="text-mono-sm text-[var(--text-muted)]">no anchor</span>
        )}
        {solanaSlot !== null && (
          <span className="text-mono-sm text-[var(--text-muted)]">
            slot {solanaSlot}
          </span>
        )}
      </div>
    </div>
  );
}
