"use client";

import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Button } from "@/components/ui/Button";
import { useTranslations } from "next-intl";
import { revokeAgent } from "@/lib/api";

interface Props {
  agentId: string;
  agentName: string;
  label: string;
}

export function RevokeButton({ agentId, agentName, label }: Props) {
  const t = useTranslations("agentDetail");
  const [open, setOpen] = useState(false);
  const [typed, setTyped] = useState("");

  async function handleRevoke() {
    // `revokeAgent` wraps this exact call and maps a non-2xx to an error
    // instead of swallowing it. It was the unused one of the pair while this
    // button ignored the status entirely.
    const res = await revokeAgent(agentId);
    if (!res.ok) {
      console.error(`revoke failed: ${res.error}`);
    }
    setOpen(false);
    window.location.reload();
  }

  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger asChild>
        <button className="text-sm text-[var(--status-stopped)] hover:opacity-80 transition-opacity duration-150">
          {label}
        </button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40 z-40" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md bg-[var(--bg-elevated)] border border-[var(--border)] rounded-lg p-6 focus:outline-none">
          <Dialog.Title className="text-base font-semibold text-[var(--text-primary)] mb-2">
            {t("revokeConfirmTitle")}
          </Dialog.Title>
          <Dialog.Description className="text-sm text-[var(--text-secondary)] mb-5 leading-relaxed">
            {t("revokeConfirmBody")}
          </Dialog.Description>

          <input
            type="text"
            value={typed}
            onChange={(e) => setTyped(e.target.value)}
            placeholder={agentName}
            className="w-full px-3 py-2 text-sm bg-[var(--bg-surface)] border border-[var(--border)] rounded text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus:outline-none focus:border-[var(--border-hover)] transition-colors duration-150 mb-4"
          />

          <div className="flex gap-3 justify-end">
            <Dialog.Close asChild>
              <Button variant="ghost" size="sm">{t("revokeCancel")}</Button>
            </Dialog.Close>
            <Button
              variant="danger"
              size="sm"
              disabled={typed !== agentName}
              onClick={handleRevoke}
            >
              {t("revokeConfirmButton")}
            </Button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
