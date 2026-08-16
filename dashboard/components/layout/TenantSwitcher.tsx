"use client";

// TenantSwitcher — dropdown of known tenant ids next to the user avatar.
//
// On mount we resolve the active tenant from the cookie/localStorage and
// fetch the list of available tenants from `/api/tenants`. Selecting an
// entry persists the choice via `setCurrentTenant`, which also dispatches
// the `sauron:tenant-changed` event; we then `router.refresh()` so RSCs
// re-render with the new tenant header forwarded by the middleware.
//
// Keyboard: Enter/Space/ArrowDown/ArrowUp open the listbox, Arrow keys move
// the focused option (roving focus), Home/End jump, Enter selects, Escape
// closes and returns focus to the trigger.

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import {
  availableTenants,
  currentTenant,
  DEFAULT_TENANT,
  setCurrentTenant,
} from "@/lib/tenant";

export function TenantSwitcher() {
  const router = useRouter();
  const [active, setActive] = useState<string>(DEFAULT_TENANT);
  const [tenants, setTenants] = useState<string[]>([DEFAULT_TENANT]);
  const [open, setOpen] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);

  // Hydrate active id once on mount (cookie/localStorage are browser-only).
  useEffect(() => {
    let cancelled = false;
    queueMicrotask(() => {
      if (!cancelled) setActive(currentTenant());
    });
    void availableTenants().then((list) => {
      if (!cancelled && list.length > 0) setTenants(list);
    });
    return () => {
      cancelled = true;
    };
  }, []);

  // Close the dropdown on outside-click.
  useEffect(() => {
    if (!open) return;
    function onClick(ev: MouseEvent) {
      if (!wrapRef.current) return;
      if (!wrapRef.current.contains(ev.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  // Roving focus — keep the focused option in sync with activeIndex.
  useEffect(() => {
    if (open) itemRefs.current[activeIndex]?.focus();
  }, [open, activeIndex]);

  function openList(index: number) {
    setActiveIndex(Math.max(0, Math.min(index, tenants.length - 1)));
    setOpen(true);
  }

  function closeList(returnFocus: boolean) {
    setOpen(false);
    if (returnFocus) triggerRef.current?.focus();
  }

  function pick(id: string) {
    closeList(true);
    if (id === active) return;
    setCurrentTenant(id);
    setActive(id);
    // RSC + route handlers read the cookie via middleware → refresh.
    router.refresh();
  }

  function onTriggerKeyDown(ev: React.KeyboardEvent) {
    const selected = Math.max(0, tenants.indexOf(active));
    switch (ev.key) {
      case "Enter":
      case " ":
      case "ArrowDown":
        ev.preventDefault();
        openList(selected);
        break;
      case "ArrowUp":
        ev.preventDefault();
        openList(tenants.length - 1);
        break;
    }
  }

  function onListKeyDown(ev: React.KeyboardEvent) {
    switch (ev.key) {
      case "ArrowDown":
        ev.preventDefault();
        setActiveIndex((i) => (i + 1) % tenants.length);
        break;
      case "ArrowUp":
        ev.preventDefault();
        setActiveIndex((i) => (i - 1 + tenants.length) % tenants.length);
        break;
      case "Home":
        ev.preventDefault();
        setActiveIndex(0);
        break;
      case "End":
        ev.preventDefault();
        setActiveIndex(tenants.length - 1);
        break;
      case "Escape":
        ev.preventDefault();
        closeList(true);
        break;
      case "Tab":
        closeList(false);
        break;
    }
  }

  return (
    <div ref={wrapRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label="Switch tenant"
        onClick={() => (open ? closeList(false) : openList(Math.max(0, tenants.indexOf(active))))}
        onKeyDown={onTriggerKeyDown}
        className="inline-flex items-center gap-1.5 px-2 py-1 text-xs font-mono rounded border border-[var(--border)] bg-[var(--bg-surface)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
        data-testid="tenant-switcher-button"
      >
        <span className="text-[var(--text-muted)] uppercase tracking-wide">tenant</span>
        <span className="text-[var(--text-primary)] truncate max-w-[10rem]">{active}</span>
        <svg
          aria-hidden
          viewBox="0 0 12 12"
          className="h-2.5 w-2.5 opacity-70"
          fill="currentColor"
        >
          <path d="M2 4l4 4 4-4z" />
        </svg>
      </button>

      {open && (
        <ul
          role="listbox"
          aria-label="Available tenants"
          // No aria-activedescendant: this listbox uses roving focus (the
          // effect above calls .focus() on the active option's button), and the
          // two patterns are alternatives, not complements. Declaring both
          // pointed assistive tech at the <li> while real focus sat on the
          // <button> inside it — two different answers to "what is focused".
          onKeyDown={onListKeyDown}
          className="absolute right-0 mt-1 min-w-[14rem] max-h-72 overflow-y-auto z-50 rounded border border-[var(--border)] bg-[var(--bg)] shadow-lg"
          data-testid="tenant-switcher-menu"
        >
          {tenants.map((id, index) => {
            const isActive = id === active;
            return (
              <li key={id} role="option" aria-selected={isActive} id={`tenant-option-${index}`}>
                <button
                  ref={(el) => {
                    itemRefs.current[index] = el;
                  }}
                  type="button"
                  tabIndex={-1}
                  onClick={() => pick(id)}
                  className={`w-full text-left px-3 py-1.5 text-xs font-mono flex items-center justify-between gap-2 hover:bg-[var(--bg-surface)] focus-visible:outline-none focus-visible:bg-[var(--bg-surface)] focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-[var(--accent)] ${
                    isActive
                      ? "text-[var(--accent-text)]"
                      : "text-[var(--text-secondary)]"
                  }`}
                >
                  <span className="truncate">{id}</span>
                  {isActive && (
                    <span aria-hidden className="text-[var(--accent-text)]">
                      ✓
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
