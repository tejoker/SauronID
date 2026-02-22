"use client";

import { useEffect, useState, useCallback } from "react";

export type ToastType = "success" | "error" | "warning" | "info";

export interface Toast {
  id: number;
  type: ToastType;
  title: string;
  body?: string;
}

let _toastId = 0;
type Listener = (t: Toast) => void;
const listeners = new Set<Listener>();

export function showToast(type: ToastType, title: string, body?: string) {
  const id = ++_toastId;
  listeners.forEach((l) => l({ id, type, title, body }));
}

const COLORS: Record<ToastType, string> = {
  success: "border-green-300 bg-white text-green-800",
  error:   "border-red-300 bg-white text-red-700",
  warning: "border-orange-300 bg-white text-orange-700",
  info:    "border-neutral-300 bg-white text-neutral-700",
};

export function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([]);

  const remove = useCallback((id: number) => {
    setToasts((p) => p.filter((t) => t.id !== id));
  }, []);

  useEffect(() => {
    const handler: Listener = (t) => {
      setToasts((p) => [...p.slice(-4), t]);
      setTimeout(() => remove(t.id), 5000);
    };
    listeners.add(handler);
    return () => { listeners.delete(handler); };
  }, [remove]);

  if (!toasts.length) return null;

  return (
    <div className="fixed bottom-5 right-5 z-[100] flex flex-col gap-2 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-lg border shadow-md transition-all ${COLORS[t.type]}`}
        >
          <div className="flex-1 min-w-0">
            <p className="font-semibold text-sm">{t.title}</p>
            {t.body && <p className="text-xs mt-0.5 opacity-70 break-words">{t.body}</p>}
          </div>
          <button
            onClick={() => remove(t.id)}
            className="text-xs opacity-40 hover:opacity-80 flex-shrink-0"
          >x</button>
        </div>
      ))}
    </div>
  );
}
