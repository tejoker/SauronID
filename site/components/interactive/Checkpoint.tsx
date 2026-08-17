"use client";

import { useEffect, useRef, useState } from "react";

/**
 * One stop on the page-scale boundary path. The rail segment draws and the
 * dot lights the first time the section enters the viewport — the page's
 * single authored motion system, alongside the run demo.
 */
export default function Checkpoint({
  index,
  kind,
  proof = false,
  children,
}: {
  index: number;
  kind: string;
  proof?: boolean;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLElement>(null);
  const [isOn, setIsOn] = useState(false);

  useEffect(() => {
    const node = ref.current;
    if (!node || !("IntersectionObserver" in window)) {
      setIsOn(true);
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsOn(true);
            observer.disconnect();
          }
        });
      },
      { threshold: 0.18 }
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      ref={ref}
      aria-label={kind}
      className={`checkpoint${proof ? " checkpoint-proof dark" : ""}${isOn ? " on" : ""}`}
    >
      <div>
        <span className="checkpoint-dot" aria-hidden="true">
          {index}
        </span>
        <span className="checkpoint-rail" aria-hidden="true" />
      </div>
      <div className="checkpoint-body">{children}</div>
    </section>
  );
}
