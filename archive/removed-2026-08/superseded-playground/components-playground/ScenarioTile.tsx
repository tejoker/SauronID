"use client";

interface ScenarioTileProps {
  label: string;
  description: string;
  isRunning: boolean;
  isSelected?: boolean;
  onRun: () => void;
}

export function ScenarioTile({ label, description, isRunning, isSelected, onRun }: ScenarioTileProps) {
  return (
    <button
      onClick={onRun}
      disabled={isRunning}
      className={`w-full text-left bg-[var(--bg-surface)] border rounded-lg p-5 hover:border-[var(--border-hover)] transition-colors duration-150 ease-out disabled:opacity-50 disabled:pointer-events-none group ${isSelected ? "border-[var(--accent)]" : "border-[var(--border)]"}`}
    >
      <p className="text-sm font-medium text-[var(--text-primary)] mb-1.5">
        {label}
      </p>
      <p className="text-sm text-[var(--text-muted)] leading-relaxed">
        {description}
      </p>
    </button>
  );
}
