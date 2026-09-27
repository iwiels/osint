import type { ReactNode } from "react";

interface EmptyStateProps {
  label: string;
  body: string;
  icon?: ReactNode;
}

export function EmptyState({ label, body, icon }: EmptyStateProps) {
  return (
    <div className="flex flex-1 items-center justify-center p-8">
      <div className="anim-rise flex max-w-sm flex-col items-center rounded-lg border border-border-weak-base bg-surface-raised-base p-7 text-center shadow-paper-sm">
        {icon && <div className="mb-3 text-icon-weak-base">{icon}</div>}
        <div className="label-caps mb-2 text-text-strong font-mono tracking-wider">{label}</div>
        <p className="text-[13px] leading-relaxed text-text-base">{body}</p>
      </div>
    </div>
  );
}
