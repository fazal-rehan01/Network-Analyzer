import type { ReactNode } from "react";

export function Card({
  title,
  children,
  className = "",
  actions,
}: {
  title?: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
}) {
  return (
    <div className={`rounded-xl border border-slate-800 bg-slate-900/50 ${className}`}>
      {(title || actions) && (
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          {title && <h3 className="text-sm font-semibold text-slate-200">{title}</h3>}
          {actions}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  );
}

export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex items-center justify-center py-12 text-slate-500">
      <svg className="animate-spin w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
      </svg>
      {label}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="text-center py-10">
      <div className="text-rose-300 mb-2">Unable to load data</div>
      <div className="text-sm text-slate-500 mb-4">{message}</div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="px-3 py-1.5 rounded-lg bg-slate-800 text-sm hover:bg-slate-700"
        >
          Retry
        </button>
      )}
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="text-center py-10 text-sm text-slate-500">{message}</div>
  );
}

export function Badge({ tone = "slate", children }: { tone?: string; children: ReactNode }) {
  const tones: Record<string, string> = {
    slate: "bg-slate-700/40 text-slate-300",
    emerald: "bg-emerald-500/10 text-emerald-300",
    amber: "bg-amber-500/10 text-amber-300",
    rose: "bg-rose-500/10 text-rose-300",
    cyan: "bg-cyan-500/10 text-cyan-300",
    violet: "bg-violet-500/10 text-violet-300",
  };
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-medium ${tones[tone] ?? tones.slate}`}>
      {children}
    </span>
  );
}
