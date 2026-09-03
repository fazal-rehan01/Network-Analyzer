import { api } from "@/api/client";
import type { ComponentStatus } from "@/api/types";
import { useApi } from "@/hooks/useApi";

function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ${
        ok ? "bg-emerald-500/10 text-emerald-300" : "bg-rose-500/10 text-rose-300"
      }`}
      title={label}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${ok ? "bg-emerald-400" : "bg-rose-400"}`} />
      {label}
    </span>
  );
}

export function TopBar() {
  const health = useApi(() => api.health(), 10000);
  const sys = useApi(() => api.systemStatus(), 10000);

  const keyInstalled = (name: string) =>
    sys.data?.components.find((c: ComponentStatus) => c.name === name)?.installed ?? null;

  return (
    <header className="h-14 shrink-0 border-b border-slate-800 bg-slate-900/60 flex items-center justify-between px-5">
      <div className="flex items-center gap-2 text-sm text-slate-300">
        <span
          className={`w-2 h-2 rounded-full ${
            health.data?.status === "ok"
              ? "bg-emerald-400 animate-pulse"
              : health.error
              ? "bg-rose-400"
              : "bg-amber-400"
          }`}
        />
        <span className="font-medium">API</span>
        <span className="text-slate-500">
          {health.loading
            ? "checking…"
            : health.error
            ? "offline"
            : health.data?.database === "ok"
            ? "connected"
            : "degraded"}
        </span>
      </div>
      <div className="flex items-center gap-2">
        <StatusDot ok={keyInstalled("TShark") === true} label={keyInstalled("TShark") ? "TShark" : "TShark missing"} />
        <StatusDot ok={keyInstalled("Zeek") === true} label={keyInstalled("Zeek") ? "Zeek" : "Zeek missing"} />
        <StatusDot ok={keyInstalled("Docker") === true} label={keyInstalled("Docker") ? "Docker" : "Docker"} />
      </div>
    </header>
  );
}
