import { useCallback, useState } from "react";
import { api } from "@/api/client";
import type { ScenarioInfo, SimulationRead } from "@/api/types";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const RUNNING = new Set(["running", "queued", "stopping"]);

function statusTone(status: string): string {
  if (status === "running") return "emerald";
  if (status === "queued" || status === "stopping") return "amber";
  if (status === "failed") return "rose";
  return "slate";
}

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

export function SimulationPage() {
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [target, setTarget] = useState("127.0.0.1");

  const scenarios = useApi(() => api.simulationScenarios(), 30000);
  // Poll while any simulation is live so stats keep streaming.
  const sims = useApi(() => api.simulationList(), 2000);

  const refresh = useCallback(() => {
    sims.refetch();
  }, [sims]);

  const runScenario = async (s: ScenarioInfo) => {
    setBusyKey(s.key);
    setActionError(null);
    try {
      const created = await api.simulationCreate({
        scenario: s.key,
        name: s.name,
        target: target || "127.0.0.1",
        config: (s.default_config ?? {}) as Record<string, unknown>,
      });
      await api.simulationStart(created.id);
      sims.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to start scenario");
    } finally {
      setBusyKey(null);
    }
  };

  const stopSim = async (id: string) => {
    setBusyKey(`stop-${id}`);
    setActionError(null);
    try {
      await api.simulationStop(id);
      sims.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Failed to stop simulation");
    } finally {
      setBusyKey(null);
    }
  };

  const live = (sims.data ?? []).some((r) => RUNNING.has(r.status));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Traffic Simulation Center</h1>
        <p className="text-sm text-slate-400">
          Generate real controlled traffic against a lab target, then capture and analyze it.
        </p>
      </div>

      <Card>
        <div className="flex flex-wrap items-center gap-3 text-sm text-slate-300">
          <span className="text-slate-500">Lab target:</span>
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500 w-52"
            placeholder="127.0.0.1"
          />
          <span className="text-xs text-slate-500">
            Safety enforced server-side: only localhost, private ranges and Docker targets are allowed.
          </span>
        </div>
      </Card>

      {actionError && <ErrorState message={actionError} />}

      {scenarios.loading ? (
        <Spinner />
      ) : scenarios.error ? (
        <ErrorState message={scenarios.error} onRetry={scenarios.refetch} />
      ) : !scenarios.data || scenarios.data.length === 0 ? (
        <EmptyState message="No simulation scenarios registered." />
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {scenarios.data.map((s) => {
            const busy = busyKey === s.key;
            return (
              <Card key={s.key}>
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-200">{s.name}</h3>
                  {s.suspicious && <Badge tone="rose">anomaly</Badge>}
                </div>
                <p className="mt-1 text-xs text-slate-500 h-8">{s.description}</p>
                <div className="mt-2 text-[11px] text-slate-500">
                  {s.default_port ? `default port ${s.default_port}` : "no fixed port"}
                </div>
                <button
                  onClick={() => runScenario(s)}
                  disabled={busy || live}
                  className="mt-3 w-full px-3 py-2 rounded-lg bg-cyan-600 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-40"
                >
                  {busy ? <Spinner label="Starting…" /> : "Run scenario"}
                </button>
              </Card>
            );
          })}
        </div>
      )}

      {live && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
          Live simulation active — updating stats…
        </div>
      )}

      <Card title="Simulation history">
        {sims.loading && sims.data === null ? (
          <Spinner />
        ) : sims.error ? (
          <ErrorState message={sims.error} onRetry={sims.refetch} />
        ) : !sims.data || sims.data.length === 0 ? (
          <EmptyState message="No simulation runs yet. Run a scenario above." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-500 text-xs">
                  <th className="py-1 pr-3">Created</th>
                  <th className="py-1 pr-3">Scenario</th>
                  <th className="py-1 pr-3">Target</th>
                  <th className="py-1 pr-3">Status</th>
                  <th className="py-1 pr-3">Packets</th>
                  <th className="py-1 pr-3">Bytes</th>
                  <th className="py-1 pr-3">Conns</th>
                  <th className="py-1 pr-3">Rate/s</th>
                  <th className="py-1 pr-3">Duration</th>
                  <th className="py-1">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sims.data.map((r) => (
                  <SimRow key={r.id} r={r} busy={busyKey === `stop-${r.id}`} onStop={() => stopSim(r.id)} onRefresh={refresh} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}

function SimRow({ r, busy, onStop, onRefresh }: { r: SimulationRead; busy: boolean; onStop: () => void; onRefresh: () => void }) {
  const running = RUNNING.has(r.status);
  return (
    <tr className="border-t border-slate-800/60 text-slate-300">
      <td className="py-2 pr-3 text-xs">{r.created_at ? r.created_at.replace("T", " ").slice(0, 19) : "—"}</td>
      <td className="py-2 pr-3">{r.name || r.scenario}</td>
      <td className="py-2 pr-3 font-mono">{r.target}{r.target_port ? `:${r.target_port}` : ""}</td>
      <td className="py-2 pr-3">
        <Badge tone={statusTone(r.status)}>{r.status}</Badge>
      </td>
      <td className="py-2 pr-3">{r.packets_sent.toLocaleString()}</td>
      <td className="py-2 pr-3">{fmtBytes(r.bytes_sent)}</td>
      <td className="py-2 pr-3">{r.connections.toLocaleString()}</td>
      <td className="py-2 pr-3">{r.rates_per_sec.toLocaleString()}</td>
      <td className="py-2 pr-3">{r.duration_sec !== null && r.duration_sec !== undefined ? `${r.duration_sec.toFixed(1)}s` : "—"}</td>
      <td className="py-2">
        {running ? (
          <button
            onClick={onStop}
            disabled={busy}
            className="px-2 py-1 rounded-md bg-rose-600/80 text-xs text-white hover:bg-rose-500 disabled:opacity-40"
          >
            {busy ? "…" : "Stop"}
          </button>
        ) : (
          <button
            onClick={onRefresh}
            className="px-2 py-1 rounded-md bg-slate-700 text-xs text-slate-200 hover:bg-slate-600"
          >
            Refresh
          </button>
        )}
      </td>
    </tr>
  );
}