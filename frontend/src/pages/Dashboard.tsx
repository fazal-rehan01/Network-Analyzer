import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

export default function Dashboard() {
  const health = useApi(() => api.health(), 15000);
  const sys = useApi(() => api.systemStatus(), 15000);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Dashboard</h1>
        <p className="text-sm text-slate-400">Live network posture. Charts populate from real analyzed data after captures.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <Card title="API Status">
          {health.loading ? <Spinner /> : health.error ? <ErrorState message={health.error} /> : (
            <div className="flex items-center gap-2">
              <Badge tone={health.data?.database === "ok" ? "emerald" : "rose"}>
                {health.data?.status}
              </Badge>
              <span className="text-sm text-slate-400">{health.data?.app}</span>
            </div>
          )}
        </Card>
        <Card title="Database">
          <div className="text-2xl font-semibold">{health.data?.database ?? "—"}</div>
        </Card>
        <Card title="External Tools">
          {sys.loading ? <Spinner /> : sys.error ? <ErrorState message={sys.error} /> : (
            <div className="space-y-1.5">
              {sys.data?.components.filter((c) => c.name !== "Platform" && c.name !== "Python").map((c) => (
                <div key={c.name} className="flex items-center justify-between text-sm">
                  <span className="text-slate-300">{c.name}</span>
                  <Badge tone={c.installed ? "emerald" : "rose"}>{c.installed ? "Installed" : "Missing"}</Badge>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="Capture State">
          <EmptyState message="No active capture. Start a simulation or live capture." />
        </Card>
      </div>

      <p className="text-xs text-slate-600">
        Analytics (protocol distribution, top talkers, traffic over time, alerts) will appear here in the dashboard milestone
        once simulation, capture and analysis are wired end-to-end.
      </p>
    </div>
  );
}
