import { Link } from "react-router-dom";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { SeverityBadge, StatusBadge } from "@/pages/IncidentsPage";

export default function Dashboard() {
  const health = useApi(() => api.health(), 15000);
  const sys = useApi(() => api.systemStatus(), 15000);
  const incidents = useApi(() => api.incidentSummary(), 30000);

  const unresolvedHighCrit = (incidents.data?.recent ?? []).filter(
    (i) =>
      (i.severity === "high" || i.severity === "critical") &&
      (i.status === "NEW" || i.status === "INVESTIGATING" || i.status === "CONTAINED")
  );

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
        <Card title="Open Incidents">
          {incidents.loading ? <Spinner /> : incidents.error ? <ErrorState message={incidents.error} /> : (
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-semibold text-cyan-300">{incidents.data?.open ?? 0}</span>
              <span className="text-sm text-slate-400">/ {incidents.data?.total ?? 0} total</span>
            </div>
          )}
        </Card>
        <Card title="Critical / High">
          {incidents.loading ? <Spinner /> : incidents.error ? <ErrorState message={incidents.error} /> : (
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-semibold text-rose-300">
                {(incidents.data?.critical ?? 0) + (incidents.data?.high ?? 0)}
              </span>
              <span className="text-sm text-slate-400">unresolved: {unresolvedHighCrit.length}</span>
            </div>
          )}
        </Card>
        <Card title="Resolved">
          {incidents.loading ? <Spinner /> : incidents.error ? <ErrorState message={incidents.error} /> : (
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-semibold text-emerald-300">{incidents.data?.resolved ?? 0}</span>
              <span className="text-sm text-slate-400">FP: {incidents.data?.false_positive ?? 0}</span>
            </div>
          )}
        </Card>
      </div>

      <Card
        title="Recent Incidents"
        actions={
          <Link to="/incidents" className="text-xs text-cyan-300 hover:text-cyan-200 underline">
            Open incidents →
          </Link>
        }
      >
        {incidents.loading ? (
          <Spinner />
        ) : incidents.error ? (
          <ErrorState message={incidents.error} onRetry={incidents.refetch} />
        ) : !incidents.data || incidents.data.recent.length === 0 ? (
          <EmptyState message="No incidents created yet. Promote detection findings from the /detect page." />
        ) : (
          <div className="space-y-2">
            {incidents.data.recent.map((i) => (
              <Link
                key={i.id}
                to="/incidents"
                className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-800/30 p-3 hover:bg-slate-800/60"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm text-slate-100 font-medium">{i.title}</div>
                  <div className="text-[11px] text-slate-500">{i.rule_name ?? i.rule_id}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityBadge severity={i.severity} />
                  <StatusBadge status={i.status} />
                </div>
              </Link>
            ))}
          </div>
        )}
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
  );
}
