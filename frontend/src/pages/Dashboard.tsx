import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/api/client";
import type {
  DashboardAnalytics,
  SeverityCount,
} from "@/api/types";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import { SeverityBadge, StatusBadge } from "@/pages/IncidentsPage";

const SEVERITY_COLORS: Record<string, string> = {
  info: "#38bdf8",
  low: "#34d399",
  medium: "#fbbf24",
  high: "#fb923c",
  critical: "#f87171",
};

const PROTO_COLORS = [
  "#38bdf8",
  "#a78bfa",
  "#34d399",
  "#fbbf24",
  "#f472b6",
  "#60a5fa",
  "#fb923c",
  "#4ade80",
];

function fmtBytes(n: number): string {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

function fmtNum(n: number): string {
  return (n ?? 0).toLocaleString();
}

function severityToArray(sc: SeverityCount): { name: string; count: number; color: string }[] {
  return (["info", "low", "medium", "high", "critical"] as const)
    .map((s) => ({ name: s, count: sc[s] ?? 0, color: SEVERITY_COLORS[s] }))
    .filter((s) => s.count > 0 || s.name !== "info");
}

interface ChartCardProps {
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  emptyMessage?: string;
}

function ChartCard({ title, subtitle, children, emptyMessage }: ChartCardProps) {
  return (
    <Card title={title}>
      {subtitle && <p className="mb-3 text-xs text-slate-500">{subtitle}</p>}
      <div className="h-64">{children}</div>
      {emptyMessage && (
        <p className="mt-2 text-xs text-slate-500">{emptyMessage}</p>
      )}
    </Card>
  );
}

export default function Dashboard() {
  const [captureId, setCaptureId] = useState<string>("");
  const health = useApi(() => api.health(), 15000);
  const sys = useApi(() => api.systemStatus(), 15000);
  const captures = useApi(() => api.captureList(), 30000);
  const analytics = useApi(
    useCallback(() => api.analyticsDashboard(captureId || undefined), [captureId]),
    30000,
  );

  const a: DashboardAnalytics | null = analytics.data;
  const summary = a?.summary;
  const hasData = (a?.summary.packets ?? 0) > 0 || (a?.summary.connections ?? 0) > 0 || (a?.summary.captures ?? 0) > 0;

  const trayTraffic = (a?.traffic_over_time ?? []).map((p) => ({
    ...p,
    time: new Date((p.ts ?? 0) * 1000).toISOString().slice(11, 19),
  }));

  const protocolData = (a?.protocol_distribution ?? []).map((p) => ({
    name: p.proto || "unknown",
    value: p.count,
  }));

  const sevData = a ? severityToArray(a.detection) : [];
  const incSevData = a ? severityToArray(a.incidents) : [];

  const dnsRcode = Object.entries(a?.dns_stats.by_rcode ?? {}).map(([name, count]) => ({ name, count }));
  const httpMethods = Object.entries(a?.http_stats.by_method ?? {}).map(([name, count]) => ({ name, count }));

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Dashboard</h1>
          <p className="text-sm text-slate-400">
            Real-time analytics computed from live database data.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <span className="text-slate-500">Scope:</span>
          <select
            value={captureId}
            onChange={(e) => setCaptureId(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">All captures (global)</option>
            {captures.data?.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      {analytics.loading ? (
        <Spinner label="Computing analytics…" />
      ) : analytics.error ? (
        <ErrorState message={analytics.error} onRetry={analytics.refetch} />
      ) : (
        <>
          {!hasData && (
            <EmptyState message="No analyzed data yet. Run a simulation or upload/analyze a PCAP to populate the dashboard with real traffic analytics." />
          )}

          {/* KPI cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <Card title="Total Packets">
              {a ? <Kpi value={fmtNum(summary?.packets ?? 0)} sub={`${fmtNum(summary?.packets_per_sec ?? 0)}/sec`} /> : <Spinner />}
            </Card>
            <Card title="Total Connections">
              {a ? <Kpi value={fmtNum(summary?.connections ?? 0)} sub={`${fmtNum(summary?.captures ?? 0)} captures`} /> : <Spinner />}
            </Card>
            <Card title="Total Bytes">
              {a ? <Kpi value={fmtBytes(summary?.bytes_total ?? 0)} sub="across normalized flows" /> : <Spinner />}
            </Card>
            <Card title="Open Incidents">
              {a ? (
                <Kpi
                  value={fmtNum(summary?.open_incidents ?? 0)}
                  sub={`${fmtNum(summary?.high_critical_incidents ?? 0)} high/critical`}
                  accent="text-rose-300"
                />
              ) : (
                <Spinner />
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard
              title="Traffic Over Time"
              subtitle="Packets and bytes per second"
              emptyMessage={!trayTraffic.length ? "No packet timestamps recorded for this scope." : undefined}
            >
              {trayTraffic.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={trayTraffic} margin={{ top: 5, right: 8, left: 0, bottom: 0 }}>
                    <defs>
                      <linearGradient id="packetsGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.6} />
                        <stop offset="95%" stopColor="#38bdf8" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Area type="monotone" dataKey="packets" name="Packets" stroke="#38bdf8" fill="url(#packetsGrad)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No traffic data in this scope." />
              )}
            </ChartCard>

            <ChartCard
              title="Protocol Distribution"
              subtitle="Connections by protocol"
              emptyMessage={!protocolData.length ? "No connections recorded." : undefined}
            >
              {protocolData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={protocolData} dataKey="value" nameKey="name" outerRadius={90} label>
                      {protocolData.map((entry, i) => (
                        <Cell key={entry.name} fill={PROTO_COLORS[i % PROTO_COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No connections recorded." />
              )}
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard
              title="Top Source IPs"
              subtitle="By connection count"
              emptyMessage={!a?.top_sources.length ? "No source talkers recorded." : undefined}
            >
              {a?.top_sources.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={a.top_sources} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <YAxis type="category" dataKey="ip" width={110} stroke="#64748b" tick={{ fontSize: 11 }} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="packets" name="Packets" fill="#38bdf8" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No source talkers recorded." />
              )}
            </ChartCard>

            <ChartCard
              title="Top Destination IPs"
              subtitle="By connection count"
              emptyMessage={!a?.top_destinations.length ? "No destination talkers recorded." : undefined}
            >
              {a?.top_destinations.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={a.top_destinations} layout="vertical" margin={{ left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis type="number" stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <YAxis type="category" dataKey="ip" width={110} stroke="#64748b" tick={{ fontSize: 11 }} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="packets" name="Packets" fill="#a78bfa" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No destination talkers recorded." />
              )}
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <ChartCard
              title="Detection Severity"
              subtitle="Detection findings by severity"
              emptyMessage={!sevData.length ? "No detections recorded." : undefined}
            >
              {sevData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={sevData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="count" name="Findings">
                      {sevData.map((s) => (
                        <Cell key={s.name} fill={s.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No detections recorded." />
              )}
            </ChartCard>

            <ChartCard
              title="Incident Severity"
              subtitle="Incidents by severity"
              emptyMessage={!incSevData.length ? "No incidents recorded." : undefined}
            >
              {incSevData.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={incSevData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="count" name="Incidents">
                      {incSevData.map((s) => (
                        <Cell key={s.name} fill={s.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No incidents recorded." />
              )}
            </ChartCard>

            <ChartCard
              title="DNS Activity"
              subtitle="Responses by rcode"
              emptyMessage={!dnsRcode.length ? "No DNS events recorded." : undefined}
            >
              {dnsRcode.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={dnsRcode}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="count" name="Events" fill="#34d399" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No DNS events recorded." />
              )}
            </ChartCard>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <ChartCard
              title="HTTP Activity"
              subtitle="Requests by method"
              emptyMessage={!httpMethods.length ? "No HTTP events recorded." : undefined}
            >
              {httpMethods.length ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={httpMethods}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 11 }} allowDecimals={false} />
                    <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #334155", color: "#e2e8f0" }} />
                    <Bar dataKey="count" name="Requests" fill="#fbbf24" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <EmptyState message="No HTTP events recorded." />
              )}
            </ChartCard>

            <Card
              title="Recent Incidents"
              actions={
                <Link to="/incidents" className="text-xs text-cyan-300 hover:text-cyan-200 underline">
                  Open incidents →
                </Link>
              }
            >
              {!a ? (
                <Spinner />
              ) : !a.recent_incidents.length ? (
                <EmptyState message="No incidents created yet. Promote detection findings from the /detect page." />
              ) : (
                <div className="space-y-2">
                  {a.recent_incidents.map((inc) => (
                    <Link
                      key={inc.id}
                      to="/incidents"
                      className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-800/30 p-3 hover:bg-slate-800/60"
                    >
                      <div className="min-w-0">
                        <div className="truncate text-sm text-slate-100 font-medium">{inc.title}</div>
                        <div className="text-[11px] text-slate-500">{inc.rule_name ?? inc.rule_id}</div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <SeverityBadge severity={inc.severity} />
                        <StatusBadge status={inc.status} />
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
          </div>

          <Card title="External Tools & Capture State">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                {sys.loading ? (
                  <Spinner />
                ) : sys.error ? (
                  <ErrorState message={sys.error} />
                ) : (
                  sys.data?.components
                    .filter((c) => c.name !== "Platform" && c.name !== "Python")
                    .map((c) => (
                      <div key={c.name} className="flex items-center justify-between text-sm">
                        <span className="text-slate-300">{c.name}</span>
                        <Badge tone={c.installed ? "emerald" : "rose"}>{c.installed ? "Installed" : "Missing"}</Badge>
                      </div>
                    ))
                )}
              </div>
              <div className="space-y-1.5 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">API</span>
                  {health.loading ? (
                    <Spinner />
                  ) : health.error ? (
                    <Badge tone="rose">Down</Badge>
                  ) : (
                    <Badge tone={health.data?.database === "ok" ? "emerald" : "rose"}>{health.data?.status}</Badge>
                  )}
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">Captures stored</span>
                  <Badge tone="cyan">{fmtNum(captures.data?.length ?? 0)}</Badge>
                </div>
              </div>
            </div>
          </Card>

          <Card title="Top Conversations">
            <p className="mb-3 text-xs text-slate-500">By bytes transferred</p>
            {!a?.top_conversations.length ? (
              <EmptyState message="No conversation flows recorded." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-500 text-xs">
                      <th className="py-1 pr-3">Source</th>
                      <th className="py-1 pr-3">Destination</th>
                      <th className="py-1 pr-3">Proto</th>
                      <th className="py-1 pr-3 text-right">Packets</th>
                      <th className="py-1 text-right">Bytes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {a.top_conversations.map((c, i) => (
                      <tr key={i} className="border-t border-slate-800/60 text-slate-300">
                        <td className="py-1.5 pr-3">{c.src}</td>
                        <td className="py-1.5 pr-3">{c.dst}</td>
                        <td className="py-1.5 pr-3">{c.proto}</td>
                        <td className="py-1.5 pr-3 text-right">{fmtNum(c.packets)}</td>
                        <td className="py-1.5 text-right">{fmtBytes(c.bytes)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}

function Kpi({ value, sub, accent = "text-cyan-300" }: { value: string; sub?: string; accent?: string }) {
  return (
    <div>
      <div className={`text-3xl font-semibold ${accent}`}>{value}</div>
      {sub && <div className="text-xs text-slate-400 mt-1">{sub}</div>}
    </div>
  );
}
