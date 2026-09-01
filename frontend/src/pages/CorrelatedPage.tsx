import { useState } from "react";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import type {
  CaptureRead,
  ConnectionRead,
  DnsEventRead,
  HttpEventRead,
  NormalizeSummary,
  PacketRead,
} from "@/api/types";

type Tab = "connections" | "dns" | "http" | "packets";

function SourceBadge({ source }: { source: string | null }) {
  if (source === "zeek") return <Badge tone="violet">zeek</Badge>;
  if (source === "tshark") return <Badge tone="cyan">tshark</Badge>;
  if (source === "tshark+zeek") return <Badge tone="emerald">both</Badge>;
  return <Badge tone="slate">{source ?? "—"}</Badge>;
}

export function CorrelatedPage() {
  const status = useApi(() => api.normalizeStatus(), 20000);
  const captures = useApi(() => api.captureList(), 10000);

  const [selectedCapture, setSelectedCapture] = useState<CaptureRead | null>(null);
  const [running, setRunning] = useState(false);
  const [summary, setSummary] = useState<NormalizeSummary | null>(null);
  const [tab, setTab] = useState<Tab>("connections");
  const [connections, setConnections] = useState<ConnectionRead[]>([]);
  const [dns, setDns] = useState<DnsEventRead[]>([]);
  const [http, setHttp] = useState<HttpEventRead[]>([]);
  const [packets, setPackets] = useState<PacketRead[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tsharkInstalled = status.data?.tshark_available ?? false;
  const zeekInstalled = status.data?.zeek_available ?? false;

  const loadData = async (captureId: string) => {
    setDataLoading(true);
    try {
      const [c, d, h, p] = await Promise.all([
        api.normalizeConnections(captureId),
        api.normalizeDns(captureId),
        api.normalizeHttp(captureId),
        api.normalizePackets(captureId),
      ]);
      setConnections(c);
      setDns(d);
      setHttp(h);
      setPackets(p);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load normalized data");
    } finally {
      setDataLoading(false);
    }
  };

  const handleRun = async () => {
    if (!selectedCapture) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.normalizeRun(selectedCapture.id);
      setSummary(res);
      await loadData(selectedCapture.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Normalization failed");
    } finally {
      setRunning(false);
    }
  };

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "connections", label: "Connections", count: connections.length },
    { key: "dns", label: "DNS", count: dns.length },
    { key: "http", label: "HTTP", count: http.length },
    { key: "packets", label: "Packets", count: packets.length },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Normalized Correlation</h1>
        <p className="text-sm text-slate-400">
          Merge TShark packet evidence with Zeek events into shared connections, DNS, and HTTP views.
        </p>
      </div>

      <Card
        title="Run Normalization"
        actions={
          <div className="flex gap-2">
            <Badge tone={tsharkInstalled ? "emerald" : "amber"}>
              TShark {tsharkInstalled ? "detected" : "not installed"}
            </Badge>
            <Badge tone={zeekInstalled ? "emerald" : "amber"}>
              Zeek {zeekInstalled ? "detected" : "not installed"}
            </Badge>
          </div>
        }
      >
        {captures.loading ? (
          <Spinner />
        ) : captures.error ? (
          <ErrorState message={captures.error} onRetry={captures.refetch} />
        ) : captures.data && captures.data.length === 0 ? (
          <EmptyState message="No captures yet. Create or upload one first." />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
              <div className="md:col-span-2">
                <label className="block text-xs text-slate-400 mb-1">Capture to analyze</label>
                <select
                  value={selectedCapture?.id ?? ""}
                  onChange={(e) =>
                    setSelectedCapture(captures.data?.find((c) => c.id === e.target.value) ?? null)
                  }
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value="">Select a capture…</option>
                  {captures.data?.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} ({c.packet_count} pkts)
                    </option>
                  ))}
                </select>
              </div>
              <button
                onClick={handleRun}
                disabled={running || !selectedCapture}
                className="px-4 py-2 rounded-lg bg-cyan-500/10 text-cyan-300 text-sm font-medium hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 justify-center"
              >
                {running ? <Spinner label="Normalizing…" /> : <>Run Normalization</>}
              </button>
            </div>
            {error && <div className="text-rose-300 text-sm">{error}</div>}
          </div>
        )}
      </Card>

      {summary && (
        <Card title="Summary">
          {summary.error && (
            <div className="rounded-lg border border-amber-700/40 bg-amber-500/5 p-3 text-sm text-amber-300 mb-4">
              {summary.error}
            </div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <Stat label="Packets parsed" value={summary.packets_parsed} />
            <Stat label="Connections" value={summary.connections} />
            <Stat label="DNS events" value={summary.dns_events} />
            <Stat label="HTTP events" value={summary.http_events} />
          </div>
        </Card>
      )}

      <Card
        title="Correlated Records"
        actions={
          <div className="flex gap-1">
            {tabs.map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`px-3 py-1 rounded-full text-xs font-medium ${
                  tab === t.key
                    ? "bg-cyan-500/20 text-cyan-300"
                    : "bg-slate-800 text-slate-400 hover:bg-slate-700"
                }`}
              >
                {t.label} ({t.count})
              </button>
            ))}
          </div>
        }
      >
        {dataLoading ? (
          <Spinner label="Loading…" />
        ) : tab === "connections" ? (
          <ConnectionsTable rows={connections} />
        ) : tab === "dns" ? (
          <DnsTable rows={dns} />
        ) : tab === "http" ? (
          <HttpTable rows={http} />
        ) : (
          <PacketsTable rows={packets} />
        )}
      </Card>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg bg-slate-800/40 p-3">
      <div className="text-xl font-semibold text-slate-100">{value}</div>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

function ConnectionsTable({ rows }: { rows: ConnectionRead[] }) {
  if (rows.length === 0) return <EmptyState message="No normalized connections. Run normalization first." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            <th className="py-2 pr-4">Source</th>
            <th className="py-2 pr-4">Proto</th>
            <th className="py-2 pr-4">Src</th>
            <th className="py-2 pr-4">Dst</th>
            <th className="py-2 pr-4">Svc</th>
            <th className="py-2 pr-4">Packets</th>
            <th className="py-2 pr-4">Bytes</th>
            <th className="py-2 pr-4">UID</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-slate-800/60 last:border-0">
              <td className="py-2.5 pr-4"><SourceBadge source={r.source} /></td>
              <td className="py-2.5 pr-4 text-slate-300">{r.proto ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.src}:{r.sport ?? ""}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.dst}:{r.dport ?? ""}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.service ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.packets}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.bytes_total}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.zeek_uid ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DnsTable({ rows }: { rows: DnsEventRead[] }) {
  if (rows.length === 0) return <EmptyState message="No normalized DNS events." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            <th className="py-2 pr-4">Source</th>
            <th className="py-2 pr-4">Query</th>
            <th className="py-2 pr-4">Type</th>
            <th className="py-2 pr-4">Rcode</th>
            <th className="py-2 pr-4">Answers</th>
            <th className="py-2 pr-4">UID</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-slate-800/60 last:border-0">
              <td className="py-2.5 pr-4"><SourceBadge source={r.source} /></td>
              <td className="py-2.5 pr-4 text-slate-300">{r.query ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.qtype_name ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.rcode_name ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.answers ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.zeek_uid ?? r.packet_ref ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function HttpTable({ rows }: { rows: HttpEventRead[] }) {
  if (rows.length === 0) return <EmptyState message="No normalized HTTP events." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            <th className="py-2 pr-4">Source</th>
            <th className="py-2 pr-4">Method</th>
            <th className="py-2 pr-4">Host</th>
            <th className="py-2 pr-4">URI</th>
            <th className="py-2 pr-4">Status</th>
            <th className="py-2 pr-4">UID</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-slate-800/60 last:border-0">
              <td className="py-2.5 pr-4"><SourceBadge source={r.source} /></td>
              <td className="py-2.5 pr-4 text-slate-300">{r.method ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.host ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.uri ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.status_code ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.zeek_uid ?? r.packet_ref ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PacketsTable({ rows }: { rows: PacketRead[] }) {
  if (rows.length === 0) return <EmptyState message="No normalized packets. Run normalization first." />;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            <th className="py-2 pr-4">Frame</th>
            <th className="py-2 pr-4">Proto</th>
            <th className="py-2 pr-4">Src</th>
            <th className="py-2 pr-4">Dst</th>
            <th className="py-2 pr-4">Len</th>
            <th className="py-2 pr-4">HTTP</th>
            <th className="py-2 pr-4">DNS</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-b border-slate-800/60 last:border-0">
              <td className="py-2.5 pr-4 text-slate-300">{r.frame_number ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.proto ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.src}:{r.sport ?? ""}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.dst}:{r.dport ?? ""}</td>
              <td className="py-2.5 pr-4 text-slate-300">{r.length ?? "—"}</td>
              <td className="py-2.5 pr-4 text-slate-300">
                {r.http_method ? `${r.http_method} ${r.http_uri ?? ""}` : "—"}
              </td>
              <td className="py-2.5 pr-4 text-slate-300">{r.dns_qname ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
