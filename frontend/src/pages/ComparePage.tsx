import { useCallback, useState } from "react";
import { api } from "@/api/client";
import type { ConnectionComparison } from "@/api/types";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

function CorrelationBadge({ status }: { status: string }) {
  const tones: Record<string, string> = {
    both: "emerald",
    tshark_only: "cyan",
    zeek_only: "violet",
  };
  const labels: Record<string, string> = {
    both: "Both",
    tshark_only: "TShark only",
    zeek_only: "Zeek only",
  };
  return <Badge tone={tones[status] ?? "slate"}>{labels[status] ?? status}</Badge>;
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

function fmtTime(ts: number | null): string {
  if (ts === null || ts === undefined) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1 border-b border-slate-800/50 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="text-slate-200 font-mono text-right">{value}</span>
    </div>
  );
}

function TsharkTable({ detail }: { detail: ConnectionComparison }) {
  if (!detail.tshark.present) {
    return <EmptyState message="No packet-level (TShark/Wireshark) evidence for this connection." />;
  }
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="rounded-lg bg-slate-800/40 p-2">
          <div className="text-slate-500">Packets</div>
          <div className="text-slate-100 font-semibold">{detail.tshark.packet_count}</div>
        </div>
        <div className="rounded-lg bg-slate-800/40 p-2">
          <div className="text-slate-500">Bytes</div>
          <div className="text-slate-100 font-semibold">{fmtBytes(detail.tshark.bytes)}</div>
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-slate-500">
              <th className="py-1 pr-2">#</th>
              <th className="py-1 pr-2">Time</th>
              <th className="py-1 pr-2">Src</th>
              <th className="py-1 pr-2">Dst</th>
              <th className="py-1 pr-2">Proto</th>
              <th className="py-1 pr-2">Len</th>
              <th className="py-1">Flags</th>
            </tr>
          </thead>
          <tbody>
            {detail.tshark.packets.map((p) => (
              <tr key={p.id} className="border-t border-slate-800/60 font-mono text-slate-300">
                <td className="py-1 pr-2">{p.frame_number ?? "—"}</td>
                <td className="py-1 pr-2">{fmtTime(p.ts)}</td>
                <td className="py-1 pr-2">{p.src ?? "—"}</td>
                <td className="py-1 pr-2">{p.dst ?? "—"}</td>
                <td className="py-1 pr-2">{p.proto ?? "—"}</td>
                <td className="py-1 pr-2">{p.length ?? "—"}</td>
                <td className="py-1">{p.tcp_flags ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ZeekTable({ detail }: { detail: ConnectionComparison }) {
  if (!detail.zeek.present) {
    return <EmptyState message="No Zeek event-level evidence for this connection." />;
  }
  const conn = detail.zeek.conn;
  return (
    <div className="space-y-3">
      {conn ? (
        <div className="text-xs">
          <Row label="Zeek UID" value={conn.uid ?? "—"} />
          <Row label="Service" value={conn.service ?? "—"} />
          <Row label="Conn state" value={conn.conn_state ?? "—"} />
          <Row label="Duration" value={conn.duration !== null && conn.duration !== undefined ? `${conn.duration.toFixed(3)}s` : "—"} />
          <Row label="Orig bytes" value={conn.orig_bytes !== null && conn.orig_bytes !== undefined ? String(conn.orig_bytes) : "—"} />
          <Row label="Resp bytes" value={conn.resp_bytes !== null && conn.resp_bytes !== undefined ? String(conn.resp_bytes) : "—"} />
        </div>
      ) : (
        <EmptyState message="Connection-level conn.log record not found for this flow." />
      )}

      {detail.zeek.dns.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold text-slate-500 uppercase">DNS events</div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500">
                  <th className="py-1 pr-2">Query</th>
                  <th className="py-1 pr-2">Qtype</th>
                  <th className="py-1">Rcode</th>
                </tr>
              </thead>
              <tbody>
                {detail.zeek.dns.map((d, i) => (
                  <tr key={i} className="border-t border-slate-800/60 font-mono text-slate-300">
                    <td className="py-1 pr-2">{String(d.query ?? "—")}</td>
                    <td className="py-1 pr-2">{String(d.qtype_name ?? "—")}</td>
                    <td className="py-1">{String(d.rcode_name ?? "—")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {detail.zeek.http.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold text-slate-500 uppercase">HTTP events</div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500">
                  <th className="py-1 pr-2">Method</th>
                  <th className="py-1 pr-2">Host</th>
                  <th className="py-1 pr-2">URI</th>
                  <th className="py-1">Status</th>
                </tr>
              </thead>
              <tbody>
                {detail.zeek.http.map((h, i) => (
                  <tr key={i} className="border-t border-slate-800/60 font-mono text-slate-300">
                    <td className="py-1 pr-2">{String(h.method ?? "—")}</td>
                    <td className="py-1 pr-2">{String(h.host ?? "—")}</td>
                    <td className="py-1 pr-2">{String(h.uri ?? "—")}</td>
                    <td className="py-1">{h.status_code !== null && h.status_code !== undefined ? String(h.status_code) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {detail.zeek.ssl.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold text-slate-500 uppercase">SSL/TLS events</div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-slate-500">
                  <th className="py-1 pr-2">Server</th>
                  <th className="py-1 pr-2">Version</th>
                  <th className="py-1">Established</th>
                </tr>
              </thead>
              <tbody>
                {detail.zeek.ssl.map((s, i) => (
                  <tr key={i} className="border-t border-slate-800/60 font-mono text-slate-300">
                    <td className="py-1 pr-2">{String(s.server_name ?? "—")}</td>
                    <td className="py-1 pr-2">{String(s.version ?? "—")}</td>
                    <td className="py-1">{s.established ? "yes" : "no"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {detail.zeek.notices.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-semibold text-slate-500 uppercase">Notices</div>
          <div className="space-y-1">
            {detail.zeek.notices.map((n, i) => (
              <div key={i} className="rounded-lg bg-amber-500/10 border border-amber-500/30 px-3 py-2 text-xs text-amber-200">
                <span className="font-semibold">{String(n.note ?? "notice")}</span> — {String(n.msg ?? "")}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function ComparePage() {
  const [captureId, setCaptureId] = useState<string>("");
  const [selected, setSelected] = useState<ConnectionComparison | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const status = useApi(() => api.compareStatus(), 15000);
  const captures = useApi(() => api.captureList(), 30000);
  const comparison = useApi(
    useCallback(() => api.compareCapture(captureId), [captureId]),
  );

  const loadDetail = useCallback(async (connId: string) => {
    setDetailLoading(true);
    setDetailError(null);
    try {
      const d = await api.compareConnection(connId);
      setSelected(d);
    } catch (e) {
      setDetailError(e instanceof Error ? e.message : "Failed to load connection detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const openCapture = (id: string) => {
    setCaptureId(id);
    setSelected(null);
  };

  const s = comparison.data;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Wireshark vs Zeek</h1>
          <p className="text-sm text-slate-400">
            The same traffic from two analytical perspectives.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <span className="text-slate-500">Capture:</span>
          <select
            value={captureId}
            onChange={(e) => openCapture(e.target.value)}
            className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">Select a capture…</option>
            {captures.data?.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <Card>
        <div className="space-y-2 text-sm text-slate-300">
          <p>
            <span className="font-semibold text-cyan-300">Wireshark/TShark</span> provides{" "}
            <em>packet-level</em> visibility: each frame, its timestamp, source/destination,
            protocol, ports and length.
          </p>
          <p>
            <span className="font-semibold text-violet-300">Zeek</span> provides{" "}
            <em>higher-level network/event</em> visibility: connection records (conn.log) with
            service, duration and byte counts, plus DNS/HTTP/SSL/notice events.
          </p>
          <p className="text-xs text-slate-500">
            Not every packet has a Zeek event and not every flow has packets — correlation is
            reported honestly per connection, including tool-unavailable states.
          </p>
        </div>
      </Card>

      <div className="flex items-center gap-3">
        {status.loading ? (
          <Spinner />
        ) : (
          <>
            <Badge tone={status.data?.tshark_available ? "emerald" : "rose"}>
              TShark: {status.data?.tshark_available ? "available" : "unavailable"}
            </Badge>
            <Badge tone={status.data?.zeek_available ? "emerald" : "rose"}>
              Zeek: {status.data?.zeek_available ? "available" : "unavailable"}
            </Badge>
            <span className="text-xs text-slate-500">
              {status.data?.zeek_available
                ? "Zeek runtime detected — using live Zeek evidence."
                : "Zeek runtime not detected — Zeek-side evidence shown only where a real Zeek log (or fixture) produced normalized events."}
            </span>
          </>
        )}
      </div>

      {!captureId ? (
        <Card>
          <EmptyState message="Select a capture to compare packet-level and event-level evidence." />
        </Card>
      ) : comparison.loading ? (
        <Spinner label="Building comparison…" />
      ) : comparison.error ? (
        <ErrorState message={comparison.error} onRetry={comparison.refetch} />
      ) : !s ? (
        <EmptyState message="No comparison data." />
      ) : s.connections.length === 0 ? (
        <Card title={s.capture_name ?? "Capture"}>
          <EmptyState message="This capture has no normalized connections to compare." />
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-3">
            <MiniStat label="Connections" value={String(s.summary.connections_total)} />
            <MiniStat label="Correlated (both)" value={String(s.summary.both)} tone="emerald" />
            <MiniStat label="TShark only" value={String(s.summary.tshark_only)} tone="cyan" />
            <MiniStat label="Zeek only" value={String(s.summary.zeek_only)} tone="violet" />
            <MiniStat label="TShark packets" value={String(s.summary.packets_tshark)} />
            <MiniStat label="Zeek events" value={String(s.summary.zeek_events)} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <Card title={`Connections — ${s.capture_name ?? s.capture_id}`}>
              {s.connections.length === 0 ? (
                <EmptyState message="No connections." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-slate-500 text-xs">
                        <th className="py-1 pr-3">Flow</th>
                        <th className="py-1 pr-3">Service</th>
                        <th className="py-1 pr-3">Packets</th>
                        <th className="py-1 pr-3">Bytes</th>
                        <th className="py-1">Correlation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {s.connections.map((c) => (
                        <tr
                          key={c.id}
                          onClick={() => loadDetail(c.id)}
                          className={`cursor-pointer border-t border-slate-800/60 text-slate-300 hover:bg-slate-800/40 ${
                            selected?.id === c.id ? "bg-slate-800/40" : ""
                          }`}
                        >
                          <td className="py-2 pr-3">
                            <div className="font-mono">
                              {c.src ?? "—"} → {c.dst ?? "—"}
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {c.proto ?? ""} {c.sport ?? ""}→{c.dport ?? ""} · zeek:{c.zeek_uid ?? "—"}
                            </div>
                          </td>
                          <td className="py-2 pr-3">{c.service ?? "—"}</td>
                          <td className="py-2 pr-3">{c.packets}</td>
                          <td className="py-2 pr-3">{fmtBytes(c.bytes_total)}</td>
                          <td className="py-2">
                            <CorrelationBadge status={c.correlation_status} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>

            <Card
              title={
                selected
                  ? "Side-by-side evidence"
                  : "Connection detail"
              }
            >
              {detailLoading ? (
                <Spinner />
              ) : detailError ? (
                <ErrorState message={detailError} />
              ) : !selected ? (
                <EmptyState message="Select a connection to see its packet-level and event-level evidence side by side." />
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="font-mono text-sm text-slate-200">
                      {selected.src} → {selected.dst}
                    </div>
                    <CorrelationBadge status={selected.correlation_status} />
                  </div>
                  <p className="text-xs text-slate-500">{selected.correlation_summary}</p>
                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                      <div className="mb-2 flex items-center justify-between">
                        <h4 className="text-xs font-semibold text-cyan-300 uppercase">Wireshark / TShark</h4>
                        <Badge tone={selected.tshark.present ? "emerald" : "slate"}>
                          {selected.tshark.present ? "present" : "absent"}
                        </Badge>
                      </div>
                      <TsharkTable detail={selected} />
                    </div>
                    <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-3">
                      <div className="mb-2 flex items-center justify-between">
                        <h4 className="text-xs font-semibold text-violet-300 uppercase">Zeek</h4>
                        <Badge tone={selected.zeek.present ? "emerald" : "slate"}>
                          {selected.zeek.present ? "present" : "absent"}
                        </Badge>
                      </div>
                      <ZeekTable detail={selected} />
                    </div>
                  </div>
                </div>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}

function MiniStat({ label, value, tone }: { label: string; value: string; tone?: string }) {
  const color = tone === "emerald" ? "text-emerald-300" : tone === "cyan" ? "text-cyan-300" : tone === "violet" ? "text-violet-300" : "text-slate-100";
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/50 px-3 py-2">
      <div className={`text-xl font-semibold ${color}`}>{value}</div>
      <div className="text-[11px] text-slate-500 truncate">{label}</div>
    </div>
  );
}