import { useMemo, useState } from "react";
import { api } from "@/api/client";
import type { PacketRead } from "@/api/types";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

function fmtTime(ts: number | null): string {
  if (ts === null || ts === undefined) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19);
}

function sourceBadgeTone(source: string): string {
  return source === "zeek" ? "violet" : "cyan";
}

function Detail({ p }: { p: PacketRead }) {
  const rows: [string, string][] = [
    ["Frame", p.frame_number !== null ? String(p.frame_number) : "—"],
    ["Time", fmtTime(p.ts)],
    ["Source", p.src ?? "—"],
    ["Destination", p.dst ?? "—"],
    ["Protocol", p.proto ?? "—"],
    ["Src port", p.sport !== null ? String(p.sport) : "—"],
    ["Dst port", p.dport !== null ? String(p.dport) : "—"],
    ["Length", p.length !== null ? `${p.length} B` : "—"],
    ["TCP flags", p.tcp_flags ?? "—"],
    ["HTTP method", p.http_method ?? "—"],
    ["HTTP host", p.http_host ?? "—"],
    ["HTTP URI", p.http_uri ?? "—"],
    ["HTTP status", p.http_status !== null ? String(p.http_status) : "—"],
    ["DNS qname", p.dns_qname ?? "—"],
    ["DNS qtype", p.dns_qtype ?? "—"],
    ["DNS rcode", p.dns_rcode ?? "—"],
    ["Source pipeline", p.source],
  ];
  return (
    <div className="max-h-[28rem] overflow-y-auto">
      <div className="flex items-center gap-2 mb-2">
        <Badge tone={sourceBadgeTone(p.source)}>{p.source} evidence</Badge>
        <span className="text-xs text-slate-500">{p.id}</span>
      </div>
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-center justify-between gap-3 py-1 border-b border-slate-800/50 text-sm">
          <span className="text-slate-500">{k}</span>
          <span className="text-slate-200 font-mono text-right break-all">{v}</span>
        </div>
      ))}
    </div>
  );
}

export function PacketsPage() {
  const [captureId, setCaptureId] = useState<string>("");
  const [search, setSearch] = useState("");
  const [proto, setProto] = useState("");
  const [selected, setSelected] = useState<PacketRead | null>(null);

  const captures = useApi(() => api.captureList(), 30000);
  const packets = useApi(() => (captureId ? api.normalizePackets(captureId, 5000) : Promise.resolve([])));

  const rows = packets.data ?? [];

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rows.filter((p) => {
      if (proto && (p.proto ?? "unknown") !== proto) return false;
      if (!q) return true;
      const hay = [
        p.src, p.dst, String(p.sport ?? ""), String(p.dport ?? ""),
        p.tcp_flags, p.http_host, p.http_uri, p.http_method,
        p.dns_qname, p.dns_qtype, String(p.frame_number ?? ""),
      ].join(" ").toLowerCase();
      return hay.includes(q);
    });
  }, [rows, proto, search]);

  const protos = useMemo(() => {
    const s = new Set<string>();
    rows.forEach((p) => s.add(p.proto ?? "unknown"));
    return ["", ...Array.from(s).sort()];
  }, [rows]);

  const openCapture = (id: string) => {
    setCaptureId(id);
    setSelected(null);
    packets.refetch();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Packets</h1>
          <p className="text-sm text-slate-400">
            Normalized packet-level evidence captured from your traffic.
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

      {!captureId ? (
        <Card>
          <EmptyState message="Select a capture to inspect its packet-level evidence." />
        </Card>
      ) : packets.loading ? (
        <Spinner label="Loading packets…" />
      ) : packets.error ? (
        <ErrorState message={packets.error} onRetry={packets.refetch} />
      ) : rows.length === 0 ? (
        <Card title="Packets">
          <EmptyState message="No normalized packets for this capture. Run normalization on the Correlated page first." />
        </Card>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="xl:col-span-2">
            <Card
              title={`${filtered.length.toLocaleString()} of ${rows.length.toLocaleString()} packets`}
              actions={
                <div className="flex items-center gap-2">
                  <input
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Filter frame/src/dst/port/http/dns…"
                    className="w-56 rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  />
                  <select
                    value={proto}
                    onChange={(e) => setProto(e.target.value)}
                    className="rounded-lg border border-slate-700 bg-slate-800 px-2 py-1 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    {protos.map((p) => (
                      <option key={p || "all"} value={p}>
                        {p || "all protocols"}
                      </option>
                    ))}
                  </select>
                </div>
              }
            >
              {filtered.length === 0 ? (
                <EmptyState message="No packets match the current filters." />
              ) : (
                <div className="max-h-[28rem] overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-slate-900">
                      <tr className="text-left text-slate-500">
                        <th className="py-1 pr-2">#</th>
                        <th className="py-1 pr-2">Time</th>
                        <th className="py-1 pr-2">Src</th>
                        <th className="py-1 pr-2">Dst</th>
                        <th className="py-1 pr-2">Proto</th>
                        <th className="py-1 pr-2">Len</th>
                        <th className="py-1 pr-2">Flags</th>
                        <th className="py-1">Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filtered.slice(0, 500).map((p) => (
                        <tr
                          key={p.id}
                          onClick={() => setSelected(p)}
                          className={`border-t border-slate-800/60 font-mono text-slate-300 cursor-pointer hover:bg-slate-800/40 ${
                            selected?.id === p.id ? "bg-slate-800/40" : ""
                          }`}
                        >
                          <td className="py-1 pr-2">{p.frame_number ?? "—"}</td>
                          <td className="py-1 pr-2">{fmtTime(p.ts)}</td>
                          <td className="py-1 pr-2">{p.src ?? "—"}</td>
                          <td className="py-1 pr-2">{p.dst ?? "—"}</td>
                          <td className="py-1 pr-2">{p.proto ?? "—"}</td>
                          <td className="py-1 pr-2">{p.length ?? "—"}</td>
                          <td className="py-1 pr-2">{p.tcp_flags ?? "—"}</td>
                          <td className="py-1">
                            <Badge tone={sourceBadgeTone(p.source)}>{p.source}</Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </div>

          <Card title="Packet detail">
            {selected ? (
              <Detail p={selected} />
            ) : (
              <EmptyState message="Click a packet row to inspect its full evidence fields." />
            )}
          </Card>
        </div>
      )}
    </div>
  );
}