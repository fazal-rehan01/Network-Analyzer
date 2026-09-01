import { useState } from "react";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import type { CaptureRead, ZeekEvent, ZeekProcessResult } from "@/api/types";

const LOG_TYPES = ["conn", "dns", "http", "ssl", "notice"] as const;
type LogType = (typeof LOG_TYPES)[number];

const LOG_COLORS: Record<LogType, string> = {
  conn: "cyan",
  dns: "violet",
  http: "emerald",
  ssl: "amber",
  notice: "rose",
};

const COLUMNS: Record<LogType, string[]> = {
  conn: ["uid", "src", "dst", "proto", "service"],
  dns: ["query", "qtype_name", "rcode_name", "answers"],
  http: ["method", "host", "uri", "status_code"],
  ssl: ["server_name", "version", "cipher", "established"],
  notice: ["note", "msg", "severity", "src", "dst"],
};

export function ZeekPage() {
  const status = useApi(() => api.zeekStatus(), 20000);
  const captures = useApi(() => api.captureList(), 10000);

  const [selectedCapture, setSelectedCapture] = useState<CaptureRead | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ZeekProcessResult | null>(null);
  const [activeType, setActiveType] = useState<LogType | "all">("all");
  const [events, setEvents] = useState<ZeekEvent[]>([]);
  const [eventsLoading, setEventsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const zeekInstalled = status.data?.available ?? false;

  const handleRun = async () => {
    if (!selectedCapture) return;
    setRunning(true);
    setError(null);
    setEvents([]);
    try {
      const res = await api.zeekProcess(selectedCapture.id);
      setResult(res);
      setActiveType("all");
      // Load events (merged across log types).
      await loadEvents(selectedCapture.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Zeek processing failed");
    } finally {
      setRunning(false);
    }
  };

  const loadEvents = async (captureId: string, logType?: string) => {
    setEventsLoading(true);
    try {
      const data = await api.zeekEvents(captureId, logType);
      setEvents(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load Zeek events");
    } finally {
      setEventsLoading(false);
    }
  };

  const handleTypeChange = (t: LogType | "all") => {
    setActiveType(t);
    if (selectedCapture) loadEvents(selectedCapture.id, t === "all" ? undefined : t);
  };

  const summaryRows = result?.summary ?? [];
  const totalRows = summaryRows.reduce((acc, s) => acc + (s.rows || 0), 0);
  const shownColumns = activeType === "all" ? ["log_type", "src", "dst"] : COLUMNS[activeType] ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Zeek Analysis</h1>
        <p className="text-sm text-slate-400">
          Run Zeek over a capture and inspect connection, DNS, HTTP, TLS, and notice events.
        </p>
      </div>

      <Card title="Run Zeek" actions={
        zeekInstalled ? <Badge tone="emerald">Zeek detected</Badge> : <Badge tone="amber">Zeek not installed</Badge>
      }>
        {!zeekInstalled ? (
          <div className="text-sm text-slate-400 space-y-2">
            <p>
              Zeek is <span className="font-medium text-amber-300">not installed</span> or not detected on this system.
              This feature will appear once Zeek is available.
            </p>
            <p className="text-xs text-slate-500">
              Install Zeek from <span className="text-cyan-400">zeek.org</span> and set <span className="font-mono">ZEEK_PATH</span> in
              your backend <span className="font-mono">.env</span> if it isn't auto-detected.
            </p>
          </div>
        ) : captures.loading ? (
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
                {running ? <Spinner label="Running Zeek…" /> : <>Run Zeek Analysis</>}
              </button>
            </div>
            {error && <div className="text-rose-300 text-sm">{error}</div>}
          </div>
        )}
      </Card>

      {result && (
        <Card title="Results" actions={<span className="text-[11px] text-slate-500">{totalRows} events total</span>}>
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => handleTypeChange("all")}
                className={`px-3 py-1 rounded-full text-xs font-medium ${
                  activeType === "all" ? "bg-cyan-500/20 text-cyan-300" : "bg-slate-800 text-slate-400 hover:bg-slate-700"
                }`}
              >
                All ({totalRows})
              </button>
              {summaryRows.map((s) => (
                <button
                  key={s.log_type}
                  onClick={() => handleTypeChange(s.log_type as LogType)}
                  className={`px-3 py-1 rounded-full text-xs font-medium ${
                    activeType === s.log_type
                      ? "bg-cyan-500/20 text-cyan-300"
                      : "bg-slate-800 text-slate-400 hover:bg-slate-700"
                  }`}
                >
                  {s.log_type} ({s.rows})
                </button>
              ))}
            </div>

            {result.error && (
              <div className="rounded-lg border border-amber-700/40 bg-amber-500/5 p-3 text-sm text-amber-300">
                {result.error}
              </div>
            )}

            <ZeekEventTable events={events} loading={eventsLoading} columns={shownColumns} />
          </div>
        </Card>
      )}
    </div>
  );
}

function ZeekEventTable({
  events,
  loading,
  columns,
}: {
  events: ZeekEvent[];
  loading: boolean;
  columns: string[];
}) {
  if (loading) return <Spinner label="Loading events…" />;
  if (events.length === 0) return <EmptyState message="No Zeek events for this selection." />;

  const headerLabels = columns.map((col) => (col === "log_type" ? "Type" : col));

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
            {headerLabels.map((h) => (
              <th key={h} className="py-2 pr-4 whitespace-nowrap">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {events.map((ev) => (
            <tr key={ev.id} className="border-b border-slate-800/60 last:border-0">
              {columns.map((col) => (
                <td key={col} className="py-2.5 pr-4 text-slate-300 whitespace-nowrap">
                  {col === "log_type" ? (
                    <Badge tone={LOG_COLORS[ev.log_type as LogType] ?? "slate"}>{ev.log_type}</Badge>
                  ) : (
                    String(ev.fields[col] ?? "")
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export type { LogType };
