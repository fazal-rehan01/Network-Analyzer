import { useState } from "react";
import { api } from "@/api/client";
import type { ReportCaptureOption } from "@/api/types";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

const SECTIONS = [
  { n: "1", t: "Capture scope", d: "Capture metadata or whole-database scope" },
  { n: "2", t: "Simulation history", d: "Recent scenario runs and generated-traffic stats" },
  { n: "3", t: "Traffic summary", d: "Packets, connections, bytes, protocols, talkers, conversations, DNS/HTTP" },
  { n: "4", t: "Detection findings", d: "Rule-based findings with severity breakdown" },
  { n: "5", t: "Packet-level analysis (Wireshark/TShark)", d: "Frames, protocols, busiest hosts" },
  { n: "6", t: "Event-level analysis (Zeek)", d: "conn/dns/http/ssl/notice log counts + services" },
  { n: "7", t: "TShark vs Zeek comparison", d: "Correlation statuses and both perspectives" },
  { n: "8", t: "Recommendations", d: "Remediation steps derived from the findings" },
];

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

function downloadPdf(blob: Blob, fallbackName: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fallbackName;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function CaptureRow({ c }: { c: ReportCaptureOption }) {
  return (
    <option value={c.id}>
      {c.name || "untitled"} — {c.packet_count.toLocaleString()} packets
    </option>
  );
}

export function ReportsPage() {
  const [captureId, setCaptureId] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const options = useApi(() => api.reportOptions(), 30000);
  const captures = options.data?.captures ?? [];

  const generate = async () => {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const blob = await api.reportGenerate(captureId || undefined);
      const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-");
      const scope = captureId
        ? captures.find((c) => c.id === captureId)?.name ?? "capture"
        : "all-captures";
      const safe = (scope || "traffic").replace(/[^A-Za-z0-9_-]+/g, "-").toLowerCase();
      downloadPdf(blob, `traffic-report-${safe}-${stamp}.pdf`);
      setDone(`PDF generated for ${captureId ? "the selected capture" : "all captures"}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Report generation failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Security Analysis Report</h1>
        <p className="text-sm text-slate-400">
          Export a professional PDF covering capture, simulation, traffic summary, detection,
          both analyses, comparison and recommendations.
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <Card title="Generate report">
          <label className="block text-sm">
            <span className="text-slate-500">Scope</span>
            <select
              value={captureId}
              onChange={(e) => {
                setCaptureId(e.target.value);
                setDone(null);
              }}
              className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All captures (whole database)</option>
              {captures.map((c) => (
                <CaptureRow key={c.id} c={c} />
              ))}
            </select>
          </label>

          {captures.length > 0 && (
            <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900/40 px-3 py-2 text-xs text-slate-500">
              {(() => {
                const c = captures.find((x) => x.id === captureId);
                return c
                  ? `${c.name} · ${c.packet_count.toLocaleString()} packets · ${fmtBytes(c.byte_count)} · source ${c.source ?? "—"}`
                  : `${captures.length} capture(s) available · report covers every persisted record`;
              })()}
            </div>
          )}

          <button
            onClick={generate}
            disabled={busy}
            className="mt-4 px-4 py-2 rounded-lg bg-cyan-600 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {busy ? "Generating PDF…" : "Generate PDF"}
          </button>

          {busy && <Spinner label="Building report…" />}
          {error && <ErrorState message={error} onRetry={generate} />}
          {done && (
            <div className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">
              {done} Check your downloads folder.
            </div>
          )}
        </Card>

        <Card title="What the report includes">
          <ul className="space-y-2">
            {SECTIONS.map((s) => (
              <li key={s.n} className="flex items-start gap-3 text-sm">
                <Badge tone="cyan">{s.n}</Badge>
                <span>
                  <span className="font-medium text-slate-200">{s.t}</span>
                  <span className="block text-xs text-slate-500">{s.d}</span>
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-4 text-xs text-slate-500">
            All numbers are derived from persisted TShark/Zeek/normalized records — reports contain
            no fabricated values.
          </p>
        </Card>
      </div>

      {captures.length === 0 && !options.loading && !options.error && (
        <EmptyState message="No captures yet. Generate or upload a capture first, then export a report." />
      )}
    </div>
  );
}