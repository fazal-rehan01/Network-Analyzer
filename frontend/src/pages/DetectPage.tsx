import { useState } from "react";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import type {
  CaptureRead,
  DetectionFindingRead,
  DetectionRunResult,
  RuleInfo,
} from "@/api/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITY_ORDER)[number];

const SEVERITY_TONE: Record<string, string> = {
  critical: "rose",
  high: "amber",
  medium: "cyan",
  low: "violet",
  info: "slate",
};

function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={SEVERITY_TONE[severity] ?? "slate"}>{severity}</Badge>;
}

function SevCounts({ bySeverity }: { bySeverity: Record<string, number> | undefined }) {
  if (!bySeverity) return null;
  const total = SEVERITY_ORDER.reduce((acc, s) => acc + (bySeverity[s] ?? 0), 0);
  return (
    <div className="flex flex-wrap gap-2 text-[11px]">
      {SEVERITY_ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((s) => (
        <span key={s} className="inline-flex items-center gap-1">
          <SeverityBadge severity={s} /> <span className="text-slate-400">{bySeverity[s]}</span>
        </span>
      ))}
      <span className="text-slate-500">· {total} total</span>
    </div>
  );
}

export function DetectPage() {
  const rules = useApi(() => api.detectRules(), 20000);
  const captures = useApi(() => api.captureList(), 10000);

  const [selectedCapture, setSelectedCapture] = useState<CaptureRead | null>(null);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<DetectionRunResult | null>(null);
  const [findings, setFindings] = useState<DetectionFindingRead[]>([]);
  const [loading, setLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [error, setError] = useState<string | null>(null);

  const loadFindings = async (captureId: string, severity?: Severity | "all") => {
    setLoading(true);
    try {
      const data = await api.detectFindings(
        captureId,
        severity === "all" || severity === undefined ? undefined : severity
      );
      setFindings(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load findings");
    } finally {
      setLoading(false);
    }
  };

  const handleRun = async () => {
    if (!selectedCapture) return;
    setRunning(true);
    setError(null);
    try {
      const res = await api.detectRun(selectedCapture.id);
      setResult(res);
      setSeverityFilter("all");
      await loadFindings(selectedCapture.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Detection run failed");
    } finally {
      setRunning(false);
    }
  };

  const handleFilter = (s: Severity | "all") => {
    setSeverityFilter(s);
    if (selectedCapture) loadFindings(selectedCapture.id, s);
  };

  const shownFindings =
    severityFilter === "all" ? findings : findings.filter((f) => f.severity === severityFilter);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Threat &amp; Anomaly Detection</h1>
        <p className="text-sm text-slate-400">
          Explainable, rule-based detection over normalized traffic. No AI, no fabricated counts.
        </p>
      </div>

      <Card title="Detection Rules" actions={<span className="text-[11px] text-slate-500">{rules.data?.length ?? 0} rules</span>}>
        {rules.loading ? (
          <Spinner />
        ) : rules.error ? (
          <ErrorState message={rules.error} onRetry={rules.refetch} />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {rules.data?.map((r: RuleInfo) => (
              <div key={r.id} className="rounded-lg border border-slate-800 bg-slate-800/30 p-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-200 font-medium">{r.name}</span>
                  <Badge tone={SEVERITY_TONE[r.default_severity] ?? "slate"}>{r.default_severity}</Badge>
                </div>
                <div className="text-[11px] text-slate-500 mt-1 font-mono">{r.id}</div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Run Detection">
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
                className="px-4 py-2 rounded-lg bg-rose-500/10 text-rose-300 text-sm font-medium hover:bg-rose-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 justify-center"
              >
                {running ? <Spinner label="Running detection…" /> : <>Run Detection</>}
              </button>
            </div>
            {error && <div className="text-rose-300 text-sm">{error}</div>}
            {result && (
              <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-200">
                    {result.findings} finding{result.findings === 1 ? "" : "s"} from {result.rules_evaluated} rules
                  </span>
                </div>
                <SevCounts bySeverity={result.by_severity} />
              </div>
            )}
          </div>
        )}
      </Card>

      <Card title="Findings"
        actions={
          <div className="flex flex-wrap gap-1">
            <FilterChip active={severityFilter === "all"} onClick={() => handleFilter("all")} label="All" />
            {SEVERITY_ORDER.map((s) => (
              <FilterChip key={s} active={severityFilter === s} onClick={() => handleFilter(s)} label={s} />
            ))}
          </div>
        }
      >
        {loading ? (
          <Spinner label="Loading findings…" />
        ) : shownFindings.length === 0 ? (
          <EmptyState message="No findings for this selection. Run detection on a capture first." />
        ) : (
          <div className="space-y-3">
            {shownFindings.map((f) => (
              <FindingRow key={f.id} f={f} />
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function FilterChip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 rounded-full text-xs font-medium ${
        active ? "bg-rose-500/20 text-rose-300" : "bg-slate-800 text-slate-400 hover:bg-slate-700"
      }`}
    >
      {label}
    </button>
  );
}

function FindingRow({ f }: { f: DetectionFindingRead }) {
  const [open, setOpen] = useState(false);
  const ev = f.evidence ?? [];
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-800/30 p-4 space-y-2">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <div className="text-sm font-medium text-slate-100">{f.rule_name}</div>
          <div className="text-xs text-slate-400">{f.summary}</div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <SeverityBadge severity={f.severity} />
          <button
            onClick={() => setOpen(!open)}
            className="text-[11px] text-cyan-300 hover:text-cyan-200 underline"
          >
            {open ? "Hide evidence" : `Show evidence (${ev.length})`}
          </button>
        </div>
      </div>
      {open && (
        <div className="text-xs text-slate-300 space-y-2">
          <p className="text-slate-400">{f.detail}</p>
          <p className="text-slate-500">
            Evidence: {f.ref_type ?? "—"} · score {f.score}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left uppercase text-slate-500 border-b border-slate-800">
                  <th className="py-1 pr-3">Type</th>
                  <th className="py-1 pr-3">ID</th>
                  <th className="py-1 pr-3">Src</th>
                  <th className="py-1 pr-3">Dst</th>
                  <th className="py-1 pr-3">Detail</th>
                </tr>
              </thead>
              <tbody>
                {ev.map((e, i) => (
                  <tr key={i} className="border-b border-slate-800/60 last:border-0">
                    <td className="py-1 pr-3 text-slate-300">{e.type}</td>
                    <td className="py-1 pr-3 font-mono text-slate-400 truncate max-w-[160px]">{e.id ?? "—"}</td>
                    <td className="py-1 pr-3 text-slate-300">{e.src ?? "—"}</td>
                    <td className="py-1 pr-3 text-slate-300">{e.dst ?? "—"}</td>
                    <td className="py-1 pr-3 text-slate-400">{e.detail ?? ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
