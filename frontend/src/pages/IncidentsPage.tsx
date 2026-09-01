import { useCallback, useMemo, useState } from "react";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import type {
  CaptureRead,
  IncidentDetail,
  IncidentListParams,
} from "@/api/types";

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
const STATUS_ORDER = ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"] as const;

const SEVERITY_TONE: Record<string, string> = {
  critical: "rose",
  high: "amber",
  medium: "cyan",
  low: "violet",
  info: "slate",
};

const STATUS_TONE: Record<string, string> = {
  NEW: "slate",
  INVESTIGATING: "cyan",
  CONTAINED: "amber",
  RESOLVED: "emerald",
  FALSE_POSITIVE: "violet",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <Badge tone={SEVERITY_TONE[severity] ?? "slate"}>{severity}</Badge>;
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <Badge tone={STATUS_TONE[status] ?? "slate"}>
      {status === "FALSE_POSITIVE" ? "FALSE POSITIVE" : status}
    </Badge>
  );
}

function StatCard({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <Card className="min-h-[96px]">
      <div className="text-sm text-slate-400">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${tone ? "text-" + tone + "-300" : "text-slate-100"}`}>
        {value}
      </div>
    </Card>
  );
}

function fmtTimestamp(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

export function IncidentsPage() {
  const [params, setParams] = useState<IncidentListParams>({ limit: 25, offset: 0, sort_by: "created_at", order: "desc" });
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<IncidentDetail | null>(null);
  const rules = useApi(() => api.detectRules(), 20000);
  const captures = useApi(() => api.captureList(), 20000);

  const fetcher = useCallback(() => api.incidentList(params), [params]);
  const list = useApi(fetcher, 20000);
  const summary = useApi(() => api.incidentSummary(), 20000);

  const apply = (patch: Partial<IncidentListParams>) => {
    setParams((p) => ({ ...p, ...patch, offset: 0 }));
  };

  const selectIncident = async (id: string) => {
    try {
      const detail = await api.incidentGet(id);
      setSelected(detail);
    } catch {
      setSelected(null);
    }
  };

  const refreshAll = async () => {
    list.refetch();
    summary.refetch();
    if (selected) {
      try {
        const detail = await api.incidentGet(selected.id);
        setSelected(detail);
      } catch {
        setSelected(null);
      }
    }
  };

  const goToFirstRelevant = async () => {
    const res = await api.incidentList({ limit: 50, sort_by: "created_at", order: "desc" });
    if (res.items.length) selectIncident(res.items[0].id);
  };

  const pageInBounds = list.data ? list.data.offset >= 0 && (list.data.offset + list.data.items.length >= list.data.total || list.data.total > list.data.offset) : true;

  const hasPrev = (list.data?.offset ?? 0) > 0;
  const hasNext = list.data ? list.data.offset + list.data.limit < list.data.total : false;

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold">Incidents</h1>
          <p className="text-sm text-slate-400">
            SOC incident queue created from M10 detection findings. Lifecycle is enforced server-side.
          </p>
        </div>
        <PromotePanel
          captures={captures.data ?? []}
          onDone={async () => {
            await refreshAll();
            await goToFirstRelevant();
          }}
        />
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total incidents" value={summary.data?.total ?? 0} />
        <StatCard label="Open" value={summary.data?.open ?? 0} tone="cyan" />
        <StatCard label="Critical/High" value={(summary.data?.critical ?? 0) + (summary.data?.high ?? 0)} tone="rose" />
        <StatCard label="Resolved" value={summary.data?.resolved ?? 0} tone="emerald" />
      </div>

      <Card
        title="Incident Queue"
        actions={
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && apply({ search })}
              placeholder="Search title/summary…"
              className="rounded-lg border border-slate-700 bg-slate-900/50 px-2.5 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <FilterSelect
              value={params.severity ?? "all"}
              onChange={(v) => apply({ severity: v === "all" ? undefined : v })}
              options={[{ value: "all", label: "Severity" }, ...SEVERITY_ORDER.map((s) => ({ value: s, label: s }))]}
            />
            <FilterSelect
              value={params.status ?? "all"}
              onChange={(v) => apply({ status: v === "all" ? undefined : v })}
              options={[{ value: "all", label: "Status" }, ...STATUS_ORDER.map((s) => ({ value: s, label: s }))]}
            />
            <FilterSelect
              value={params.rule_id ?? "all"}
              onChange={(v) => apply({ rule_id: v === "all" ? undefined : v })}
              options={[{ value: "all", label: "Rule" }, ...(rules.data ?? []).map((r) => ({ value: r.id, label: r.name }))]}
            />
            <FilterSelect
              value={params.capture_id ?? "all"}
              onChange={(v) => apply({ capture_id: v === "all" ? undefined : v })}
              options={[{ value: "all", label: "Capture" }, ...(captures.data ?? []).map((c) => ({ value: c.id, label: c.name }))]}
            />
            <FilterSelect
              value={params.sort_by ?? "created_at"}
              onChange={(v) => apply({ sort_by: v })}
              options={[
                { value: "created_at", label: "Sort: created" },
                { value: "updated_at", label: "Sort: updated" },
                { value: "severity", label: "Sort: severity" },
              ]}
            />
            <button
              onClick={() => apply({ order: params.order === "asc" ? "desc" : "asc" })}
              className="px-2.5 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
            >
              {params.order === "asc" ? "↑ asc" : "↓ desc"}
            </button>
          </div>
        }
      >
        {list.loading ? (
          <Spinner label="Loading incidents…" />
        ) : list.error ? (
          <ErrorState message={list.error} onRetry={list.refetch} />
        ) : !list.data || list.data.items.length === 0 ? (
          <EmptyState message="No incidents. Promote detection findings into incidents, or adjust filters." />
        ) : pageInBounds ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left uppercase text-[11px] text-slate-500 border-b border-slate-800">
                  <th className="py-2 pr-3">ID</th>
                  <th className="py-2 pr-3">Title</th>
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Rule</th>
                  <th className="py-2 pr-3">Source</th>
                  <th className="py-2 pr-3">Detected</th>
                  <th className="py-2 pr-3">Updated</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((i) => (
                  <tr
                    key={i.id}
                    onClick={() => selectIncident(i.id)}
                    className={`border-b border-slate-800/60 cursor-pointer hover:bg-slate-800/40 ${
                      selected?.id === i.id ? "bg-cyan-500/5" : ""
                    }`}
                  >
                    <td className="py-2 pr-3 font-mono text-slate-400 text-[11px]">{shortId(i.id)}</td>
                    <td className="py-2 pr-3 text-slate-100 font-medium">{i.title}</td>
                    <td className="py-2 pr-3"><SeverityBadge severity={i.severity} /></td>
                    <td className="py-2 pr-3"><StatusBadge status={i.status} /></td>
                    <td className="py-2 pr-3 text-slate-300">{i.rule_name ?? i.rule_id ?? "—"}</td>
                    <td className="py-2 pr-3 text-slate-400">{i.capture_name ?? "—"}</td>
                    <td className="py-2 pr-3 text-slate-300">{fmtTimestamp(i.created_at)}</td>
                    <td className="py-2 pr-3 text-slate-400">{fmtTimestamp(i.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              total={list.data.total}
              limit={list.data.limit}
              offset={list.data.offset}
              hasPrev={hasPrev}
              hasNext={hasNext}
              onPrev={() => setParams((p) => ({ ...p, offset: Math.max(0, (p.offset ?? 0) - (p.limit ?? 25)) }))}
              onNext={() => setParams((p) => ({ ...p, offset: (p.offset ?? 0) + (p.limit ?? 25) }))}
            />
          </div>
        ) : (
          <EmptyState message="Out of range — reset filters." />
        )}
      </Card>

      {selected && (
        <div className="pb-8">
          <h2 className="text-lg font-semibold mb-1">{selected.title}</h2>
          <div className="flex flex-wrap items-center gap-2 mb-4">
            <SeverityBadge severity={selected.severity} />
            <StatusBadge status={selected.status} />
            <span className="text-[11px] font-mono text-slate-500">{selected.id}</span>
            <span className="text-xs text-slate-400">finding · {selected.detection_finding_id}</span>
          </div>
          <IncidentDetailPanel incident={selected} onChange={refreshAll} />
        </div>
      )}
    </div>
  );
}

function shortId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}…` : id;
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-slate-700 bg-slate-900/50 px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  );
}

function Pagination({
  total,
  limit,
  offset,
  hasPrev,
  hasNext,
  onPrev,
  onNext,
}: {
  total: number;
  limit: number;
  offset: number;
  hasPrev: boolean;
  hasNext: boolean;
  onPrev: () => void;
  onNext: () => void;
}) {
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(total, offset + limit);
  return (
    <div className="flex items-center justify-between mt-3 text-xs text-slate-500">
      <span>
        Showing {from}–{to} of {total}
      </span>
      <div className="flex gap-2">
        <button
          onClick={onPrev}
          disabled={!hasPrev}
          className="px-3 py-1 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Prev
        </button>
        <button
          onClick={onNext}
          disabled={!hasNext}
          className="px-3 py-1 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Next
        </button>
      </div>
    </div>
  );
}

function PromotePanel({ captures, onDone }: { captures: CaptureRead[]; onDone: () => Promise<void> }) {
  const [captureId, setCaptureId] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  const promote = async () => {
    if (!captureId) return;
    setBusy(true);
    setMsg(null);
    try {
      const res = await api.incidentCreateFromCapture(captureId);
      setMsg(`Created ${res.created}, skipped ${res.skipped}`);
      await onDone();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Failed to promote findings");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-end gap-2">
      <div>
        <label className="block text-[11px] text-slate-500 mb-1">Promote detection findings → incidents</label>
        <select
          value={captureId}
          onChange={(e) => setCaptureId(e.target.value)}
          className="rounded-lg border border-slate-700 bg-slate-900/50 px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        >
          <option value="">Select capture…</option>
          {captures.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
        </select>
      </div>
      <button
        onClick={promote}
        disabled={busy || !captureId}
        className="px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-300 text-sm font-medium hover:bg-emerald-500/20 disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {busy ? "Promoting…" : "Promote"}
      </button>
      {msg && <div className="text-xs text-slate-400">{msg}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ detail

function IncidentDetailPanel({
  incident,
  onChange,
}: {
  incident: IncidentDetail;
  onChange: () => Promise<void>;
}) {
  const [actor, setActor] = useState("");
  const [noteText, setNoteText] = useState("");
  const [noteAuthor, setNoteAuthor] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState<string | null>(null);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  };

  const actions = availableActions(incident.status);
  const canAddNote = noteText.trim().length > 0;
  const needsResolution = incident.status === "INVESTIGATING" || incident.status === "CONTAINED";

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div className="space-y-4">
        <Card title="Overview">
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <Field label="Incident ID" value={incident.id} mono />
            <Field label="Detection finding" value={incident.detection_finding_id} mono />
            <Field label="Rule" value={incident.rule_name ?? incident.rule_id ?? "—"} />
            <Field label="Score" value={String(incident.score)} />
            <Field label="Created" value={fmtTimestamp(incident.created_at)} />
            <Field label="Updated" value={fmtTimestamp(incident.updated_at)} />
            <Field label="First seen" value={fmtTimestamp(incident.first_seen_at)} />
            <Field label="Last seen" value={fmtTimestamp(incident.last_seen_at)} />
            <Field label="Assigned analyst" value={incident.assigned_to ?? "—"} />
            <Field label="Capture" value={incident.capture_name ?? incident.capture_id ?? "—"} />
            <Field label="Closed" value={fmtTimestamp(incident.closed_at)} />
            <Field label="Resolution" value={incident.resolution ?? "—"} />
          </div>
          {incident.description && (
            <p className="mt-3 text-sm text-slate-300">{incident.description}</p>
          )}
        </Card>

        <Card title="Detection Details">
          <div className="text-sm space-y-2">
            <p className="text-slate-300">{incident.summary ?? "—"}</p>
            {incident.detail && <p className="text-slate-400 text-xs">{incident.detail}</p>}
            {incident.resolution_notes && (
              <p className="text-xs text-emerald-300/80">Resolution notes: {incident.resolution_notes}</p>
            )}
          </div>
        </Card>

        <Card title="Actions">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            <ActionButton label="Investigate" disabled={!actions.canInvestigate} busy={busy}
              onClick={() => act(() => api.incidentPatch(incident.id, { status: "INVESTIGATING" }))} />
            <ActionButton label="Contain" disabled={!actions.canContain} busy={busy}
              onClick={() => act(() => api.incidentPatch(incident.id, { status: "CONTAINED" }))} />
            <ActionButton label="Resolve" disabled={!actions.canResolve} busy={busy}
              onClick={() =>
                act(() => api.incidentPatch(incident.id, { status: "RESOLVED", resolution_notes: resolutionNotes ?? undefined }))
              } />
            <ActionButton label="Mark FP" disabled={!actions.canFalsePositive} busy={busy}
              onClick={() => act(() => api.incidentPatch(incident.id, { status: "FALSE_POSITIVE", resolution_notes: resolutionNotes ?? undefined }))} />
            <ActionButton label="Reopen" disabled={!actions.canReopen} busy={busy}
              onClick={() => act(() => api.incidentPatch(incident.id, { status: "INVESTIGATING" }))} />
            <ActionButton label="Delete" danger busy={busy}
              onClick={() => act(async () => { await api.incidentDelete(incident.id); return null; })} />
          </div>
          {needsResolution && (
            <div className="mt-3">
              <label className="block text-[11px] text-slate-500 mb-1">Resolution notes (optional)</label>
              <input
                value={resolutionNotes ?? ""}
                onChange={(e) => setResolutionNotes(e.target.value)}
                placeholder="How was this handled? The outcome is validated server-side."
                className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
            </div>
          )}
          <div className="mt-3 space-y-1">
            <label className="block text-[11px] text-slate-500">Assign to analyst</label>
            <div className="flex gap-2">
              <input
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                placeholder="analyst name"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <button
                onClick={() => actor.trim() && act(() => api.incidentPatch(incident.id, { assigned_to: actor.trim() }))}
                disabled={busy || !actor.trim()}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-200 hover:bg-slate-700 disabled:opacity-50"
              >
                Assign
              </button>
            </div>
          </div>
          {error && <div className="mt-3 text-rose-300 text-sm">{error}</div>}
        </Card>
      </div>

      <div className="space-y-4">
        <Card title={`Evidence (${incident.evidence.length})`}>
          <EvidenceTable evidence={incident.evidence} resolved={incident.evidence_resolved} />
        </Card>

        <Card title="Investigation Notes">
          <div className="space-y-2 mb-3">
            {incident.notes.length === 0 ? (
              <EmptyState message="No notes yet." />
            ) : (
              incident.notes.map((n) => (
                <div key={n.id} className="rounded-lg border border-slate-800 bg-slate-800/30 p-3">
                  <div className="flex justify-between text-[11px] text-slate-500">
                    <span>{n.author ?? "analyst"}</span>
                    <span>{fmtTimestamp(n.created_at)}</span>
                  </div>
                  <p className="text-sm text-slate-200 mt-1">{n.text}</p>
                </div>
              ))
            )}
          </div>
          <div className="space-y-2">
            <textarea
              value={noteText}
              onChange={(e) => setNoteText(e.target.value)}
              rows={2}
              placeholder="Add an investigation note…"
              className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
            <div className="flex gap-2">
              <input
                value={noteAuthor}
                onChange={(e) => setNoteAuthor(e.target.value)}
                placeholder="analyst name (optional)"
                className="flex-1 rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-1.5 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <button
                onClick={() => noteText.trim() && act(() => api.incidentAddNote(incident.id, noteText.trim(), noteAuthor.trim() || undefined).then(() => { setNoteText(""); }))}
                disabled={busy || !canAddNote}
                className="px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-300 text-sm font-medium hover:bg-cyan-500/20 disabled:opacity-50"
              >
                Add note
              </button>
            </div>
          </div>
        </Card>

        <Card title="History">
          {incident.history.length === 0 ? (
            <EmptyState message="No history yet." />
          ) : (
            <ol className="space-y-2 text-sm">
              {incident.history.map((h) => (
                <li key={h.id} className="flex gap-3 text-slate-300">
                  <span className="text-slate-500 font-mono text-[11px] whitespace-nowrap">{fmtTimestamp(h.created_at)}</span>
                  <span>
                    <span className="font-medium text-slate-200">{h.event_type}</span>
                    {h.old_status && h.new_status && (
                      <span className="text-slate-400"> · {h.old_status} → {h.new_status}</span>
                    )}
                    {h.message && <span className="text-slate-500"> · {h.message}</span>}
                    {h.actor && <span className="text-slate-500"> · {h.actor}</span>}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </Card>
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`truncate text-slate-200 ${mono ? "font-mono text-xs" : ""}`}>{value}</div>
    </div>
  );
}

function ActionButton({
  label,
  onClick,
  disabled,
  busy,
  danger,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  busy?: boolean;
  danger?: boolean;
}) {
  const base = danger
    ? "bg-rose-500/10 text-rose-300 hover:bg-rose-500/20"
    : "bg-slate-800 text-slate-200 hover:bg-slate-700";
  return (
    <button
      onClick={onClick}
      disabled={disabled || busy}
      className={`px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-40 disabled:cursor-not-allowed ${base}`}
    >
      {label}
    </button>
  );
}

function EvidenceTable({
  evidence,
  resolved,
}: {
  evidence: IncidentDetail["evidence"];
  resolved: IncidentDetail["evidence_resolved"];
}) {
  const byId = useMemo(() => {
    const m = new Map<string, IncidentDetail["evidence_resolved"][number]>();
    resolved.forEach((r) => {
      if (r.id) m.set(r.id, r);
    });
    return m;
  }, [resolved]);

  if (evidence.length === 0) return <EmptyState message="No evidence references." />;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left uppercase text-slate-500 border-b border-slate-800">
            <th className="py-1 pr-3">Type</th>
            <th className="py-1 pr-3">ID</th>
            <th className="py-1 pr-3">Src</th>
            <th className="py-1 pr-3">Dst</th>
            <th className="py-1 pr-3">Detail / Record</th>
          </tr>
        </thead>
        <tbody>
          {evidence.map((e, i) => {
            const rec = e.id ? byId.get(e.id) : undefined;
            return (
              <tr key={i} className="border-b border-slate-800/60 last:border-0">
                <td className="py-1 pr-3 text-slate-300">{e.type}</td>
                <td className="py-1 pr-3 font-mono text-slate-400 truncate max-w-[140px]">{e.id ?? "—"}</td>
                <td className="py-1 pr-3 text-slate-300">{e.src ?? "—"}</td>
                <td className="py-1 pr-3 text-slate-300">{e.dst ?? "—"}</td>
                <td className="py-1 pr-3 text-slate-400">
                  {rec ? (
                    <span className="text-emerald-300/90">
                      ✓ {rec.status === "ok" ? "record " + e.type : "missing"} {rec.record ? formatRecord(e.type, rec.record) : ""}
                    </span>
                  ) : (
                    e.detail ?? "—"
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function formatRecord(type: string, record: Record<string, unknown>): string {
  if (type === "connection") return `{${record.src}→${record.dst} :${record.dport} ${record.service ?? ""} ${record.bytes_total} bytes}`.trim();
  if (type === "dns") return `{${record.query ?? ""} ${record.rcode_name ?? ""}}`.trim();
  if (type === "http") return `{${record.method ?? ""} ${record.host ?? ""}${record.uri ?? ""}}`.trim();
  return `{fr ${record.frame_number ?? ""} ${record.length ?? ""} bytes}`.trim();
}

function availableActions(status: string) {
  return {
    canInvestigate: status === "NEW",
    canContain: status === "INVESTIGATING",
    canResolve: status === "INVESTIGATING" || status === "CONTAINED",
    canFalsePositive: status === "INVESTIGATING" || status === "CONTAINED",
    canReopen: status === "RESOLVED" || status === "FALSE_POSITIVE",
  };
}