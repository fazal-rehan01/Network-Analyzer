import type {
  HealthResponse,
  SystemStatusResponse,
  InterfaceInfo,
  CaptureRead,
  CaptureCreate,
  CaptureStats,
  ZeekProcessResult,
  ZeekEvent,
  NormalizeStatus,
  NormalizeSummary,
  ConnectionRead,
  DnsEventRead,
  HttpEventRead,
  PacketRead,
  RuleInfo,
  DetectionRunResult,
  DetectionSummary,
  DetectionFindingRead,
  IncidentRead,
  IncidentDetail,
  IncidentCreateResult,
  IncidentListResult,
  IncidentListParams,
  IncidentNoteRead,
  IncidentSummary,
  DashboardAnalytics,
  CompareStatus,
  CaptureComparison,
  ConnectionComparison,
  ReportOptions,
  ReportGenerateRequest,
  ScenarioInfo,
  SimulationCreate,
  SimulationRead,
} from "./types";

const BASE = "/api/v1";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json() as Promise<T>;
}

async function blobRequest(path: string, payload: ReportGenerateRequest): Promise<Blob> {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.blob();
}

export const api = {
  health: () => request<HealthResponse>("/health"),
  systemStatus: () => request<SystemStatusResponse>("/system/status"),

  captureInterfaces: () => request<InterfaceInfo[]>("/captures/interfaces"),
  captureList: () => request<CaptureRead[]>("/captures"),
  captureStart: (payload: CaptureCreate) => request<CaptureRead>("/captures", { method: "POST", body: JSON.stringify(payload) }),
  captureGet: (id: string) => request<CaptureRead>(`/captures/${id}`),
  captureStats: (id: string) => request<CaptureStats>(`/captures/${id}/stats`),
  captureStop: (id: string) => request<CaptureRead>(`/captures/${id}/stop`, { method: "POST" }),
  captureDelete: (id: string) => request<void>(`/captures/${id}`, { method: "DELETE" }),
  captureUpload: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<CaptureRead>("/captures/upload", { method: "POST", body: form, headers: {} });
  },

  zeekStatus: () => request<{ available: boolean; zeek_dir: string }>("/zeek/status"),
  zeekProcess: (captureId: string) =>
    request<ZeekProcessResult>(`/zeek/process?capture_id=${encodeURIComponent(captureId)}`, { method: "POST" }),
  zeekEvents: (captureId: string, logType?: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    if (logType) params.set("log_type", logType);
    return request<ZeekEvent[]>(`/zeek/events?${params.toString()}`);
  },

  normalizeStatus: () => request<NormalizeStatus>("/normalize/status"),
  normalizeRun: (captureId: string) =>
    request<NormalizeSummary>(`/normalize/run?capture_id=${encodeURIComponent(captureId)}`, { method: "POST" }),
  normalizeConnections: (captureId: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    return request<ConnectionRead[]>(`/normalize/connections?${params.toString()}`);
  },
  normalizeDns: (captureId: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    return request<DnsEventRead[]>(`/normalize/dns?${params.toString()}`);
  },
  normalizeHttp: (captureId: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    return request<HttpEventRead[]>(`/normalize/http?${params.toString()}`);
  },
  normalizePackets: (captureId: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    return request<PacketRead[]>(`/normalize/packets?${params.toString()}`);
  },

  detectRules: () => request<RuleInfo[]>("/detect/rules"),
  detectRun: (captureId: string) =>
    request<DetectionRunResult>(`/detect/run?capture_id=${encodeURIComponent(captureId)}`, { method: "POST" }),
  detectFindings: (captureId: string, severity?: string, limit = 500) => {
    const params = new URLSearchParams({ capture_id: captureId, limit: String(limit) });
    if (severity) params.set("severity", severity);
    return request<DetectionFindingRead[]>(`/detect/findings?${params.toString()}`);
  },
  detectSummary: (captureId: string) =>
    request<DetectionSummary>(`/detect/summary?capture_id=${encodeURIComponent(captureId)}`),

  incidentList: (params: IncidentListParams = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== "") qs.set(k, String(v));
    });
    return request<IncidentListResult>(`/incidents?${qs.toString()}`);
  },
  incidentGet: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  incidentCreateFromFinding: (detection_finding_id: string, title?: string, description?: string) =>
    request<IncidentCreateResult>("/incidents/from-finding", {
      method: "POST",
      body: JSON.stringify({ detection_finding_id, title, description }),
    }),
  incidentCreateFromCapture: (captureId: string) =>
    request<IncidentCreateResult>(`/incidents/from-capture?capture_id=${encodeURIComponent(captureId)}`, { method: "POST" }),
  incidentPatch: (id: string, payload: Record<string, unknown>) =>
    request<IncidentRead>(`/incidents/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
  incidentAddNote: (id: string, text: string, author?: string) =>
    request<IncidentNoteRead>(`/incidents/${id}/notes`, {
      method: "POST",
      body: JSON.stringify({ text, author }),
    }),
  incidentDelete: (id: string) => request<void>(`/incidents/${id}`, { method: "DELETE" }),
  incidentSummary: () => request<IncidentSummary>("/incidents/summary"),

  analyticsDashboard: (captureId?: string) => {
    const qs = new URLSearchParams();
    if (captureId) qs.set("capture_id", captureId);
    return request<DashboardAnalytics>(`/analytics/dashboard?${qs.toString()}`);
  },

  compareStatus: () => request<CompareStatus>("/compare/status"),
  compareCapture: (captureId: string) => request<CaptureComparison>(`/compare/capture/${encodeURIComponent(captureId)}`),
  compareConnection: (connectionId: string) =>
    request<ConnectionComparison>(`/compare/connection/${encodeURIComponent(connectionId)}`),

  reportOptions: () => request<ReportOptions>("/reports/options"),
  reportGenerate: (captureId?: string) =>
    blobRequest("/reports/generate", { capture_id: captureId ?? null }),

  simulationScenarios: () => request<ScenarioInfo[]>("/simulations/scenarios"),
  simulationList: () => request<SimulationRead[]>("/simulations"),
  simulationCreate: (payload: SimulationCreate) =>
    request<SimulationRead>("/simulations", { method: "POST", body: JSON.stringify(payload) }),
  simulationStart: (id: string) => request<SimulationRead>(`/simulations/${encodeURIComponent(id)}/start`, { method: "POST" }),
  simulationStop: (id: string) => request<SimulationRead>(`/simulations/${encodeURIComponent(id)}/stop`, { method: "POST" }),
  simulationGet: (id: string) => request<SimulationRead>(`/simulations/${encodeURIComponent(id)}`),
};
