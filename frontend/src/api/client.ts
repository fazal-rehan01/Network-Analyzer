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
};
