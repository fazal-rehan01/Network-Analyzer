import type { HealthResponse, SystemStatusResponse, InterfaceInfo, CaptureRead, CaptureCreate, CaptureStats } from "./types";

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
};
