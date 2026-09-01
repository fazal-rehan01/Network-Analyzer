export interface ComponentStatus {
  name: string;
  installed: boolean;
  version: string | null;
  path: string | null;
  note: string | null;
}

export interface HealthResponse {
  status: string;
  app: string;
  database: string;
  version: string;
}

export interface SystemStatusResponse {
  status: string;
  components: ComponentStatus[];
}

export interface InterfaceInfo {
  index: number;
  name: string;
  description: string | null;
  loopback: boolean;
}

export interface ProtocolStat {
  protocol: string;
  frames: number;
  bytes: number;
}

export interface CaptureStats {
  packet_count: number;
  byte_count: number;
  protocols: ProtocolStat[];
  top_talkers: Array<Record<string, unknown>>;
  time_series: Array<{ t: number; frames: number; bytes: number }>;
  captures_count: number;
}

export interface CaptureRead {
  id: string;
  name: string;
  source: string;
  filename: string | null;
  file_path: string | null;
  interface: string | null;
  filter_expr: string | null;
  start_time: string | null;
  end_time: string | null;
  duration_sec: number | null;
  packet_count: number;
  byte_count: number;
  status: string;
  error: string | null;
  created_at: string;
}

export interface CaptureCreate {
  name?: string;
  interface_index: number;
  filter_expr?: string;
  duration_sec?: number;
}

export interface ZeekLogSummary {
  log_type: string;
  filename: string;
  path: string;
  present: boolean;
  rows: number;
}

export interface ZeekProcessResult {
  available: boolean;
  summary: ZeekLogSummary[];
  logs: Record<string, Array<Record<string, unknown>>>;
  error: string | null;
  capture_id: string | null;
}

export interface ZeekEvent {
  id: string;
  log_type: string;
  capture_id: string | null;
  ts: number | null;
  uid: string | null;
  src: string | null;
  dst: string | null;
  fields: Record<string, unknown>;
  created_at: string;
}
