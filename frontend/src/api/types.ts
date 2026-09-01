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

export interface NormalizeStatus {
  tshark_available: boolean;
  zeek_available: boolean;
}

export interface NormalizeSummary {
  capture_id: string | null;
  tshark_available: boolean;
  zeek_available: boolean;
  packets_parsed: number;
  packets_persisted: number;
  connections: number;
  dns_events: number;
  http_events: number;
  connections_with_zeek: number;
  error: string | null;
}

export interface ConnectionRead {
  id: string;
  capture_id: string | null;
  conn_key: string;
  src: string | null;
  dst: string | null;
  proto: string | null;
  sport: number | null;
  dport: number | null;
  service: string | null;
  zeek_uid: string | null;
  conn_state: string | null;
  packets: number;
  bytes_total: number;
  orig_bytes: number | null;
  resp_bytes: number | null;
  duration: number | null;
  first_ts: number | null;
  last_ts: number | null;
  source: string;
  created_at: string;
}

export interface DnsEventRead {
  id: string;
  capture_id: string | null;
  connection_id: string | null;
  ts: number | null;
  src: string | null;
  dst: string | null;
  query: string | null;
  qtype_name: string | null;
  rcode_name: string | null;
  answers: string | null;
  proto: string | null;
  trans_id: number | null;
  source: string;
  zeek_uid: string | null;
  packet_ref: string | null;
  raw: string | null;
  created_at: string;
}

export interface HttpEventRead {
  id: string;
  capture_id: string | null;
  connection_id: string | null;
  ts: number | null;
  src: string | null;
  dst: string | null;
  method: string | null;
  host: string | null;
  uri: string | null;
  user_agent: string | null;
  status_code: number | null;
  resp_len: number | null;
  referrer: string | null;
  source: string;
  zeek_uid: string | null;
  packet_ref: string | null;
  raw: string | null;
  created_at: string;
}

export interface PacketRead {
  id: string;
  capture_id: string | null;
  frame_number: number | null;
  ts: number | null;
  src: string | null;
  dst: string | null;
  proto: string | null;
  sport: number | null;
  dport: number | null;
  length: number | null;
  tcp_flags: string | null;
  http_method: string | null;
  http_host: string | null;
  http_uri: string | null;
  http_status: number | null;
  dns_qname: string | null;
  dns_qtype: string | null;
  dns_rcode: string | null;
  source: string;
  created_at: string;
}
