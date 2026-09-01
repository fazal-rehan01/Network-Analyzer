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

export interface RuleInfo {
  id: string;
  name: string;
  default_severity: string;
}

export interface DetectionRunResult {
  capture_id: string | null;
  findings: number;
  rules_evaluated: number;
  by_severity: Record<string, number>;
}

export interface DetectionSummary {
  capture_id: string | null;
  total: number;
  by_severity: Record<string, number>;
}

export interface DetectionFindingRead {
  id: string;
  capture_id: string | null;
  rule_id: string | null;
  rule_name: string | null;
  severity: string;
  score: number;
  summary: string | null;
  detail: string | null;
  evidence: Array<{
    type: string;
    id: string | null;
    src: string | null;
    dst: string | null;
    detail: string | null;
  }>;
  ref_type: string | null;
  created_at: string | null;
}

export interface IncidentRead {
  id: string;
  detection_finding_id: string;
  capture_id: string | null;
  capture_name: string | null;
  rule_id: string | null;
  rule_name: string | null;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  score: number;
  summary: string | null;
  detail: string | null;
  ref_type: string | null;
  assigned_to: string | null;
  resolution: string | null;
  resolution_notes: string | null;
  closed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
}

export interface IncidentNoteRead {
  id: string;
  incident_id: string;
  text: string;
  author: string | null;
  created_at: string | null;
}

export interface IncidentEventRead {
  id: string;
  incident_id: string;
  event_type: string;
  old_status: string | null;
  new_status: string | null;
  message: string | null;
  actor: string | null;
  created_at: string | null;
}

export interface IncidentDetail extends IncidentRead {
  evidence: Array<{
    type: string;
    id: string | null;
    src: string | null;
    dst: string | null;
    detail: string | null;
  }>;
  evidence_resolved: Array<{
    type: string;
    id: string | null;
    status: string;
    record: Record<string, unknown> | null;
  }>;
  notes: IncidentNoteRead[];
  history: IncidentEventRead[];
}

export interface IncidentCreateResult {
  incident: IncidentRead | null;
  created: number;
  skipped: number;
  existing: string | null;
}

export interface IncidentListResult {
  items: IncidentRead[];
  total: number;
  limit: number;
  offset: number;
}

export interface IncidentSummary {
  total: number;
  open: number;
  critical: number;
  high: number;
  resolved: number;
  false_positive: number;
  recent: IncidentRead[];
}

export interface IncidentListParams {
  status?: string;
  severity?: string;
  capture_id?: string;
  rule_id?: string;
  search?: string;
  sort_by?: string;
  order?: string;
  limit?: number;
  offset?: number;
}

export interface AnalyticsSummary {
  captures: number;
  packets: number;
  connections: number;
  bytes_total: number;
  packets_per_sec: number;
  open_incidents: number;
  high_critical_incidents: number;
  resolved_incidents: number;
}

export interface ProtocolSlice {
  proto: string;
  count: number;
  bytes: number;
}

export interface TalkerSlice {
  ip: string;
  packets: number;
  bytes: number;
}

export interface ConversationSlice {
  src: string;
  dst: string;
  proto: string;
  packets: number;
  bytes: number;
}

export interface TrafficPoint {
  ts: number;
  packets: number;
  bytes: number;
}

export interface DnsStats {
  total: number;
  unique_queries: number;
  by_rcode: Record<string, number>;
  top_queries: { query: string; count: number }[];
}

export interface HttpStats {
  total: number;
  by_method: Record<string, number>;
  by_status: Record<string, number>;
  top_hosts: { host: string; count: number }[];
}

export interface SeverityCount {
  total: number;
  info: number;
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface DashboardAnalytics {
  scope: string;
  capture_id: string | null;
  summary: AnalyticsSummary;
  protocol_distribution: ProtocolSlice[];
  top_sources: TalkerSlice[];
  top_destinations: TalkerSlice[];
  top_conversations: ConversationSlice[];
  traffic_over_time: TrafficPoint[];
  dns_stats: DnsStats;
  http_stats: HttpStats;
  detection: SeverityCount;
  incidents: SeverityCount;
  recent_incidents: {
    id: string;
    title: string;
    severity: string;
    status: string;
    rule_name: string | null;
    rule_id: string | null;
    capture_id: string | null;
    created_at: string | null;
  }[];
}

export interface CompareStatus {
  tshark_available: boolean;
  zeek_available: boolean;
}

export interface TsharkSide {
  present: boolean;
  description: string;
  src: string | null;
  dst: string | null;
  proto: string | null;
  sport: number | null;
  dport: number | null;
  packet_count: number;
  bytes: number;
  first_ts: number | null;
  last_ts: number | null;
  packets: {
    id: string;
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
    dns_qname: string | null;
    dns_rcode: string | null;
  }[];
}

export interface ZeekConnSide {
  present: boolean;
  uid: string | null;
  service: string | null;
  conn_state: string | null;
  duration: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  src: string | null;
  dst: string | null;
  proto: string | null;
  sport: number | null;
  dport: number | null;
}

export interface ZeekSide {
  present: boolean;
  description: string;
  uid: string | null;
  conn: ZeekConnSide | null;
  dns: Record<string, unknown>[];
  http: Record<string, unknown>[];
  ssl: Record<string, unknown>[];
  notices: Record<string, unknown>[];
  event_count: number;
}

export interface ConnectionComparison {
  id: string;
  src: string | null;
  dst: string | null;
  proto: string | null;
  sport: number | null;
  dport: number | null;
  service: string | null;
  packets: number;
  bytes_total: number;
  zeek_uid: string | null;
  source: string;
  correlation_status: string;
  correlation_summary: string;
  tshark: TsharkSide;
  zeek: ZeekSide;
  evidence: { tshark: string[]; zeek: string[] };
}

export interface CaptureComparisonSummary {
  connections_total: number;
  both: number;
  tshark_only: number;
  zeek_only: number;
  packets_tshark: number;
  zeek_events: number;
}

export interface CaptureComparison {
  capture_id: string;
  capture_name: string | null;
  tshark_available: boolean;
  zeek_available: boolean;
  summary: CaptureComparisonSummary;
  connections: {
    id: string;
    src: string | null;
    dst: string | null;
    proto: string | null;
    sport: number | null;
    dport: number | null;
    service: string | null;
    packets: number;
    bytes_total: number;
    zeek_uid: string | null;
    source: string;
    correlation_status: string;
    correlation_summary: string;
  }[];
}
