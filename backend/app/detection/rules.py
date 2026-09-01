"""Explainable, rule-based detection rules (M10).

Each rule is a pure function over normalized records (Connections, DnsEvents,
HttpEvents, Packets). Rules are deterministic and produce concrete
``DetectionFinding`` objects whose ``evidence`` references the normalized
records they were derived from. Thresholds come from a configurable dict so
the engine is tunable without code changes.

Severity is computed from a base severity that may be scaled upward by how far
the observed value exceeds the threshold (deterministic ratio). No AI, no
fabricated counts.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.normalized import Connection, DnsEvent, HttpEvent, Packet

SEVERITIES = ("info", "low", "medium", "high", "critical")

# Default thresholds; overridden by settings-derived dict at run time.
DEFAULT_THRESHOLDS: dict[str, Any] = {
    "portscan_min_ports": 10,
    "conn_rate_window_sec": 10.0,
    "conn_rate_max_per_window": 100,
    "dns_nxdomain_min": 5,
    "dns_query_diversity_min": 50,
    "data_transfer_min_bytes": 10_000_000,
    "severity_high_multiplier": 2.0,
    "severity_critical_multiplier": 4.0,
}


@dataclass
class RuleContext:
    """Normalized evidence the rules operate on."""

    connections: list[Connection] = field(default_factory=list)
    dns: list[DnsEvent] = field(default_factory=list)
    http: list[HttpEvent] = field(default_factory=list)
    packets: list[Packet] = field(default_factory=list)
    thresholds: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))


@dataclass
class DetectionFinding:
    """A deterministic detection result referencing its evidence."""

    rule_id: str
    rule_name: str
    severity: str
    score: float
    summary: str
    detail: str
    evidence: list[dict] = field(default_factory=list)
    ref_type: str | None = None

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "score": self.score,
            "summary": self.summary,
            "detail": self.detail,
            "evidence": self.evidence,
            "ref_type": self.ref_type,
        }


def _scaled_severity(base: str, ratio: float, thresholds: dict) -> str:
    """Scale severity up deterministically by how far over threshold we are."""
    high_mult = float(thresholds.get("severity_high_multiplier", 2.0))
    crit_mult = float(thresholds.get("severity_critical_multiplier", 4.0))
    if ratio is None or ratio < 1.0:
        return base
    if ratio >= crit_mult:
        return "critical"
    if ratio >= high_mult:
        return "high"
    return base


def _t_ports(ctx: RuleContext) -> int:
    return int(ctx.thresholds.get("portscan_min_ports", DEFAULT_THRESHOLDS["portscan_min_ports"]))


def _find_ev(type_: str, obj_id: str, src, dst, detail: str) -> dict:
    return {
        "type": type_,
        "id": obj_id,
        "src": src,
        "dst": dst,
        "detail": detail,
    }


def detect_possible_port_scan(ctx: RuleContext) -> list[DetectionFinding]:
    """One source IP contacting many distinct TCP destination ports."""
    min_ports = _t_ports(ctx)
    # src -> set of dst_ports summed over TCP connections.
    by_src: dict[str, set] = {}
    conn_by_key: dict[str, Connection] = {}
    for c in ctx.connections:
        if not c.src or c.proto not in ("tcp", "6"):
            continue
        by_src.setdefault(c.src, set()).add(c.dport)
        conn_by_key[c.conn_key] = c

    findings: list[DetectionFinding] = []
    for src, ports in by_src.items():
        if len(ports) < min_ports:
            continue
        ratio = len(ports) / min_ports
        severity = _scaled_severity("medium", ratio, ctx.thresholds)
        ev = []
        for key in list(conn_by_key.keys()):
            c = conn_by_key[key]
            if c.src == src and len(ev) < 20:
                ev.append(_find_ev("connection", c.id, c.src, c.dst, f"{c.proto} {c.dport}"))
        findings.append(
            DetectionFinding(
                rule_id="port_scan",
                rule_name="Possible Port Scan",
                severity=severity,
                score=float(len(ports)),
                summary=f"Source {src} contacted {len(ports)} distinct destination ports",
                detail=(
                    f"{len(ports)} distinct TCP destination ports from {src} "
                    f"(threshold {min_ports}). Possible horizontal port scan."
                ),
                evidence=ev,
                ref_type="connection",
            )
        )
    return findings


def _max_in_window(timestamps: list[float], window: float, max_first_before: float | None = None) -> int:
    """Return the max number of timestamps inside any sliding window."""
    times = sorted(t for t in timestamps if t is not None)
    if not times:
        return 0
    max_count = 0
    left = 0
    for right in range(len(times)):
        while times[right] - times[left] > window:
            left += 1
        max_count = max(max_count, right - left + 1)
    return max_count


def detect_abnormal_connection_rate(ctx: RuleContext) -> list[DetectionFinding]:
    """Abnormally high number of connection starts within a time window."""
    window = float(ctx.thresholds.get("conn_rate_window_sec", DEFAULT_THRESHOLDS["conn_rate_window_sec"]))
    cap = int(ctx.thresholds.get("conn_rate_max_per_window", DEFAULT_THRESHOLDS["conn_rate_max_per_window"]))
    starts = [c.first_ts for c in ctx.connections if c.first_ts is not None]
    peak = _max_in_window(starts, window)
    if peak <= cap:
        return []
    ratio = peak / cap
    severity = _scaled_severity("medium", ratio, ctx.thresholds)
    ev = []
    # Reference up to a handful of connection records within the busiest window.
    times = sorted(starts)
    for c in ctx.connections:
        if c.first_ts is not None and len(ev) < 10:
            ev.append(_find_ev("connection", c.id, c.src, c.dst, f"{c.proto} {c.dport}"))
    return [
        DetectionFinding(
            rule_id="conn_rate",
            rule_name="Abnormal Connection Rate",
            severity=severity,
            score=float(peak),
            summary=f"Connection rate peaked at {peak} connections in {window:g}s window",
            detail=(
                f"Peak of {peak} connection starts within {window:g}s exceeds threshold {cap}. "
                "Could indicate a burst/flood or scan activity."
            ),
            evidence=ev,
            ref_type="connection",
        )
    ]


def _is_nxdomain(marker: Any) -> bool:
    """True for an NXDOMAIN DNS response.

    Zeek stores the human-readable rcode name (``NXDOMAIN``) while TShark's
    ``dns.flags.rcode`` field is numeric (3 = NXDOMAIN). Accept both so the
    rule works against normalized records from either evidence source.
    """
    if marker is None:
        return False
    s = str(marker).strip().upper()
    return s == "NXDOMAIN" or s == "3"


def detect_dns_anomaly(ctx: RuleContext) -> list[DetectionFinding]:
    """Abnormally many NXDOMAIN responses — possible DNS anomaly/recon."""
    min_nx = int(ctx.thresholds.get("dns_nxdomain_min", DEFAULT_THRESHOLDS["dns_nxdomain_min"]))
    nxdomain = [d for d in ctx.dns if _is_nxdomain(d.rcode_name)]
    if len(nxdomain) < min_nx:
        return []
    ratio = len(nxdomain) / min_nx
    severity = _scaled_severity("medium", ratio, ctx.thresholds)
    ev = [
        _find_ev("dns", d.id, d.src, d.dst, d.query or "")
        for d in nxdomain[:10]
    ]
    return [
        DetectionFinding(
            rule_id="dns_anomaly",
            rule_name="Possible DNS Anomaly",
            severity=severity,
            score=float(len(nxdomain)),
            summary=f"{len(nxdomain)} NXDOMAIN DNS responses observed",
            detail=(
                f"{len(nxdomain)} NXDOMAIN responses (threshold {min_nx}). "
                "Frequent NXDOMAIN can indicate domain-generation algorithms or DNS recon."
            ),
            evidence=ev,
            ref_type="dns",
        )
    ]


def detect_dns_query_diversity(ctx: RuleContext) -> list[DetectionFinding]:
    """Unusually high diversity of unique DNS queries from one source."""
    min_unique = int(ctx.thresholds.get("dns_query_diversity_min", DEFAULT_THRESHOLDS["dns_query_diversity_min"]))
    by_src: dict[str, set] = {}
    ev_by_src: dict[str, list] = {}
    for d in ctx.dns:
        if not d.src or not d.query:
            continue
        by_src.setdefault(d.src, set()).add(d.query)
        if len(ev_by_src.setdefault(d.src, [])) < 10:
            ev_by_src[d.src].append(_find_ev("dns", d.id, d.src, d.dst, d.query))
    findings: list[DetectionFinding] = []
    for src, queries in by_src.items():
        if len(queries) < min_unique:
            continue
        ratio = len(queries) / min_unique
        severity = _scaled_severity("low", ratio, ctx.thresholds)
        findings.append(
            DetectionFinding(
                rule_id="dns_query_diversity",
                rule_name="High DNS Query Diversity",
                severity=severity,
                score=float(len(queries)),
                summary=f"{len(queries)} unique DNS queries from {src}",
                detail=(
                    f"Source {src} resolved {len(queries)} unique query names "
                    f"(threshold {min_unique}). Possible DNS tunneling or recon."
                ),
                evidence=ev_by_src[src],
                ref_type="dns",
            )
        )
    return findings


def detect_high_data_transfer(ctx: RuleContext) -> list[DetectionFinding]:
    """A single connection transferring an unusually large volume of data."""
    # Threshold expressed as a diagnostic minimum (bytes); deterministic.
    min_bytes = int(
        ctx.thresholds.get("data_transfer_min_bytes", DEFAULT_THRESHOLDS["data_transfer_min_bytes"])
    )
    findings: list[DetectionFinding] = []
    for c in ctx.connections:
        total = c.bytes_total or 0
        if total < min_bytes:
            continue
        ratio = total / min_bytes
        severity = _scaled_severity("low", ratio, ctx.thresholds)
        findings.append(
            DetectionFinding(
                rule_id="high_data_transfer",
                rule_name="Large Data Transfer",
                severity=severity,
                score=float(total),
                summary=f"{total} bytes transferred on {c.proto} connection to {c.dst}",
                detail=(
                    f"A connection from {c.src} to {c.dst}:{c.dport} ({c.proto}) transferred "
                    f"{total} bytes (threshold {min_bytes}). Large egress may indicate exfiltration."
                ),
                evidence=[
                    _find_ev("connection", c.id, c.src, c.dst, f"{c.proto} {c.bytes_total} bytes")
                ],
                ref_type="connection",
            )
        )
    return findings


# Registry of all rules: function -> (rule_id).
ALL_RULES: list[dict] = [
    {"id": "port_scan", "name": "Possible Port Scan", "fn": detect_possible_port_scan, "default_severity": "medium"},
    {"id": "conn_rate", "name": "Abnormal Connection Rate", "fn": detect_abnormal_connection_rate, "default_severity": "medium"},
    {"id": "dns_anomaly", "name": "Possible DNS Anomaly", "fn": detect_dns_anomaly, "default_severity": "medium"},
    {"id": "dns_query_diversity", "name": "High DNS Query Diversity", "fn": detect_dns_query_diversity, "default_severity": "low"},
    {"id": "high_data_transfer", "name": "Large Data Transfer", "fn": detect_high_data_transfer, "default_severity": "low"},
]


def run_all_rules(ctx: RuleContext) -> list[DetectionFinding]:
    """Run every rule and return all findings (deterministic order)."""
    findings: list[DetectionFinding] = []
    for rule in ALL_RULES:
        findings.extend(rule["fn"](ctx))
    return findings
