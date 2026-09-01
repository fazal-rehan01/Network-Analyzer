"""Tests for the detection engine (MILESTONE 10).

Each rule is tested with positive (fires) and negative (does not fire) cases,
plus severity scaling and the service/API layer. All rules are deterministic.
"""
from __future__ import annotations

import pytest

from app.detection.rules import (
    RuleContext,
    run_all_rules,
    detect_possible_port_scan,
    detect_abnormal_connection_rate,
    detect_dns_anomaly,
    detect_dns_query_diversity,
    detect_high_data_transfer,
)
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.models.normalized import Connection, DnsEvent
from app.models.detection import DetectionFinding as FindingRow
from app.services import detection as detect_svc


def mk_conn(src, dst, proto="tcp", sport=1, dport=80, first_ts=None, bytes_total=0, conn_key=None):
    import uuid

    return Connection(
        id=str(uuid.uuid4()),
        src=src, dst=dst, proto=proto, sport=sport, dport=dport,
        first_ts=first_ts, bytes_total=bytes_total,
        conn_key=conn_key or f"{proto}|{src}|{dst}|{sport}|{dport}",
    )


def mk_dns(src, query, rcode_name="NOERROR", dst="8.8.8.8", ts=None):
    import uuid

    return DnsEvent(id=str(uuid.uuid4()), src=src, dst=dst, query=query, rcode_name=rcode_name, ts=ts)


def ctx(connections=None, dns=None, http=None, packets=None, thresholds=None):
    kwargs = dict(
        connections=connections or [],
        dns=dns or [],
        http=http or [],
        packets=packets or [],
    )
    if thresholds is not None:
        kwargs["thresholds"] = thresholds
    return RuleContext(**kwargs)


# ------------------------------------------------------------- port scan


def test_port_scan_positive():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=p) for p in range(15)]
    findings = detect_possible_port_scan(ctx(conns))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "port_scan"
    assert f.severity in ("medium", "high", "critical")
    assert f.evidence  # references normalized connections
    assert f.evidence[0]["type"] == "connection"
    assert f.evidence[0]["id"]


def test_port_scan_negative_below_threshold():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=p) for p in range(5)]
    assert detect_possible_port_scan(ctx(conns)) == []


def test_port_scan_negative_udp_only():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", proto="udp", dport=p) for p in range(20)]
    assert detect_possible_port_scan(ctx(conns)) == []


def test_port_scan_severity_scales_with_magnitude():
    low = detect_possible_port_scan(ctx([mk_conn("10.0.0.1", "10.0.0.2", dport=p) for p in range(12)]))
    high = detect_possible_port_scan(ctx([mk_conn("10.0.0.1", "10.0.0.2", dport=p) for p in range(60)]))
    assert low[0].severity == "medium"
    assert high[0].severity == "critical"


def test_port_scan_configurable_threshold():
    # A custom low threshold makes a small scan fire.
    th = {"portscan_min_ports": 3}
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=p) for p in range(4)]
    assert detect_possible_port_scan(ctx(conns, thresholds=th))
    assert detect_possible_port_scan(ctx(conns)) == []  # default 10


# ------------------------------------------------------------- conn rate


def test_conn_rate_positive():
    # 200 connections all starting within a 1-second window.
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=80 + i, first_ts=1000.0 + i * 0.001) for i in range(200)]
    th = {"conn_rate_window_sec": 10.0, "conn_rate_max_per_window": 100}
    findings = detect_abnormal_connection_rate(ctx(conns, thresholds=th))
    assert len(findings) == 1
    assert findings[0].rule_id == "conn_rate"
    assert findings[0].score >= 190


def test_conn_rate_negative():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=i, first_ts=1000.0 + i * 5.0) for i in range(10)]
    assert detect_abnormal_connection_rate(ctx(conns)) == []


def test_conn_rate_uses_sliding_window():
    # Burst of 150 in a tight window then quiet -> still fires.
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=i, first_ts=2000.0 + i * 0.001) for i in range(150)]
    th = {"conn_rate_window_sec": 10.0, "conn_rate_max_per_window": 100}
    findings = detect_abnormal_connection_rate(ctx(conns, thresholds=th))
    assert len(findings) == 1


def test_conn_rate_configurable_threshold():
    # Default threshold (100) doesn't fire; a lower custom threshold does.
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=i, first_ts=3000.0 + i * 0.001) for i in range(50)]
    assert detect_abnormal_connection_rate(ctx(conns)) == []
    th = {"conn_rate_window_sec": 10.0, "conn_rate_max_per_window": 40}
    assert detect_abnormal_connection_rate(ctx(conns, thresholds=th))


# ------------------------------------------------------------- dns anomaly


def test_dns_nxdomain_positive():
    dns = [mk_dns("10.0.0.1", q, rcode_name="NXDOMAIN") for q in [f"q{i}.invalid" for i in range(7)]]
    findings = detect_dns_anomaly(ctx(dns=dns))
    assert len(findings) == 1
    assert findings[0].rule_id == "dns_anomaly"
    assert findings[0].score == 7
    assert findings[0].evidence[0]["type"] == "dns"


def test_dns_nxdomain_negative():
    dns = [mk_dns("10.0.0.1", "example.com", rcode_name="NOERROR")]
    assert detect_dns_anomaly(ctx(dns=dns)) == []
    # Below the threshold.
    dns2 = [mk_dns("10.0.0.1", q, rcode_name="NXDOMAIN") for q in [f"q{i}.invalid" for i in range(3)]]
    assert detect_dns_anomaly(ctx(dns=dns2)) == []


def test_dns_nxdomain_case_insensitive():
    dns = [mk_dns("10.0.0.1", f"q{i}.invalid", rcode_name="nxdomain") for i in range(6)]
    assert detect_dns_anomaly(ctx(dns=dns))


def test_dns_query_diversity_positive():
    dns = [mk_dns("10.0.0.1", f"host{i}.example.com") for i in range(60)]
    findings = detect_dns_query_diversity(ctx(dns=dns))
    assert len(findings) == 1
    assert findings[0].rule_id == "dns_query_diversity"


def test_dns_query_diversity_negative():
    dns = [mk_dns("10.0.0.1", "same.example.com") for _ in range(60)]
    assert detect_dns_query_diversity(ctx(dns=dns)) == []


# ------------------------------------------------------------- data transfer


def test_high_data_transfer_positive():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=443, bytes_total=12_000_000)]
    findings = detect_high_data_transfer(ctx(conns))
    assert len(findings) == 1
    assert findings[0].rule_id == "high_data_transfer"


def test_high_data_transfer_negative():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=80, bytes_total=1000)]
    assert detect_high_data_transfer(ctx(conns)) == []


# ------------------------------------------------------------- all rules


def test_run_all_rules_aggregates():
    conns = [mk_conn("10.0.0.1", "10.0.0.2", dport=p, first_ts=100.0 + 0.001 * p) for p in range(15)]
    dns = [mk_dns("10.0.0.1", f"q{i}.invalid", rcode_name="NXDOMAIN") for i in range(7)]
    findings = run_all_rules(ctx(connections=conns, dns=dns))
    ids = {f.rule_id for f in findings}
    assert "port_scan" in ids
    assert "dns_anomaly" in ids


# ------------------------------------------------------------- service/db/API


@pytest.fixture()
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture()
def seeded_capture(db_session):
    cap = Capture(name="detect-test", source="upload", status="done")
    db_session.add(cap)
    db_session.commit()
    db_session.refresh(cap)
    # Seed normalized connections + dns to trigger rules.
    for p in range(12):
        db_session.add(Connection(
            capture_id=cap.id, conn_key=f"tcp|10.0.0.1|10.0.0.2|1|{p}",
            src="10.0.0.1", dst="10.0.0.2", proto="tcp", sport=1, dport=p,
            first_ts=100.0 + p, source="tshark",
        ))
    for i in range(7):
        db_session.add(DnsEvent(
            capture_id=cap.id, src="10.0.0.1", dst="8.8.8.8",
            query=f"q{i}.invalid", rcode_name="NXDOMAIN", source="tshark",
        ))
    db_session.commit()
    return cap.id


def test_detection_rules_endpoint(client):
    resp = client.get("/api/v1/detect/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 3
    assert any(r["id"] == "port_scan" for r in rules)


def test_run_detection_persists_findings(seeded_capture, db_session):
    result = detect_svc.run_detection(db_session, seeded_capture)
    assert result.findings >= 2  # port_scan + dns_anomaly
    assert result.rules_evaluated >= 3
    # Re-run is idempotent (clears then recomputes, same count).
    result2 = detect_svc.run_detection(db_session, seeded_capture)
    assert result2.findings == result.findings
    total = db_session.query(FindingRow).filter(FindingRow.capture_id == seeded_capture).count()
    assert total == result.findings


def test_detection_summary(seeded_capture, db_session):
    detect_svc.run_detection(db_session, seeded_capture)
    summary = detect_svc.summary_for_capture(db_session, seeded_capture)
    assert summary.total >= 2
    assert summary.by_severity["medium"] >= 2


def test_findings_have_evidence(seeded_capture, db_session):
    detect_svc.run_detection(db_session, seeded_capture)
    findings = detect_svc.findings_for_capture(db_session, seeded_capture)
    assert findings
    port_scan = next(f for f in findings if f["rule_id"] == "port_scan")
    assert port_scan["evidence"]
    assert port_scan["evidence"][0]["type"] == "connection"
    assert port_scan["detail"]


def test_run_detection_missing_capture(client):
    resp = client.post("/api/v1/detect/run", params={"capture_id": "nope"})
    assert resp.status_code == 404


def test_findings_endpoint_bad_capture(client):
    assert client.get("/api/v1/detect/findings", params={"capture_id": "nope"}).status_code == 404
