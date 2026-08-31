"""Normal traffic — a realistic mix of TCP, UDP, and ICMP against the lab target."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class NormalTraffic(Scenario):
    key = "normal"
    name = "Normal Traffic"
    description = "A balanced mix of TCP handshakes, DNS queries, and ICMP pings to a lab target."
    default_port = 80

    def default_config(self) -> dict:
        return {
            "packet_count": 200,
            "duration_sec": 10,
            "tcp_ratio": 0.5,
            "dns_ratio": 0.3,
            "icmp_ratio": 0.2,
            "tcp_port": 80,
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        total = int(cfg.get("packet_count", 200))
        tcp_port = int(cfg.get("tcp_port", 80))
        dns_conns = int(total * float(cfg.get("dns_ratio", 0.3)))
        icmp_count = int(total * float(cfg.get("icmp_ratio", 0.2)))
        tcp_conns = max(0, total - dns_conns - icmp_count)

        dns_ids = range(1, dns_conns + 1)
        domains = [f"host{i}.example.test" for i in dns_ids]

        for i in range(max(dns_conns, icmp_count, tcp_conns)):
            ctx.check_stop()
            if i < dns_conns:
                _net.send_dns_query(ctx, domains[i])
            if i < icmp_count:
                _net.send_icmp_packet(ctx, 1)
            if i < tcp_conns:
                _net.tcp_handshake(ctx, tcp_port, 1)
            _net.sleep_or_stop(ctx, 0.01)
