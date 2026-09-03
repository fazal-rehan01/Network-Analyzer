"""DNS traffic simulation — queries against a controlled resolver/domain."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class DnsTraffic(Scenario):
    key = "dns"
    name = "DNS Traffic"
    description = "A set of DNS queries for controlled example domains against a resolver."
    default_port = 53

    def default_config(self) -> dict:
        return {
            "packet_count": 100,
            "duration_sec": 8,
            "interval_ms": 50,
            "qtype": "A",
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        count = int(cfg.get("packet_count", 100))
        interval = float(cfg.get("interval_ms", 50)) / 1000.0
        qtype = cfg.get("qtype", "A")
        for i in range(count):
            ctx.check_stop()
            _net.send_dns_query(ctx, f"query{i}.example.test", qtype)
            _net.sleep_or_stop(ctx, interval)
