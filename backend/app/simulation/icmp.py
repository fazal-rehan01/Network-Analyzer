"""ICMP traffic simulation — pings against the lab target."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class IcmpTraffic(Scenario):
    key = "icmp"
    name = "ICMP Traffic"
    description = "Continuous ICMP echo requests (pings) to a lab target."
    default_port = None

    def default_config(self) -> dict:
        return {
            "packet_count": 100,
            "duration_sec": 5,
            "interval_ms": 50,
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        count = int(cfg.get("packet_count", 100))
        interval = float(cfg.get("interval_ms", 50)) / 1000.0
        for _ in range(count):
            ctx.check_stop()
            _net.send_icmp_packet(ctx, 1)
            _net.sleep_or_stop(ctx, interval)
