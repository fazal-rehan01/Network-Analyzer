"""Port scan simulation — controlled scan against a lab target."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class PortScan(Scenario):
    key = "port_scan"
    name = "Port Scan Simulation"
    description = "Controlled TCP connect scan across a range of ports on a lab target."
    default_port = 22
    suspicious = True

    def default_config(self) -> dict:
        return {
            "port_start": 1,
            "port_end": 1024,
            "step": 1,
            "delay_ms": 5,
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        start = int(cfg.get("port_start", 1))
        end = int(cfg.get("port_end", 1024))
        step = int(cfg.get("step", 1))
        delay = float(cfg.get("delay_ms", 5)) / 1000.0

        # Keep the tenant on lab targets; each probe is a real TCP connect.
        for port in range(start, end + 1, step):
            ctx.check_stop()
            _net.tcp_handshake(ctx, port, 1)
            _net.sleep_or_stop(ctx, delay)
