"""Connection burst simulation — abnormally high connection rate to a lab port."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class ConnectionBurst(Scenario):
    key = "connection_burst"
    name = "High Connection Rate"
    description = "A burst of TCP connections to a lab service to trigger connection-rate detection."
    default_port = 8080
    suspicious = True

    def default_config(self) -> dict:
        return {
            "connection_count": 500,
            "port": 8080,
            "delay_ms": 1,
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        count = int(cfg.get("connection_count", 500))
        port = int(cfg.get("port", 8080))
        delay = float(cfg.get("delay_ms", 1)) / 1000.0
        for _ in range(count):
            ctx.check_stop()
            _net.tcp_handshake(ctx, port, 1)
            _net.sleep_or_stop(ctx, delay)
