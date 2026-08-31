"""HTTP traffic simulation — real HTTP requests against a local test server."""
from __future__ import annotations

import time

from app.simulation import _net
from app.simulation._localserver import LocalHttpServer
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class HttpTraffic(Scenario):
    key = "http"
    name = "HTTP Traffic"
    description = "Real HTTP GET/POST requests against a local test server on localhost."
    default_port = 8080

    def default_config(self) -> dict:
        return {
            "request_count": 150,
            "duration_sec": 10,
            "port": 8080,
            "interval_ms": 50,
        }

    def run(self, ctx: ScenarioContext) -> None:
        import requests

        cfg = ctx.config
        count = int(cfg.get("request_count", 150))
        port = int(cfg.get("port", 8080))
        interval = float(cfg.get("interval_ms", 50)) / 1000.0

        server = LocalHttpServer(port)
        server.start()
        try:
            for i in range(count):
                ctx.check_stop()
                method = "POST" if i % 3 == 0 else "GET"
                try:
                    if method == "GET":
                        requests.get(f"http://127.0.0.1:{port}/", timeout=1)
                    else:
                        requests.post(f"http://127.0.0.1:{port}/", data=b"payload", timeout=1)
                    ctx.packets_sent += 2  # request + response
                    ctx.bytes_sent += 350
                    ctx.connections += 1
                except Exception:  # noqa: BLE001
                    pass
                _net.sleep_or_stop(ctx, interval)
        finally:
            server.stop()
