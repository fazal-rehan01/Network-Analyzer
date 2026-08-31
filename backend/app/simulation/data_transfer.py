"""Large data transfer simulation — bulk TCP data to a local test server."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class DataTransfer(Scenario):
    key = "data_transfer"
    name = "Large Data Transfer"
    description = "Sends a large payload over TCP to a local test server to create steady traffic volume."
    default_port = 9000
    suspicious = False

    def default_config(self) -> dict:
        return {
            "mega_bytes": 5,
            "duration_sec": 10,
            "port": 9000,
            "chunk_size": 65536,
        }

    def run(self, ctx: ScenarioContext) -> None:
        import socket

        cfg = ctx.config
        port = int(cfg.get("port", 9000))
        chunk = int(cfg.get("chunk_size", 65536))
        total = int(float(cfg.get("mega_bytes", 5)) * 1024 * 1024)
        payload = b"x" * chunk
        sent_total = 0
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            try:
                while sent_total < total:
                    ctx.check_stop()
                    sent = sock.send(payload[: min(chunk, total - sent_total)])
                    sent_total += sent
                    ctx.bytes_sent += sent
                    ctx.packets_sent += 1
            finally:
                sock.close()
            ctx.connections += 1
        except (OSError, ConnectionError):
            return
