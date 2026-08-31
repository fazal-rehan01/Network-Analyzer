"""DNS anomaly simulation — high query rate and NXDOMAIN-generating queries."""
from __future__ import annotations

from app.simulation import _net
from app.simulation.base import Scenario, ScenarioContext
from app.simulation.registry import register


@register
class DnsAnomaly(Scenario):
    key = "dns_anomaly"
    name = "DNS Anomaly"
    description = "Abnormally high DNS query rate with many unique / likely-NXDOMAIN domains."
    default_port = 53
    suspicious = True

    def default_config(self) -> dict:
        return {
            "query_count": 400,
            "duration_sec": 6,
            "rate_per_sec": 80,
            "nxdomain_ratio": 0.5,
        }

    def run(self, ctx: ScenarioContext) -> None:
        cfg = ctx.config
        count = int(cfg.get("query_count", 400))
        nx_ratio = float(cfg.get("nxdomain_ratio", 0.5))
        for i in range(count):
            ctx.check_stop()
            # Alternate between many unique likely-bogus domains and repeat queries.
            if i % 2 == 0:
                domain = f"nonexistent{i}.invalid.example"
            else:
                domain = f"rand{i}.dynamic.example"
            _net.send_dns_query(ctx, domain)
            _net.sleep_or_stop(ctx, 1.0 / max(1, int(cfg.get("rate_per_sec", 80))))
