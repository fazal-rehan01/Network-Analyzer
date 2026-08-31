"""Simulation package.

Scenario modules are imported eagerly here so they register with the registry.
This must come AFTER the registry import to avoid circular imports.
"""
from __future__ import annotations

from app.simulation.registry import ScenarioRegistry, registry, register

__all__ = ["registry", "ScenarioRegistry", "register"]


def load_scenarios() -> None:
    """Import every scenario module so it registers with the global registry.

    Grouped separately to avoid circular import ordering issues.
    """
    from app.simulation import connection_burst, data_transfer, dns, dns_anomaly  # noqa: F401
    from app.simulation import http, icmp, normal, port_scan  # noqa: F401


load_scenarios()
