"""Scenario registry — maps scenario keys to Scenario classes."""
from __future__ import annotations

from app.simulation.base import Scenario


class ScenarioRegistry:
    def __init__(self) -> None:
        self._scenarios: dict[str, type[Scenario]] = {}

    def register(self, cls: type[Scenario]) -> None:
        self._scenarios[cls.key] = cls

    def get(self, key: str) -> type[Scenario] | None:
        return self._scenarios.get(key)

    def names(self) -> list[str]:
        return list(self._scenarios.keys())

    def list(self) -> list[dict]:
        out = []
        for key, cls in self._scenarios.items():
            out.append(
                {
                    "key": key,
                    "name": cls.name,
                    "description": cls.description,
                    "default_port": cls.default_port,
                    "suspicious": cls.suspicious,
                    "default_config": cls().default_config(),
                }
            )
        return out


registry = ScenarioRegistry()


def register(cls: type[Scenario]) -> type[Scenario]:
    """Decorator to register a scenario class with the global registry."""
    registry.register(cls)
    return cls
