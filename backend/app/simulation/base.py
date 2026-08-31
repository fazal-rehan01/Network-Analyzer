"""Simulation scenario abstraction.

A scenario generates *real* controlled traffic against a lab target. Scenarios
run inside the SimulationRunner, which manages lifecycle, cancellation, timing,
and progress reporting.

Safety: commands NEVER target arbitrary public systems. The target is validated
by the runner against approved lab targets (localhost, private ranges, Docker).
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class SimulationCancelled(Exception):
    """Raised by scenarios to signal they were asked to stop."""


@dataclass
class ScenarioContext:
    """Everything a scenario needs to generate traffic and report progress."""

    target: str
    target_port: int | None
    config: dict
    duration_sec: int | None
    # Monotonic clock timestamp marking when the run began (for live rates).
    started_at: float = field(default_factory=time.monotonic)
    # progress reporting + cancellation
    _stop_event: threading.Event = field(default_factory=threading.Event)

    # Runtime tallies gathered by the runner.
    packets_sent: int = 0
    bytes_sent: int = 0
    connections: int = 0

    def should_stop(self) -> bool:
        return self._stop_event.is_set()

    def request_stop(self) -> None:
        self._stop_event.set()

    def check_stop(self) -> None:
        if self.should_stop():
            raise SimulationCancelled()


class Scenario(ABC):
    """Base class for a simulation scenario."""

    key: str = "base"
    name: str = "Base"
    description: str = ""
    # Default target port for the scenario, if any.
    default_port: int | None = None
    # Hint to the UI: is this a "suspicious/anomaly" scenario?
    suspicious: bool = False

    @abstractmethod
    def run(self, ctx: ScenarioContext) -> None:
        """Generate traffic. Raise SimulationCancelled to stop cleanly."""

    def default_config(self) -> dict:
        return {}
