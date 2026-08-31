"""SimulationRunner — manages scenario lifecycle in a background thread."""
from __future__ import annotations

import ipaddress
import threading
import time

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.simulation import Simulation
from app.simulation.base import ScenarioContext, SimulationCancelled
from app.simulation.registry import registry
from app.utils.timeutil import utcnow

# IPs / ranges that are always allowable as simulation targets.
_PRIVATE_HOSTS = ("127.0.0.1", "127.0.0.2", "localhost", "::1")


def is_safe_target(target: str) -> bool:
    """Return True if the target is a lab/private host we allow to hit."""
    if target in _PRIVATE_HOSTS:
        return True
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        # Hostnames other than localhost are not allowed by default.
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


class SimulationRunner:
    """Runs one simulation scenario in a background thread with lifecycle tracking."""

    def __init__(self, simulation_id: str) -> None:
        self.simulation_id = simulation_id
        self._thread: threading.Thread | None = None
        self._ctx: ScenarioContext | None = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            raise RuntimeError("Simulation already running")
        self._thread = threading.Thread(target=self._worker, daemon=True, name=f"sim-{self.simulation_id}")
        self._thread.start()

    def stop(self) -> None:
        if self._ctx:
            self._ctx.request_stop()

    def _mark(self, sim: Simulation, status: str) -> None:
        sim.status = status
        if status in ("running",) and sim.start_time is None:
            sim.start_time = utcnow()
        if status in ("completed", "stopped", "failed"):
            sim.end_time = utcnow()
            if sim.start_time:
                sim.duration_sec = (sim.end_time - sim.start_time).total_seconds()

    def _worker(self) -> None:
        db = SessionLocal()
        try:
            sim = db.get(Simulation, self.simulation_id)
            if sim is None:
                return
            scenario_cls = registry.get(sim.scenario)
            if scenario_cls is None:
                sim.status = "failed"
                sim.error = f"Unknown scenario: {sim.scenario}"
                db.commit()
                return
            if not is_safe_target(sim.target):
                sim.status = "failed"
                sim.error = f"Refusing to target non-lab host: {sim.target}"
                db.commit()
                return

            self._ctx = ScenarioContext(
                target=sim.target,
                target_port=sim.target_port,
                config=sim.get_config(),
                duration_sec=int(sim.get_config().get("duration_sec", 0)) or None,
            )
            scenario = scenario_cls()
            self._mark(sim, "running")
            db.commit()

            started = time.monotonic()
            scenario.run(self._ctx)
            elapsed = time.monotonic() - started

            sim.packets_sent = self._ctx.packets_sent
            sim.bytes_sent = self._ctx.bytes_sent
            sim.connections = self._ctx.connections
            if elapsed > 0:
                sim.rates_per_sec = int(self._ctx.packets_sent / elapsed)
            sim.set_stats(
                {
                    "elapsed_sec": round(elapsed, 3),
                    "packets_sent": self._ctx.packets_sent,
                    "bytes_sent": self._ctx.bytes_sent,
                    "connections": self._ctx.connections,
                    "rates_per_sec": sim.rates_per_sec,
                }
            )
            sim.result = "Completed successfully"
            self._mark(sim, "completed")
            db.commit()
        except SimulationCancelled:
            db.rollback()
            sim = db.get(Simulation, self.simulation_id)
            if sim:
                sim.result = "Stopped by user"
                self._mark(sim, "stopped")
                db.commit()
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            sim = db.get(Simulation, self.simulation_id)
            if sim:
                sim.result = "Failed"
                sim.error = f"{type(exc).__name__}: {exc}"
                self._mark(sim, "failed")
                db.commit()
        finally:
            self._ctx = None
            db.close()


_runner_lock = threading.Lock()
_active: dict[str, SimulationRunner] = {}


def start_simulation(db: Session, simulation_id: str) -> SimulationRunner:
    runner = SimulationRunner(simulation_id)
    with _runner_lock:
        _active[simulation_id] = runner
    runner.start()
    return runner


def stop_simulation(simulation_id: str) -> bool:
    with _runner_lock:
        runner = _active.get(simulation_id)
    if runner is None:
        return False
    runner.stop()
    return True
