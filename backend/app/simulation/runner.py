"""SimulationRunner — manages scenario lifecycle in a background thread."""
from __future__ import annotations

import ipaddress
import threading
import time

from sqlalchemy import select
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

    # Graceful shutdown timeout in seconds
    GRACEFUL_SHUTDOWN_TIMEOUT = 10.0

    def __init__(self, simulation_id: str) -> None:
        self.simulation_id = simulation_id
        self._thread: threading.Thread | None = None
        self._ctx: ScenarioContext | None = None
        self._flush_thread: threading.Thread | None = None
        self._flush_stop_event = threading.Event()
        self._stop_requested = threading.Event()
        self._finished = threading.Event()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.running:
            raise RuntimeError("Simulation already running")
        self._thread = threading.Thread(target=self._worker, daemon=True, name=f"sim-{self.simulation_id}")
        self._thread.start()

    def stop(self) -> bool:
        """Request graceful stop. Returns True if stop was requested, False if already stopped/finished."""
        if self._stop_requested.is_set():
            return True  # Idempotent: already stopping/stopped
        if not self.running and self._finished.is_set():
            return False  # Already finished, nothing to stop
        self._stop_requested.set()
        if self._ctx:
            self._ctx.request_stop()
        return True

    def wait_for_stop(self, timeout: float | None = None) -> bool:
        """Wait for the simulation to finish stopping. Returns True if stopped, False if timeout."""
        return self._finished.wait(timeout=timeout)

    def _mark(self, sim: Simulation, status: str) -> None:
        sim.status = status
        if status in ("running",) and sim.start_time is None:
            sim.start_time = utcnow()
        if status in ("completed", "stopped", "failed"):
            sim.end_time = utcnow()
            if sim.start_time:
                sim.duration_sec = (sim.end_time - sim.start_time).total_seconds()

    def _start_flush(self) -> None:
        self._flush_stop_event.clear()
        self._flush_thread = threading.Thread(
            target=self._flush_worker, daemon=True, name=f"sim-flush-{self.simulation_id}"
        )
        self._flush_thread.start()

    def _stop_flush(self) -> None:
        self._flush_stop_event.set()
        if self._flush_thread is not None:
            self._flush_thread.join(timeout=3)
            self._flush_thread = None

    def _flush_worker(self) -> None:
        """Persist live counters to the DB while the scenario is running."""
        while not self._flush_stop_event.is_set():
            ctx = self._ctx
            if ctx is None:
                return
            db = SessionLocal()
            try:
                sim = db.get(Simulation, self.simulation_id)
                if sim is None or sim.status != "running":
                    return
                if elapsed := (time.monotonic() - ctx.started_at):
                    sim.packets_sent = ctx.packets_sent
                    sim.bytes_sent = ctx.bytes_sent
                    sim.connections = ctx.connections
                    sim.rates_per_sec = int(ctx.packets_sent / elapsed)
                    db.commit()
            except Exception:  # noqa: BLE001
                db.rollback()
            finally:
                db.close()
            time.sleep(1)

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

            self._start_flush()
            started = time.monotonic()
            try:
                scenario.run(self._ctx)
            finally:
                self._stop_flush()
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
            if sim and self._ctx:
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
            self._finished.set()
            # Remove runner from active registry
            with _runner_lock:
                _active.pop(self.simulation_id, None)
            db.close()


_runner_lock = threading.Lock()
_active: dict[str, SimulationRunner] = {}


def reconcile_stale_simulations() -> int:
    """
    Reconcile stale simulation records on application startup.
    
    Finds simulations with status 'running' or 'stopping' that have no active runner
    (indicating the process died or was restarted while they were running).
    Marks them as 'failed' with a clear error message, preserving all historical data.
    
    Returns the number of simulations reconciled.
    """
    from app.core.database import SessionLocal
    from app.models.simulation import Simulation
    from app.utils.timeutil import utcnow
    
    with _runner_lock:
        active_ids = set(_active.keys())
    
    db = SessionLocal()
    try:
        # Find simulations that appear to be running/stopping but have no active runner
        stale_sims = db.execute(
            select(Simulation).where(
                Simulation.status.in_(("running", "stopping"))
            )
        ).scalars().all()
        
        reconciled = 0
        for sim in stale_sims:
            if sim.id in active_ids:
                # Has an active runner - skip (legitimately running/stopping)
                continue
            
            # This is a stale record - reconcile it
            if sim.end_time is None:
                sim.end_time = utcnow()
            if sim.start_time and sim.duration_sec is None:
                sim.duration_sec = (sim.end_time - sim.start_time).total_seconds()
            
            # Preserve existing stats/packets/bytes/connections
            # Mark as failed with clear recovery message
            sim.status = "failed"
            sim.result = "Recovered stale stopping/running state after application restart"
            sim.error = "Simulation worker process was not found on startup; likely the application was restarted while this simulation was running/stopping. Historical packet/byte/connection data has been preserved."
            
            reconciled += 1
        
        if reconciled > 0:
            db.commit()
        
        return reconciled
    finally:
        db.close()


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
        # Check if simulation exists and is in a terminal state
        db = SessionLocal()
        try:
            sim = db.get(Simulation, simulation_id)
            if sim and sim.status in ("completed", "stopped", "failed"):
                return False  # Already in terminal state
        finally:
            db.close()
        return False
    runner.stop()
    # Wait for graceful shutdown with timeout
    runner.wait_for_stop(timeout=SimulationRunner.GRACEFUL_SHUTDOWN_TIMEOUT)
    return True