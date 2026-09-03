"""Simulation management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.simulation import Simulation
from app.schemas.simulation import ScenarioInfo, SimulationCreate, SimulationRead
from app.simulation.registry import registry
from app.simulation.runner import is_safe_target, start_simulation, stop_simulation

router = APIRouter(prefix="/simulations", tags=["simulations"])


def _to_read(sim: Simulation) -> SimulationRead:
    return SimulationRead(
        id=sim.id,
        scenario=sim.scenario,
        name=sim.name,
        description=sim.description,
        target=sim.target,
        target_port=sim.target_port,
        status=sim.status,
        start_time=sim.start_time,
        end_time=sim.end_time,
        duration_sec=sim.duration_sec,
        packets_sent=sim.packets_sent,
        bytes_sent=sim.bytes_sent,
        connections=sim.connections,
        rates_per_sec=sim.rates_per_sec,
        config=sim.get_config(),
        stats=sim.get_stats(),
        result=sim.result,
        error=sim.error,
        created_at=sim.created_at,
    )


@router.get("/scenarios", response_model=list[ScenarioInfo])
def list_scenarios() -> list[ScenarioInfo]:
    """List all available simulation scenarios with their metadata."""
    return [ScenarioInfo(**s) for s in registry.list()]


@router.get("", response_model=list[SimulationRead])
def list_simulations(db: Session = Depends(get_db)) -> list[SimulationRead]:
    rows = db.execute(
        select(Simulation).order_by(Simulation.created_at.desc()).limit(100)
    ).scalars().all()
    return [_to_read(s) for s in rows]


@router.get("/{simulation_id}", response_model=SimulationRead)
def get_simulation(simulation_id: str, db: Session = Depends(get_db)) -> SimulationRead:
    sim = db.get(Simulation, simulation_id)
    if sim is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    return _to_read(sim)


@router.post("", response_model=SimulationRead, status_code=201)
def create_simulation(payload: SimulationCreate, db: Session = Depends(get_db)) -> SimulationRead:
    scenario_cls = registry.get(payload.scenario)
    if scenario_cls is None:
        raise HTTPException(status_code=400, detail=f"Unknown scenario: {payload.scenario}")
    if not is_safe_target(payload.target):
        raise HTTPException(
            status_code=400,
            detail=f"Refusing to target non-lab host: {payload.target}",
        )

    sim = Simulation(
        scenario=payload.scenario,
        name=payload.name or scenario_cls.name,
        description=scenario_cls.description,
        target=payload.target,
        target_port=payload.target_port or scenario_cls.default_port,
        status="idle",
    )
    sim.set_config(payload.config or scenario_cls().default_config())
    db.add(sim)
    db.commit()
    db.refresh(sim)
    return _to_read(sim)


@router.post("/{simulation_id}/start", response_model=SimulationRead)
def start_simulation_run(simulation_id: str, db: Session = Depends(get_db)) -> SimulationRead:
    sim = db.get(Simulation, simulation_id)
    if sim is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    if sim.status == "running":
        raise HTTPException(status_code=409, detail="Simulation already running")
    sim.status = "queued"
    sim.error = None
    sim.result = None
    db.commit()
    start_simulation(db, simulation_id)
    db.refresh(sim)
    return _to_read(sim)


@router.post("/{simulation_id}/stop", response_model=SimulationRead)
def stop_simulation_run(simulation_id: str, db: Session = Depends(get_db)) -> SimulationRead:
    sim = db.get(Simulation, simulation_id)
    if sim is None:
        raise HTTPException(status_code=404, detail="Simulation not found")
    if sim.status != "running":
        # Idempotent: if already stopped/completed/failed, return current state
        return _to_read(sim)
    # Set stopping status FIRST, then signal the worker
    sim.status = "stopping"
    db.commit()
    stop_simulation(simulation_id)
    db.refresh(sim)
    return _to_read(sim)
