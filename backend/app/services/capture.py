"""Live packet capture and PCAP analysis driven by TShark.

Graceful degradation: every function degrades cleanly if TShark is unavailable.
Capture processes run in a background daemon thread so a long capture never blocks
a request, and an optional duration auto-finalizes the capture.
"""
from __future__ import annotations

import re
import subprocess
import threading
import time
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.capture import Capture
from app.schemas.capture import CaptureStats, InterfaceInfo, ProtocolStat
from app.utils.timeutil import utcnow
from app.utils.tools import detect_tshark

_PHS_RE = re.compile(r"^(\S+)\s+frames:(\d+)\s+bytes:(\d+)")
_TIME_RE = re.compile(r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|")
_STAT_RE = re.compile(r"<>\s*[0-9.]+\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|")


def get_tshark_path() -> str | None:
    status = detect_tshark()
    if not status.installed or not status.path:
        return None
    settings = get_settings()
    path = Path(status.path)
    if not path.is_absolute():
        return status.path
    return str(path)


def _run_tshark(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    exe = get_tshark_path()
    if exe is None:
        raise RuntimeError("TShark is not installed")
    return subprocess.run(
        [exe, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def list_interfaces() -> list[InterfaceInfo]:
    """Return capture interfaces detected via `tshark -D`."""
    if get_tshark_path() is None:
        return []
    try:
        proc = _run_tshark("-D", timeout=20)
    except Exception:  # noqa: BLE001
        return []
    out = (proc.stdout or "") + (proc.stderr or "")
    interfaces: list[InterfaceInfo] = []
    for line in out.splitlines():
        line = line.strip()
        m = re.match(r"^(\d+)\.\s+(.+)$", line)
        if not m:
            continue
        index, rest = int(m.group(1)), m.group(2).strip()
        desc = None
        name = rest
        if " (" in rest and rest.endswith(")"):
            name, _, d = rest.rpartition(" (")
            desc = d[:-1]
            name = name.strip()
        loopback = "loopback" in (name + (desc or "")).lower()
        interfaces.append(
            InterfaceInfo(index=index, name=name, description=desc, loopback=loopback)
        )
    return interfaces


def _capture_dir() -> Path:
    return get_settings().pcap_dir_abs


# Active live captures: capture_id -> Popen
_active: dict[str, subprocess.Popen] = {}
_active_lock = threading.Lock()


def _finalize_capture(capture_id: str) -> None:
    """Compute stats for a finished capture file and persist them."""
    db = SessionLocal()
    try:
        cap = db.get(Capture, capture_id)
        if cap is None or cap.status != "running":
            return
        path = Path(cap.file_path) if cap.file_path else None
        cap.end_time = utcnow()
        if cap.start_time:
            cap.duration_sec = (cap.end_time - cap.start_time).total_seconds()
        if path and path.exists():
            frames, total_bytes = _tshark_status(path)
            cap.packet_count = frames
            cap.byte_count = total_bytes
        cap.status = "done"
        cap.error = None
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        cap = db.get(Capture, capture_id)
        if cap:
            cap.status = "error"
            cap.error = f"{type(exc).__name__}: {exc}"
            db.commit()
    finally:
        db.close()


def start_live_capture(
    db: Session,
    name: str,
    interface_index: int,
    *,
    filter_expr: str | None = None,
    duration_sec: int | None = None,
) -> Capture:
    exe = get_tshark_path()
    if exe is None:
        raise RuntimeError("TShark is not installed")

    _capture_dir().mkdir(parents=True, exist_ok=True)
    now = time.strftime("%Y%m%d-%H%M%S")
    filename = f"live-{now}-{interface_index}.pcapng"
    path = _capture_dir() / filename

    cap = Capture(
        name=name or f"Live capture on interface {interface_index}",
        source="live",
        filename=filename,
        file_path=str(path),
        interface=str(interface_index),
        filter_expr=filter_expr,
        start_time=utcnow(),
        status="running",
    )
    db.add(cap)
    db.commit()
    db.refresh(cap)

    cmd = [exe, "-i", str(interface_index)]
    if filter_expr:
        cmd += ["-f", filter_expr]
    cmd += ["-w", str(path)]

    devnull = open(__import__("os").devnull, "w")  # noqa: SIM115
    proc = subprocess.Popen(cmd, stdout=devnull, stderr=subprocess.PIPE)
    with _active_lock:
        _active[cap.id] = proc

    if duration_sec:
        threading.Thread(
            target=_auto_stop, args=(cap.id, duration_sec), daemon=True
        ).start()
    else:
        # Watch for early termination (e.g. invalid interface) and finalize.
        threading.Thread(target=_watch, args=(cap.id, proc), daemon=True).start()
    return cap


def _auto_stop(capture_id: str, duration_sec: int) -> None:
    time.sleep(max(1, duration_sec))
    stop_live_capture(capture_id)


def _watch(capture_id: str, proc: subprocess.Popen) -> None:
    proc.wait()
    time.sleep(0.5)
    with _active_lock:
        _active.pop(capture_id, None)
    _finalize_capture(capture_id)


def stop_live_capture(capture_id: str) -> bool:
    with _active_lock:
        proc = _active.get(capture_id)
        if proc is None:
            return False
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    with _active_lock:
        _active.pop(capture_id, None)
    _finalize_capture(capture_id)
    return True


def _tshark_status(path: Path) -> tuple[int, int]:
    """Return (frame_count, byte_count) from `tshark -q -z io,stat,0`."""
    try:
        proc = _run_tshark("-r", str(path), "-q", "-z", "io,stat,0")
    except Exception:  # noqa: BLE001
        return 0, 0
    text = (proc.stdout or "") + (proc.stderr or "")
    last = None
    for line in text.splitlines():
        m = _STAT_RE.search(line)
        if m:
            last = (int(m.group(1)), int(m.group(2)))
    return last if last else (0, 0)


def analyze_pcap(path: Path) -> CaptureStats:
    """Produce protocol hierarchy, per-second series, and top talkers."""
    stats = CaptureStats()
    if not path.exists():
        return stats

    stats.protocols = _protocol_hierarchy(path)

    status = _tshark_status(path)
    stats.packet_count = status[0]
    stats.byte_count = status[1]

    stats.time_series = _time_series(path)
    stats.top_talkers = _top_talkers(path)
    return stats


def get_capture_stats(cap: Capture) -> CaptureStats:
    """Return computed stats for a finished capture, or empty if not available."""
    if not cap.file_path:
        return CaptureStats(packet_count=cap.packet_count, byte_count=cap.byte_count)
    return analyze_pcap(Path(cap.file_path))


def _protocol_hierarchy(path: Path) -> list[ProtocolStat]:
    try:
        proc = _run_tshark("-r", str(path), "-q", "-z", "io,phs")
    except Exception:  # noqa: BLE001
        return []
    result: list[ProtocolStat] = []
    seen: set[str] = set()
    for line in (proc.stdout or "").splitlines():
        m = _PHS_RE.search(line.strip())
        if not m:
            continue
        proto = m.group(1)
        frames = int(m.group(2))
        total_bytes = int(m.group(3))
        if proto in seen:
            continue
        seen.add(proto)
        result.append(ProtocolStat(protocol=proto, frames=frames, bytes=total_bytes))
    return result


def _time_series(path: Path) -> list[dict]:
    try:
        proc = _run_tshark("-r", str(path), "-q", "-z", "io,stat,1")
    except Exception:  # noqa: BLE001
        return []
    series: list[dict] = []
    for line in (proc.stdout or "").splitlines():
        m = _TIME_RE.search(line)
        if m:
            series.append({"t": int(m.group(1)), "frames": int(m.group(2)), "bytes": int(m.group(3))})
    return series


def _top_talkers(path: Path, limit: int = 10) -> list[dict]:
    """Aggregate src/dst (and bytes) from packet fields in Python."""
    try:
        proc = _run_tshark(
            "-r", str(path),
            "-T", "fields",
            "-e", "frame.len",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-E", "occurrence=a",
        )
    except Exception:  # noqa: BLE001
        return []
    totals: dict[str, dict] = {}
    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        try:
            size = int(parts[0])
        except ValueError:
            continue
        src, dst = parts[1], parts[2]
        for addr in (src, dst):
            if not addr:
                continue
            entry = totals.setdefault(addr, {"address": addr, "packets": 0, "bytes": 0})
            entry["packets"] += 1
            entry["bytes"] += size
    ordered = sorted(totals.values(), key=lambda e: e["bytes"], reverse=True)[:limit]
    return ordered
