"""Zeek integration: subprocess driver and defensive log parsers.

Zeek is an optional component. Every function here degrades cleanly when the
Zeek binary is missing or when a particular log type was not produced, so the
rest of the application keeps working.

Zeek writes logs in a tab-separated format. Each file starts with meta lines
(``#separator``, ``#set_separator``, ``#fields``, ``#types``) followed by data
rows. Parsers read those headers and turn rows into dicts keyed by field name.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings
from app.utils.tools import detect_zeek

# Standard Zeek log types this module understands.
LOG_TYPES = ["conn", "dns", "http", "ssl", "notice"]
LOG_FILENAMES = {t: f"{t}.log" for t in LOG_TYPES}


@dataclass
class ZeekLogFile:
    """Describes a single parsed Zeek log (or its absence)."""

    log_type: str
    filename: str
    path: Path
    present: bool
    rows: int

    def to_dict(self) -> dict:
        return {
            "log_type": self.log_type,
            "filename": self.filename,
            "path": str(self.path),
            "present": self.present,
            "rows": self.rows,
        }


def get_zeek_path() -> str | None:
    """Return the configured or auto-detected Zeek binary path, or None."""
    status = detect_zeek()
    if not status.installed or not status.path:
        return None
    return status.path


def zeek_available() -> bool:
    return get_zeek_path() is not None


def run_zeek(pcap: Path, workdir: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run Zeek over a PCAP file, writing its logs into ``workdir``.

    Raises RuntimeError if Zeek is not installed. Returns the CompletedProcess
    so callers can inspect returncode / stderr for graceful handling.
    """
    exe = get_zeek_path()
    if exe is None:
        raise RuntimeError("Zeek is not installed")
    workdir.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [exe, "-r", str(pcap)],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(workdir),
    )


def parse_zeek_tsv(path: Path) -> list[dict]:
    """Parse a Zeek TSV log file into a list of row dicts.

    Returns an empty list for missing or unparseable files. NaN/blank values
    are kept as-is (strings) so callers can choose how to coerce them.
    """
    if not path.exists():
        return []
    rows: list[dict] = []
    fields: list[str] | None = None
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#"):
                    if line.startswith("#fields"):
                        fields = line.rstrip("\n").split("\t")[1:]
                    continue
                if fields is None:
                    continue
                values = line.rstrip("\n").split("\t")
                # Trailing blank fields are common; pad with empty strings.
                if len(values) < len(fields):
                    values.extend([""] * (len(fields) - len(values)))
                rows.append({name: values[i] for i, name in enumerate(fields)})
    except OSError:
        return []
    return rows


def _list_log_files(workdir: Path) -> dict[str, ZeekLogFile]:
    """Enumerate known Zeek log files in a processing directory."""
    result: dict[str, ZeekLogFile] = {}
    for log_type in LOG_TYPES:
        filename = LOG_FILENAMES[log_type]
        path = workdir / filename
        present = path.exists()
        rows = 0
        if present:
            try:
                with path.open("r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line and not line.startswith("#"):
                            rows += 1
            except OSError:
                pass
        result[log_type] = ZeekLogFile(
            log_type=log_type,
            filename=filename,
            path=path,
            present=present,
            rows=rows,
        )
    return result


def process_pcap(pcap: Path, workdir: Path | None = None) -> dict:
    """Run Zeek over a PCAP and return the parsed logs plus a summary.

    ``workdir`` defaults to a per-file subdirectory under the configured Zeek
    storage dir. Returns a dict with ``available`` (bool), ``summary`` (logs),
    ``logs`` (parsed log data keyed by log type), and ``error`` (str | None).
    Gracefully degrades when Zeek is missing or the run fails.
    """
    if workdir is None:
        settings = get_settings()
        workdir = settings.zeek_dir_abs / pcap.stem
    workdir.mkdir(parents=True, exist_ok=True)

    if not zeek_available():
        return {
            "available": False,
            "summary": [_l.to_dict() for _l in _list_log_files(workdir).values()],
            "logs": {},
            "error": "Zeek is not installed on this system",
        }

    try:
        proc = run_zeek(pcap, workdir)
    except Exception as exc:  # noqa: BLE001
        return {
            "available": True,
            "summary": [_l.to_dict() for _l in _list_log_files(workdir).values()],
            "logs": {},
            "error": f"{type(exc).__name__}: {exc}",
        }

    files = _list_log_files(workdir)
    logs: dict[str, list[dict]] = {}
    for log_type, lf in files.items():
        if lf.present:
            logs[log_type] = parse_zeek_tsv(lf.path)

    error = None
    if proc.returncode != 0:
        detail = proc.stderr.strip() or "zeek exited with a non-zero status"
        if not logs:
            error = f"Zeek run failed: {detail[:500]}"

    return {
        "available": True,
        "summary": [lf.to_dict() for lf in files.values()],
        "logs": logs,
        "error": error,
    }
