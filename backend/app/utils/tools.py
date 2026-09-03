"""Detection and status reporting for external tools used by the app."""
from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from app.core.config import get_settings

POSSIBLE_TSHARK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]

POSSIBLE_ZEEK_PATHS = [
    r"C:\Program Files\Zeek\bin\zeek.exe",
    r"/usr/local/zeek/bin/zeek",
    r"/opt/zeek/bin/zeek",
]


@dataclass
class ToolStatus:
    name: str
    installed: bool
    version: str | None = None
    path: str | None = None
    note: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "installed": self.installed,
            "version": self.version,
            "path": self.path,
            "note": self.note,
        }


def _which(name: str) -> str | None:
    return shutil.which(name)


def _lookup_path(configured: str, candidates: list[str]) -> str | None:
    settings = get_settings()
    configured = (configured or "").strip()
    if configured:
        candidate = Path(configured)
        if candidate.is_file():
            return str(candidate)
    for c in candidates:
        p = Path(c)
        if p.is_file():
            return str(p)
    found = _which(os.path.basename(candidates[0]) if candidates else "")
    return found


def detect_tshark() -> ToolStatus:
    settings = get_settings()
    path = _lookup_path(settings.tshark_path, POSSIBLE_TSHARK_PATHS)
    if not path:
        return ToolStatus(
            name="TShark",
            installed=False,
            note="Live packet capture and PCAP parsing require TShark. Install Wireshark (includes TShark) from https://www.wireshark.org/download.html",
        )
    version = _read_version(path)
    return ToolStatus(name="TShark", installed=True, version=version, path=path)


def detect_zeek() -> ToolStatus:
    settings = get_settings()
    path = _lookup_path(settings.zeek_path, POSSIBLE_ZEEK_PATHS)
    if not path:
        return ToolStatus(
            name="Zeek",
            installed=False,
            note="Zeek is optional. Install it to enable connection/event analysis. https://zeek.org/",
        )
    version = _read_version(path)
    return ToolStatus(name="Zeek", installed=True, version=version, path=path)


def detect_docker() -> ToolStatus:
    path = _which("docker")
    if not path:
        return ToolStatus(
            name="Docker",
            installed=False,
            note="Docker is optional, used for lab target containers. https://www.docker.com/",
        )
    version = _read_version(path, "--version")
    return ToolStatus(name="Docker", installed=True, version=version, path=path)


def detect_python() -> ToolStatus:
    return ToolStatus(
        name="Python",
        installed=True,
        version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        path=sys.executable,
    )


def detect_platform() -> ToolStatus:
    note = platform.system()
    if note.lower() == "windows":
        note += " - ensure Npcap is installed for live capture."
    return ToolStatus(name="Platform", installed=True, version=platform.system(), path=platform.platform(), note=note)


def _read_version(path: str, flag: str = "--version") -> str | None:
    """Best-effort version read; never raise."""
    try:
        import subprocess

        result = subprocess.run(
            [path, flag],
            capture_output=True,
            text=True,
            timeout=10,
        )
        first = (result.stdout or result.stderr).strip().splitlines()
        return first[0][:200] if first else None
    except Exception:
        return None


def all_tool_status() -> list[ToolStatus]:
    return [
        detect_python(),
        detect_platform(),
        detect_tshark(),
        detect_zeek(),
        detect_docker(),
    ]
