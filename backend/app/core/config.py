"""Application configuration loaded from environment / .env file."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Absolute base directory of the backend package (backend/)
BASE_DIR = Path(__file__).resolve().parents[2]  # backend/


class Settings(BaseSettings):
    """Typed settings for the application.

    Values are read from environment variables and a local `.env` file.
    See `backend/.env.example` for all documented options.
    """

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    app_name: str = "Network Traffic Analyzer"
    api_prefix: str = "/api/v1"
    debug: bool = False

    # Database
    database_url: str = "sqlite:///./traffic.db"

    # Storage
    storage_dir: Path = BASE_DIR / "storage"
    upload_dir: Path = Field(default_factory=lambda: Path("uploads"))
    pcap_dir: Path = Field(default_factory=lambda: Path("pcaps"))
    report_dir: Path = Field(default_factory=lambda: Path("reports"))
    zeek_dir: Path = Field(default_factory=lambda: Path("zeek"))

    # Upload limits
    max_upload_mb: int = 100

    # Tool paths (empty = auto-detect)
    tshark_path: str = ""
    zeek_path: str = ""

    # Safe default simulation targets
    sim_target_localhost: str = "127.0.0.1"
    sim_target_private: str = "192.168.10.10"

    # CORS
    cors_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

    # Detection engine thresholds (M10) — all configurable via env/.env.
    detect_portscan_min_ports: int = 10
    detect_conn_rate_window_sec: float = 10.0
    detect_conn_rate_max_per_window: int = 100
    detect_dns_nxdomain_min: int = 5
    detect_dns_query_diversity_min: int = 50
    detect_data_transfer_min_bytes: int = 10_000_000
    detect_severity_high_multiplier: float = 2.0
    detect_severity_critical_multiplier: float = 4.0

    @property
    def upload_dir_abs(self) -> Path:
        return self.storage_dir / self.upload_dir

    @property
    def pcap_dir_abs(self) -> Path:
        return self.storage_dir / self.pcap_dir

    @property
    def report_dir_abs(self) -> Path:
        return self.storage_dir / self.report_dir

    @property
    def zeek_dir_abs(self) -> Path:
        return self.storage_dir / self.zeek_dir

    def ensure_dirs(self) -> None:
        """Create all storage directories if they do not exist."""
        for d in (
            self.storage_dir,
            self.upload_dir_abs,
            self.pcap_dir_abs,
            self.report_dir_abs,
            self.zeek_dir_abs,
        ):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()
