"""Shared pytest fixtures."""
from __future__ import annotations

import os
import tempfile

import pytest
from fastapi.testclient import TestClient

# Set test environment BEFORE importing app modules so settings pick them up.
_test_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["DATABASE_URL"] = f"sqlite:///{_test_db.name}"
os.environ["STORAGE_DIR"] = tempfile.mkdtemp(prefix="traffic_test_")

from app.core.config import get_settings  # noqa: E402

get_settings.cache_clear()


@pytest.fixture(scope="session")
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session", autouse=True)
def _ensure_tables():
    """Create all tables in the test DB for tests that use sessions directly."""
    from app.core.database import init_db

    init_db()
