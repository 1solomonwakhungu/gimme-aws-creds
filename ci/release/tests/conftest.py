"""Shared fixtures for the release readiness tests.

Every test runs with a temporary HOME, XDG and cache directories, a null keyring
backend and cloud metadata lookups disabled, so no real credentials, keychains or
cloud endpoints can be reached.
"""
import sys
from pathlib import Path

import pytest

RELEASE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = RELEASE_DIR.parents[1]
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))


@pytest.fixture(autouse=True)
def isolated_environment(tmp_path, monkeypatch):
    home = tmp_path / "home"
    for sub in ("", ".config", ".cache"):
        (home / sub).mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    monkeypatch.setenv("PYTHON_KEYRING_BACKEND", "keyring.backends.null.Keyring")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for name in ("GITHUB_TOKEN", "PYPI_PUBLISH_ENABLED", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(name, raising=False)
    yield
