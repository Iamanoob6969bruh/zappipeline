import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    monkeypatch.setenv("SSP_STATE_DIR", str(tmp_path / "state"))
    for name in (
        "GITHUB_TOKEN",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LITELLM_API_KEY",
        "SSP_API_TOKEN",
        "SSP_SOURCE_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)
