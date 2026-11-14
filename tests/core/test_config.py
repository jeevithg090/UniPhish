"""Settings are read from the environment; blank values behave like unset ones."""

from __future__ import annotations

from pathlib import Path

import pytest

from uniphish.core.config import Settings

_VARS = (
    "UNIPHISH_DATA_DIR", "UNIPHISH_DB", "UNIPHISH_USER_AGENT", "UNIPHISH_API_KEYS",
    "UNIPHISH_RATE_LIMIT", "UNIPHISH_ONLINE", "UNIPHISH_AI_MODEL", "ANTHROPIC_API_KEY",
    "VT_API_KEY", "TELEGRAM_BOT_TOKEN", "UNIPHISH_MALICIOUS_THRESHOLD",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _VARS:
        monkeypatch.delenv(name, raising=False)


def test_defaults_when_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    s = Settings.from_env()
    assert s.data_dir == tmp_path / ".uniphish"
    assert s.db_path == tmp_path / ".uniphish" / "uniphish.db"
    assert s.api_keys == [] and s.online is False and s.rate_limit_per_minute == 120
    assert s.user_agent.startswith("UniPhish/")
    assert s.anthropic_api_key is None


def test_blank_values_fall_back_to_defaults(monkeypatch, tmp_path):
    """`VAR=` lines from a sourced .env must not turn paths into the cwd."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for name in _VARS:
        monkeypatch.setenv(name, "")
    s = Settings.from_env()
    assert s.data_dir == tmp_path / ".uniphish"
    assert s.db_path.name == "uniphish.db"
    assert s.user_agent.startswith("UniPhish/")
    assert s.ai_model == Settings.model_fields["ai_model"].default
    assert s.anthropic_api_key is None and s.virustotal_api_key is None
    assert s.telegram_bot_token is None
    assert s.api_keys == [] and s.rate_limit_per_minute == 120
    assert s.malicious_threshold == 0.85


def test_explicit_values(monkeypatch, tmp_path):
    monkeypatch.setenv("UNIPHISH_DATA_DIR", str(tmp_path / "d"))
    monkeypatch.setenv("UNIPHISH_API_KEYS", " k1 , ,k2 ")
    monkeypatch.setenv("UNIPHISH_RATE_LIMIT", "7")
    monkeypatch.setenv("UNIPHISH_ONLINE", "yes")
    monkeypatch.setenv("UNIPHISH_MALICIOUS_THRESHOLD", "not-a-number")
    s = Settings.from_env()
    assert s.data_dir == Path(tmp_path / "d")
    assert s.db_path == tmp_path / "d" / "uniphish.db"
    assert s.api_keys == ["k1", "k2"]
    assert s.rate_limit_per_minute == 7 and s.online is True
    assert s.malicious_threshold == 0.85  # unparsable -> default
