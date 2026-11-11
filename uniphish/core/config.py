"""Runtime settings, read once from the environment (``UNIPHISH_*``).

Offline-first: nothing in UniPhish touches the network unless ``online`` is enabled
(globally via ``UNIPHISH_ONLINE=1`` or per request via ``AnalysisOptions.online``).
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


def _env_list(name: str) -> list[str]:
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]


class Settings(BaseModel):
    """Process-wide configuration. Obtain via :func:`get_settings`."""

    data_dir: Path = Field(description="Where the SQLite DB, feed caches and models live.")
    db_path: Path
    online: bool = Field(default=False, description="Default for AnalysisOptions.online.")
    user_agent: str = "UniPhish/2.0 (+https://github.com/jeevithg090/UniPhish)"
    http_timeout_s: float = 8.0
    http_max_bytes: int = 3_000_000

    # Decision thresholds on fused risk (probability space).
    suspicious_threshold: float = 0.50
    malicious_threshold: float = 0.85

    # API security
    api_keys: list[str] = Field(default_factory=list,
                                description="Accepted API keys (empty = auth disabled, dev).")
    cors_origins: list[str] = Field(default_factory=list)
    rate_limit_per_minute: int = 120

    # Optional third-party integrations (all optional; features degrade gracefully).
    anthropic_api_key: str | None = None
    ai_model: str = "claude-sonnet-5-5"
    virustotal_api_key: str | None = None
    urlscan_api_key: str | None = None
    safebrowsing_api_key: str | None = None
    telegram_bot_token: str | None = None

    @classmethod
    def from_env(cls) -> Settings:
        data_dir = Path(os.environ.get("UNIPHISH_DATA_DIR", Path.home() / ".uniphish")).expanduser()
        return cls(
            data_dir=data_dir,
            db_path=Path(os.environ.get("UNIPHISH_DB", data_dir / "uniphish.db")).expanduser(),
            online=_env_bool("UNIPHISH_ONLINE", False),
            user_agent=os.environ.get("UNIPHISH_USER_AGENT",
                                      cls.model_fields["user_agent"].default),
            http_timeout_s=_env_float("UNIPHISH_HTTP_TIMEOUT", 8.0),
            suspicious_threshold=_env_float("UNIPHISH_SUSPICIOUS_THRESHOLD", 0.50),
            malicious_threshold=_env_float("UNIPHISH_MALICIOUS_THRESHOLD", 0.85),
            api_keys=_env_list("UNIPHISH_API_KEYS"),
            cors_origins=_env_list("UNIPHISH_CORS_ORIGINS"),
            rate_limit_per_minute=int(_env_float("UNIPHISH_RATE_LIMIT", 120)),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
            ai_model=os.environ.get("UNIPHISH_AI_MODEL", "claude-sonnet-5-5"),
            virustotal_api_key=os.environ.get("VT_API_KEY") or None,
            urlscan_api_key=os.environ.get("URLSCAN_API_KEY") or None,
            safebrowsing_api_key=os.environ.get("GSB_API_KEY") or None,
            telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN") or None,
        )

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings.from_env()


def reset_settings() -> None:
    """Forget cached settings (tests change the environment)."""
    get_settings.cache_clear()
