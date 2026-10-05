"""Configuration, read once at start-up from environment variables."""

from dataclasses import dataclass, field


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    portal_key: str
    admin_key: str
    threshold: int = 10
    window_seconds: int = 60
    ban_duration_seconds: int = 900
    # Extension. None means "use the default": 5, or one below `threshold` if that is
    # lower, because a window never holds `threshold` failures without a ban.
    success_alert_threshold: int | None = None
    db_path: str = "./sentinel.db"
    host: str = "127.0.0.1"
    port: int = 8080
    # Optional AI incident brief. Without a key the deterministic summary is used.
    # The key is kept out of repr() so it cannot end up in a log line.
    groq_api_key: str = field(default="", repr=False)
    groq_model: str = "openai/gpt-oss-20b"
    groq_base_url: str = "https://api.groq.com/openai/v1"

    def __post_init__(self):
        for name in ("threshold", "window_seconds", "ban_duration_seconds"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1:
                raise ConfigError(f"{name} must be a positive integer")
        alert = self.success_alert_threshold
        if alert is None:
            if self.threshold > 1:  # with a threshold of 1 the alert cannot exist; it stays off
                object.__setattr__(self, "success_alert_threshold", min(5, self.threshold - 1))
        elif not isinstance(alert, int) or alert < 1:
            raise ConfigError("success_alert_threshold must be a positive integer")
        elif alert >= self.threshold:
            raise ConfigError(
                "success_alert_threshold must be lower than threshold: "
                "at or above it the alert could never fire"
            )
        if not self.portal_key or not self.admin_key:
            raise ConfigError("portal key and admin key are both required")
        if self.portal_key == self.admin_key:
            raise ConfigError("portal key and admin key must be different")

    @classmethod
    def from_env(cls, env) -> "Config":
        def integer(name, default):
            raw = env.get(name)
            if raw is None or raw == "":
                return default
            try:
                return int(raw)
            except ValueError:
                raise ConfigError(f"{name} must be an integer") from None

        return cls(
            portal_key=env.get("SENTINEL_PORTAL_KEY", ""),
            admin_key=env.get("SENTINEL_ADMIN_KEY", ""),
            threshold=integer("SENTINEL_THRESHOLD", 10),
            window_seconds=integer("SENTINEL_WINDOW_SECONDS", 60),
            ban_duration_seconds=integer("SENTINEL_BAN_DURATION_SECONDS", 900),
            success_alert_threshold=integer("SENTINEL_SUCCESS_ALERT_THRESHOLD", None),
            db_path=env.get("SENTINEL_DB_PATH") or "./sentinel.db",
            host=env.get("SENTINEL_HOST") or ("0.0.0.0" if env.get("PORT") else "127.0.0.1"),
            port=integer("PORT", integer("SENTINEL_PORT", 8080)),
            groq_api_key=(env.get("GROQ_API_KEY") or "").strip(),
            groq_model=env.get("GROQ_MODEL") or "openai/gpt-oss-20b",
            groq_base_url=env.get("GROQ_BASE_URL") or "https://api.groq.com/openai/v1",
        )
