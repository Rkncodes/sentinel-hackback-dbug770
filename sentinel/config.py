"""Configuration, read once at start-up from environment variables."""

from dataclasses import dataclass


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    portal_key: str
    admin_key: str
    threshold: int = 10
    window_seconds: int = 60
    ban_duration_seconds: int = 900
    db_path: str = "./sentinel.db"
    host: str = "127.0.0.1"
    port: int = 8080

    def __post_init__(self):
        for name in ("threshold", "window_seconds", "ban_duration_seconds"):
            value = getattr(self, name)
            if not isinstance(value, int) or value < 1:
                raise ConfigError(f"{name} must be a positive integer")
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
            db_path=env.get("SENTINEL_DB_PATH") or "./sentinel.db",
            host=env.get("SENTINEL_HOST") or "127.0.0.1",
            port=integer("SENTINEL_PORT", 8080),
        )
