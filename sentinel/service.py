"""Ban Manager and control flow: report, check, list, unban."""

import threading
from dataclasses import dataclass

from .clock import format_ms
from .config import Config
from .detector import Detector
from .store import Ban, BanStore

_STRIPES = 256


# Fixed wording per reason. It refers to the network address, not the person,
# because many people can share one IP.
_MESSAGES = {
    "failed_login_threshold": (
        "Sign-in from your network address is temporarily blocked "
        "because of too many failed sign-in attempts."
    ),
}


class BanNotFound(Exception):
    pass


def explanation(ban: Ban | None, now_ms: int) -> dict | None:
    """What a blocked person may be told. Derived from an active ban, never stored.

    Carries no evidence, usernames or rule values.
    """
    if ban is None or ban.status(now_ms) != "active":
        return None
    remaining_ms = ban.expires_at - now_ms
    return {
        "blocked": True,
        "reason_code": ban.reason,
        "message": _MESSAGES[ban.reason],
        "started_at": format_ms(ban.triggered_at),
        "expires_at": format_ms(ban.expires_at),
        "retry_after_seconds": -(-remaining_ms // 1000),  # rounded up: at least 1 while active
    }


@dataclass(frozen=True)
class Verdict:
    ip: str
    now_ms: int
    ban: Ban | None  # the active ban, if any
    ban_triggered: bool = False

    @property
    def banned(self) -> bool:
        return self.ban is not None


class Sentinel:
    def __init__(self, config: Config, store: BanStore, clock):
        self.config = config
        self.clock = clock
        self._store = store
        self._detector = Detector(config.window_seconds)
        # Per-IP atomicity (D-6): every state-changing operation for an IP runs
        # under that IP's lock. A fixed set of locks keeps memory bounded; two
        # IPs sharing one is harmless.
        self._locks = [threading.Lock() for _ in range(_STRIPES)]

    def _lock(self, ip: str) -> threading.Lock:
        return self._locks[hash(ip) % _STRIPES]

    def report(self, ip: str, outcome: str, username: str | None) -> Verdict:
        with self._lock(ip):
            now = self.clock.now_ms()
            ban = self._store.active_for_ip(ip, now)
            if ban is not None:
                # Already banned: nothing is counted, whatever the outcome.
                return Verdict(ip, now, ban)
            if outcome != "failure":
                return Verdict(ip, now, None)
            failures = self._detector.record_failure(ip, now, username)
            if len(failures) < self.config.threshold:
                return Verdict(ip, now, None)
            ban = self._store.create(
                ip=ip,
                triggered_at=now,
                expires_at=now + self.config.ban_duration_seconds * 1000,
                rule={
                    "threshold": self.config.threshold,
                    "window_seconds": self.config.window_seconds,
                    "ban_duration_seconds": self.config.ban_duration_seconds,
                },
                evidence=failures,
            )
            self._detector.clear(ip)
            return Verdict(ip, now, ban, ban_triggered=True)

    def check(self, ip: str) -> Verdict:
        now = self.clock.now_ms()
        return Verdict(ip, now, self._store.active_for_ip(ip, now))

    def list_bans(self, ip: str | None, status: str | None, limit: int) -> tuple[list[Ban], int]:
        now = self.clock.now_ms()
        return self._store.list(now, ip, status, limit), now

    def revoke(self, ban_id: str) -> tuple[Ban, int]:
        ban = self._store.get(ban_id)
        if ban is None:
            raise BanNotFound(ban_id)
        with self._lock(ban.ip):
            now = self.clock.now_ms()
            ban = self._store.get(ban_id)
            if ban.status(now) == "active":
                self._store.revoke(ban_id, now)
                self._detector.clear(ban.ip)
                ban = self._store.get(ban_id)
            return ban, now

    def sweep(self) -> None:
        self._detector.sweep(self.clock.now_ms())

    def tracked_ips(self) -> int:
        return self._detector.tracked_ips()

    def close(self) -> None:
        self._store.close()
