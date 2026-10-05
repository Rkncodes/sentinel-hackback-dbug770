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


_SUCCESS_ALERT = {
    "code": "success_after_failed_attempts",
    "message": "Successful login followed repeated failed attempts from this address.",
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
    warning: dict | None = None  # set only on a successful report; see Sentinel.report

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
        # Last success alert per IP as (time, failed attempts): memory only, no username.
        # Read by incident_facts so an administrator's brief can mention it.
        self._alerts: dict[str, tuple[int, int]] = {}

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
                return Verdict(ip, now, None, warning=self._success_alert(ip, now, username))
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

    def _success_alert(self, ip: str, now: int, username: str | None) -> dict | None:
        """A correct password right after repeated failures on the same account from
        the same address may be a guess that worked. This only tells the portal:
        nothing is counted, persisted or banned, and the failure window is untouched."""
        threshold = self.config.success_alert_threshold
        if not username or threshold is None:
            return None
        failures = self._detector.count_failures(ip, now, username)
        if failures < threshold:
            return None
        self._alerts[ip] = (now, failures)
        return {**_SUCCESS_ALERT, "failed_attempts": failures}

    def incident_facts(self, ip: str) -> dict:
        """Structured facts about one address for the administrator's incident brief.

        Read-only, and built from Sentinel's own state: nothing the caller says about
        the incident is taken on trust. Carries no usernames and no evidence.
        """
        with self._lock(ip):
            now = self.clock.now_ms()
            window_ms = self.config.window_seconds * 1000
            recent = self._store.list(now, ip, None, 1)
            latest = recent[0] if recent else None
            ban = latest if latest is not None and latest.status(now) == "active" else None
            noted = self._alerts.get(ip)
            failures = self._detector.count_all(ip, now)

        alert = None
        if noted is not None:
            at, count = noted
            if ban is not None:
                relevant = at <= ban.triggered_at <= at + window_ms  # it led up to this ban
            else:
                relevant = now - at <= window_ms and not (latest and latest.triggered_at >= at)
            if relevant:
                alert = {"code": _SUCCESS_ALERT["code"], "failed_attempts": count, "at": format_ms(at)}

        rule = ban.rule if ban is not None else {
            "threshold": self.config.threshold, "window_seconds": self.config.window_seconds}
        if ban is not None:
            failures = len(ban.evidence)
            status, action = "banned", "ip_banned"
        elif alert is not None:
            status, action = "flagged", "login_allowed_and_flagged"
        else:
            status, action = ("monitoring" if failures else "clear"), "none"

        last_ban = None
        if ban is None and latest is not None:
            revoked = latest.revoked_at is not None
            last_ban = {
                "reason": latest.reason,
                "started_at": format_ms(latest.triggered_at),
                "ended_at": format_ms(latest.revoked_at if revoked else latest.expires_at),
                "ended_by": "administrator" if revoked else "expiry",
            }
        return {
            "source_ip": ip,
            "generated_at": format_ms(now),
            "status": status,
            "action": action,
            "currently_banned": ban is not None,
            "failed_attempts": failures,
            "threshold": rule["threshold"],
            "window_seconds": rule["window_seconds"],
            "threshold_reached": ban is not None,
            "ban": None if ban is None else {
                "reason": ban.reason,
                "started_at": format_ms(ban.triggered_at),
                "expires_at": format_ms(ban.expires_at),
                "seconds_remaining": -(-(ban.expires_at - now) // 1000),
            },
            "success_alert": alert,
            "last_ban": last_ban,
        }

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
        now = self.clock.now_ms()
        self._detector.sweep(now)
        # An alert note can matter for one window plus one ban at most.
        keep_ms = (self.config.window_seconds + self.config.ban_duration_seconds) * 1000
        for ip, (at, _) in list(self._alerts.items()):
            if now - at > keep_ms:
                self._alerts.pop(ip, None)

    def tracked_ips(self) -> int:
        return self._detector.tracked_ips()

    def close(self) -> None:
        self._store.close()
