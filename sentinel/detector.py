"""Failure Windows: the recent failed logins of each IP. In memory only."""

import threading


class Detector:
    def __init__(self, window_seconds: int):
        self._window_ms = window_seconds * 1000
        self._windows: dict[str, list[dict]] = {}
        self._mutex = threading.Lock()  # guards the dict itself, not per-IP ordering

    def _fresh(self, failures, now_ms):
        # A failure exactly `window` old still counts.
        return [f for f in failures if now_ms - f["received_at"] <= self._window_ms]

    def record_failure(self, ip: str, now_ms: int, username) -> list[dict]:
        """Drop failures older than the window, add this one, return what remains."""
        with self._mutex:
            failures = self._fresh(self._windows.get(ip, ()), now_ms)
            failures.append({"received_at": now_ms, "username": username})
            self._windows[ip] = failures
            return list(failures)

    def count_failures(self, ip: str, now_ms: int, username: str) -> int:
        """Failures for this IP and username still inside the window. Changes nothing."""
        with self._mutex:
            failures = self._fresh(self._windows.get(ip, ()), now_ms)
        return sum(1 for f in failures if f["username"] == username)

    def clear(self, ip: str) -> None:
        with self._mutex:
            self._windows.pop(ip, None)

    def sweep(self, now_ms: int) -> None:
        """Memory cleanup only: forget failures no later report could count."""
        with self._mutex:
            for ip in list(self._windows):
                failures = self._fresh(self._windows[ip], now_ms)
                if failures:
                    self._windows[ip] = failures
                else:
                    del self._windows[ip]

    def tracked_ips(self) -> int:
        with self._mutex:
            return len(self._windows)
