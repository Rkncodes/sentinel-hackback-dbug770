"""Ban Store: the durable record of every ban ever created."""

import json
import sqlite3
import threading
import uuid
from dataclasses import dataclass

REASON = "failed_login_threshold"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS bans (
    seq                  INTEGER PRIMARY KEY AUTOINCREMENT,
    id                   TEXT NOT NULL UNIQUE,
    ip                   TEXT NOT NULL,
    reason               TEXT NOT NULL,
    triggered_at         INTEGER NOT NULL,
    expires_at           INTEGER NOT NULL,
    revoked_at           INTEGER,
    threshold            INTEGER NOT NULL,
    window_seconds       INTEGER NOT NULL,
    ban_duration_seconds INTEGER NOT NULL,
    evidence             TEXT NOT NULL,
    CHECK (expires_at > triggered_at)
);
CREATE INDEX IF NOT EXISTS bans_ip ON bans (ip, expires_at);
CREATE INDEX IF NOT EXISTS bans_triggered ON bans (triggered_at);
"""

_COLUMNS = (
    "id, ip, reason, triggered_at, expires_at, revoked_at, "
    "threshold, window_seconds, ban_duration_seconds, evidence"
)

# Status is never stored; these are the same conditions as Ban.status().
_STATUS_SQL = {
    "active": "revoked_at IS NULL AND expires_at > :now",
    "expired": "revoked_at IS NULL AND expires_at <= :now",
    "revoked": "revoked_at IS NOT NULL",
}


@dataclass(frozen=True)
class Ban:
    id: str
    ip: str
    reason: str
    triggered_at: int
    expires_at: int
    revoked_at: int | None
    rule: dict
    evidence: list

    def status(self, now_ms: int) -> str:
        if self.revoked_at is not None:
            return "revoked"
        return "active" if now_ms < self.expires_at else "expired"


def _ban(row) -> Ban:
    return Ban(
        id=row[0], ip=row[1], reason=row[2],
        triggered_at=row[3], expires_at=row[4], revoked_at=row[5],
        rule={"threshold": row[6], "window_seconds": row[7], "ban_duration_seconds": row[8]},
        evidence=json.loads(row[9]),
    )


class BanStore:
    def __init__(self, path: str):
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._mutex = threading.Lock()  # one connection shared by request threads
        with self._mutex, self._db:
            self._db.execute("PRAGMA synchronous = FULL")
            self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._mutex:
            self._db.close()

    def create(self, ip: str, triggered_at: int, expires_at: int, rule: dict, evidence: list) -> Ban:
        ban = Ban(
            id="ban_" + uuid.uuid4().hex, ip=ip, reason=REASON,
            triggered_at=triggered_at, expires_at=expires_at, revoked_at=None,
            rule=dict(rule), evidence=list(evidence),
        )
        with self._mutex, self._db:  # committed on exit, before any answer is sent
            self._db.execute(
                f"INSERT INTO bans ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ban.id, ban.ip, ban.reason, ban.triggered_at, ban.expires_at, None,
                 rule["threshold"], rule["window_seconds"], rule["ban_duration_seconds"],
                 json.dumps(ban.evidence)),
            )
        return ban

    def active_for_ip(self, ip: str, now_ms: int) -> Ban | None:
        with self._mutex:
            row = self._db.execute(
                f"SELECT {_COLUMNS} FROM bans WHERE ip = :ip AND {_STATUS_SQL['active']} "
                "ORDER BY seq DESC LIMIT 1",
                {"ip": ip, "now": now_ms},
            ).fetchone()
        return _ban(row) if row else None

    def get(self, ban_id: str) -> Ban | None:
        with self._mutex:
            row = self._db.execute(
                f"SELECT {_COLUMNS} FROM bans WHERE id = ?", (ban_id,)
            ).fetchone()
        return _ban(row) if row else None

    def list(self, now_ms: int, ip: str | None, status: str | None, limit: int) -> list[Ban]:
        where, params = [], {"now": now_ms, "limit": limit}
        if ip is not None:
            where.append("ip = :ip")
            params["ip"] = ip
        if status is not None:
            where.append(_STATUS_SQL[status])
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        with self._mutex:
            rows = self._db.execute(
                f"SELECT {_COLUMNS} FROM bans {clause} "
                "ORDER BY triggered_at DESC, seq DESC LIMIT :limit",
                params,
            ).fetchall()
        return [_ban(row) for row in rows]

    def revoke(self, ban_id: str, now_ms: int) -> None:
        with self._mutex, self._db:
            self._db.execute(
                "UPDATE bans SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (now_ms, ban_id),
            )
