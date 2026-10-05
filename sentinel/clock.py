"""The single source of "now". Times are whole milliseconds since the Unix epoch, UTC."""

import time
from datetime import datetime, timedelta, timezone

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class SystemClock:
    def now_ms(self) -> int:
        # Floored to the millisecond, the precision of every stored timestamp,
        # so `now < expires_at` is exact at the boundary.
        return time.time_ns() // 1_000_000


def format_ms(ms: int) -> str:
    """RFC 3339, UTC, millisecond precision: 2026-10-05T10:00:00.000Z"""
    dt = _EPOCH + timedelta(milliseconds=ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"
