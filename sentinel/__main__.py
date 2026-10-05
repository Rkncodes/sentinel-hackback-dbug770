"""Run Sentinel: python -m sentinel"""

import os
import sys
import threading
import time

from .api import create_server
from .config import Config, ConfigError


def _sweep_forever(sentinel, interval_seconds: int):
    # Bounded memory only (NFR-9). Decisions never depend on this running.
    while True:
        time.sleep(interval_seconds)
        sentinel.sweep()


def main() -> int:
    try:
        config = Config.from_env(os.environ)
    except ConfigError as exc:
        print(f"sentinel: configuration error: {exc}", file=sys.stderr)
        return 2
    server = create_server(config)
    threading.Thread(
        target=_sweep_forever, args=(server.sentinel, config.window_seconds), daemon=True
    ).start()
    print(
        f"sentinel: listening on http://{config.host}:{server.server_address[1]} "
        f"(threshold={config.threshold}, window={config.window_seconds}s, "
        f"ban={config.ban_duration_seconds}s, "
        f"success_alert={config.success_alert_threshold or 'off'}, "
        f"ai_brief={'groq:' + config.groq_model if config.groq_api_key else 'fallback only'}, "
        f"db={config.db_path})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
