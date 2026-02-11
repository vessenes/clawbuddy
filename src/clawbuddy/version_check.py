"""Background upgrade check against PyPI, cached for 24h."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


CACHE_TTL = 86400  # 24 hours
PYPI_URL = "https://pypi.org/pypi/clawbuddy/json"


def _cache_path() -> Path:
    from clawbuddy.config import get_config_dir
    return get_config_dir() / ".version_check"


def _read_cache() -> tuple[str | None, float]:
    """Return (latest_version, timestamp) or (None, 0)."""
    p = _cache_path()
    if not p.exists():
        return None, 0
    try:
        data = json.loads(p.read_text())
        return data.get("latest"), data.get("ts", 0)
    except Exception:
        return None, 0


def _write_cache(latest: str) -> None:
    try:
        _cache_path().write_text(json.dumps({"latest": latest, "ts": time.time()}))
    except Exception:
        pass


def _fetch_latest() -> str | None:
    """Fetch latest version from PyPI. Returns None on any failure."""
    try:
        import httpx
        r = httpx.get(PYPI_URL, timeout=5)
        if r.status_code == 200:
            return r.json()["info"]["version"]
    except Exception:
        pass
    return None


def check_for_upgrade() -> None:
    """Print a stderr warning if a newer version is available on PyPI.

    Cached for 24h so this adds no latency on most invocations.
    Silently does nothing on any error.
    """
    try:
        from clawbuddy import __version__

        cached, ts = _read_cache()
        if time.time() - ts < CACHE_TTL and cached:
            latest = cached
        else:
            latest = _fetch_latest()
            if latest:
                _write_cache(latest)
            else:
                return

        if latest != __version__ and _is_newer(latest, __version__):
            print(
                f"clawbuddy {latest} available (you have {__version__})"
                f" — uvx clawbuddy@latest",
                file=sys.stderr,
            )
    except Exception:
        pass


def _is_newer(latest: str, current: str) -> bool:
    """Simple version comparison using packaging-style tuples."""
    try:
        def _parts(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split("."))
        return _parts(latest) > _parts(current)
    except Exception:
        return False
