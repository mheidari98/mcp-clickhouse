"""Housekeeping for the OAuth proxy's on-disk state.

FastMCP stores OAuth state (client registrations, tokens, transactions) as one
JSON file per key under ``<FASTMCP_HOME>/oauth-proxy/<key fingerprint>/``. The
file store never deletes expired entries, so a long-running server slowly
exhausts the volume's inodes. Entries carry a plaintext ``expires_at`` next to
the encrypted value, which lets this module remove expired files without the
encryption key. Client registrations carry no expiry; they are removed once
older than a configurable age.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("mcp-clickhouse")

_PRUNERS: dict[Path, threading.Thread] = {}
_PRUNERS_LOCK = threading.Lock()


def _parse_timestamp(value: object) -> Optional[float]:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _is_prunable(path: str, now: float, max_age_seconds: int) -> bool:
    """Whether the entry file at ``path`` has expired or aged out."""
    try:
        with open(path, encoding="utf-8") as entry_file:
            entry = json.load(entry_file)
    except (OSError, ValueError):
        # Unreadable or mid-write files are left alone; a later pass retries.
        return False
    if not isinstance(entry, dict):
        return False

    expires_at = _parse_timestamp(entry.get("expires_at"))
    if expires_at is not None:
        return expires_at <= now

    if max_age_seconds <= 0:
        return False
    created_at = _parse_timestamp(entry.get("created_at"))
    return created_at is not None and created_at + max_age_seconds <= now


def prune_oauth_state(root: Path, max_age_seconds: int, now: Optional[float] = None) -> int:
    """Delete expired entry files below ``root`` and return how many were removed.

    ``max_age_seconds`` applies only to entries without an ``expires_at`` (client
    registrations); 0 keeps them forever. Collection metadata files and anything
    that is not a JSON entry file are never touched.
    """
    now = time.time() if now is None else now
    removed = 0
    for current_dir, _dir_names, file_names in os.walk(root):
        for file_name in file_names:
            # Collection metadata ("<collection>-info.json") is not an entry.
            if not file_name.endswith(".json") or file_name.endswith("-info.json"):
                continue
            path = os.path.join(current_dir, file_name)
            try:
                before = os.stat(path)
                if not _is_prunable(path, now, max_age_seconds):
                    continue
                # The store replaces files atomically; skip one rewritten since it was read.
                after = os.stat(path)
                if (after.st_ino, after.st_mtime_ns) != (before.st_ino, before.st_mtime_ns):
                    continue
                os.unlink(path)
                removed += 1
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning("Could not prune OAuth state file %s: %s", path, exc)
    return removed


def _prune_forever(root: Path, interval_seconds: int, max_age_seconds: int) -> None:
    while True:
        try:
            removed = prune_oauth_state(root, max_age_seconds)
            if removed:
                logger.info("Pruned %d expired OAuth state entries from %s", removed, root)
        except Exception:
            logger.exception("OAuth state pruning failed")
        time.sleep(interval_seconds)


def start_oauth_state_pruner(
    root: Path, interval_seconds: int, max_age_seconds: int
) -> Optional[threading.Thread]:
    """Prune ``root`` now and then every ``interval_seconds`` on a daemon thread.

    Returns None when ``interval_seconds`` is not positive (pruning disabled). A root
    that already has a running pruner is not given a second one.
    """
    if interval_seconds <= 0:
        logger.info("OAuth state pruning is disabled")
        return None
    with _PRUNERS_LOCK:
        existing = _PRUNERS.get(root)
        if existing is not None and existing.is_alive():
            return existing
        thread = threading.Thread(
            target=_prune_forever,
            args=(root, interval_seconds, max_age_seconds),
            name="oauth-state-pruner",
            daemon=True,
        )
        thread.start()
        _PRUNERS[root] = thread
    return thread
