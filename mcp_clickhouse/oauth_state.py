"""Housekeeping for the OAuth proxy's on-disk state.

FastMCP stores OAuth state (client registrations, tokens, transactions) as one
JSON file per key under ``<FASTMCP_HOME>/oauth-proxy/<key fingerprint>/``. The
file store never deletes expired entries, so a long-running server slowly
exhausts the volume's inodes. Entries carry a plaintext ``expires_at`` next to
the encrypted value, which lets this module remove expired files without the
encryption key. Client registrations carry no expiry; they are removed once
older than a configurable age, which must exceed the longest refresh-token
lifetime (FastMCP falls back to one year) or active sessions are signed out.

Remove this module once FastMCP culls its own file store itself.
"""

import errno
import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, Optional

logger = logging.getLogger("mcp-clickhouse")

# Temp files are written next to their target and renamed; leftovers mean a crash.
_STALE_TEMP_FILE_SECONDS = 3600
# A pass that sees at least this many files and none with an expiry means the
# on-disk format changed and the pruner is no longer effective.
_FORMAT_CHANGE_CANARY_FILES = 100
_FATAL_ERRNOS = (errno.EROFS, errno.EACCES, errno.EPERM)

_PRUNERS: dict[Path, threading.Thread] = {}
_PRUNERS_LOCK = threading.Lock()


class PruneResult(NamedTuple):
    scanned: int = 0
    removed: int = 0
    with_expiry: int = 0


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


def _is_prunable(path: str, now: float, max_age_seconds: int) -> tuple[bool, bool]:
    """Whether the entry file at ``path`` has expired or aged out, and had an expiry."""
    try:
        with open(path, encoding="utf-8") as entry_file:
            entry = json.load(entry_file)
    except (OSError, ValueError):
        # Unreadable or mid-write files are left alone; a later pass retries.
        return False, False
    if not isinstance(entry, dict):
        return False, False

    expires_at = _parse_timestamp(entry.get("expires_at"))
    if expires_at is not None:
        return expires_at <= now, True

    if max_age_seconds <= 0:
        return False, False
    created_at = _parse_timestamp(entry.get("created_at"))
    return created_at is not None and created_at + max_age_seconds <= now, False


def prune_oauth_state(root: Path, max_age_seconds: int, now: Optional[float] = None) -> PruneResult:
    """Delete expired entry files below ``root`` and report what the pass saw.

    ``max_age_seconds`` applies only to entries without an ``expires_at`` (client
    registrations); 0 keeps them forever. Collection metadata files and anything
    that is not a JSON entry file are never touched. The pass stops early when the
    volume is read-only or not writable.
    """
    now = time.time() if now is None else now
    scanned = removed = with_expiry = 0
    for current_dir, _dir_names, file_names in os.walk(root):
        for file_name in file_names:
            path = os.path.join(current_dir, file_name)
            try:
                if file_name.endswith(".tmp"):
                    if now - os.stat(path).st_mtime > _STALE_TEMP_FILE_SECONDS:
                        os.unlink(path)
                        removed += 1
                    continue
                # Collection metadata ("<collection>-info.json") is not an entry.
                if not file_name.endswith(".json") or file_name.endswith("-info.json"):
                    continue
                scanned += 1
                before = os.stat(path)
                prunable, has_expiry = _is_prunable(path, now, max_age_seconds)
                with_expiry += has_expiry
                if not prunable:
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
                if exc.errno in _FATAL_ERRNOS:
                    return PruneResult(scanned, removed, with_expiry)
    return PruneResult(scanned, removed, with_expiry)


def _prune_forever(root: Path, interval_seconds: int, max_age_seconds: int) -> None:
    while True:
        try:
            result = prune_oauth_state(root, max_age_seconds)
            if result.removed:
                logger.info(
                    "Pruned %d of %d OAuth state files from %s",
                    result.removed,
                    result.scanned,
                    root,
                )
            if result.scanned >= _FORMAT_CHANGE_CANARY_FILES and not result.with_expiry:
                logger.warning(
                    "OAuth state under %s has %d entry files but none with an expiry; "
                    "the on-disk format may have changed and pruning is ineffective",
                    root,
                    result.scanned,
                )
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
