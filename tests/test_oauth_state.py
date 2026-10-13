import asyncio
import errno
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone

from cryptography.fernet import Fernet
from key_value.aio.stores.filetree import (
    FileTreeStore,
    FileTreeV1CollectionSanitizationStrategy,
    FileTreeV1KeySanitizationStrategy,
)
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

from mcp_clickhouse import oauth_state
from mcp_clickhouse.oauth_state import prune_oauth_state, start_oauth_state_pruner

NOW = datetime(2026, 10, 13, tzinfo=timezone.utc)


def write_entry(directory, name, *, created_at=NOW, expires_at=None):
    entry = {
        "created_at": created_at.isoformat(),
        "value": {"__encrypted_data__": "x", "__encryption_version__": 1},
        "version": 1,
    }
    if expires_at is not None:
        entry["expires_at"] = expires_at.isoformat()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(json.dumps(entry))
    return path


def test_prunes_only_expired_and_aged_entries(tmp_path):
    tokens = tmp_path / "fingerprint" / "mcp-refresh-tokens"
    clients = tmp_path / "fingerprint" / "mcp-oauth-proxy-clients"
    expired = write_entry(tokens, "expired.json", expires_at=NOW - timedelta(seconds=1))
    live = write_entry(tokens, "live.json", expires_at=NOW + timedelta(hours=1))
    old_client = write_entry(clients, "old.json", created_at=NOW - timedelta(days=91))
    new_client = write_entry(clients, "new.json", created_at=NOW - timedelta(days=1))
    info = tmp_path / "fingerprint" / "mcp-refresh-tokens-info.json"
    info.write_text(json.dumps({"collection": "mcp-refresh-tokens", "version": 1}))

    result = prune_oauth_state(tmp_path, 90 * 86400, now=NOW.timestamp())

    assert result.removed == 2
    assert result.scanned == 4
    assert result.with_expiry == 2
    assert not expired.exists()
    assert not old_client.exists()
    assert live.exists()
    assert new_client.exists()
    assert info.exists()


def test_max_age_zero_keeps_registrations(tmp_path):
    clients = tmp_path / "mcp-oauth-proxy-clients"
    old_client = write_entry(clients, "old.json", created_at=NOW - timedelta(days=1000))
    expired = write_entry(clients, "expired.json", expires_at=NOW - timedelta(days=1))

    assert prune_oauth_state(tmp_path, 0, now=NOW.timestamp()).removed == 1
    assert old_client.exists()
    assert not expired.exists()


def test_leaves_unreadable_and_foreign_files(tmp_path):
    directory = tmp_path / "mcp-upstream-tokens"
    directory.mkdir()
    corrupt = directory / "corrupt.json"
    corrupt.write_text("{not json")
    foreign = directory / "notes.txt"
    foreign.write_text("keep")

    assert prune_oauth_state(tmp_path, 86400, now=NOW.timestamp()).removed == 0
    assert corrupt.exists()
    assert foreign.exists()


def test_missing_root_is_a_noop(tmp_path):
    assert prune_oauth_state(tmp_path / "absent", 86400).removed == 0


def test_skips_entry_rewritten_after_read(tmp_path, monkeypatch):
    directory = tmp_path / "mcp-jti-mappings"
    path = write_entry(directory, "racy.json", expires_at=NOW - timedelta(days=1))
    original_stat = os.stat
    calls = {"count": 0}

    def stat_with_rewrite(target, *args, **kwargs):
        result = original_stat(target, *args, **kwargs)
        if str(target) == str(path):
            calls["count"] += 1
            if calls["count"] == 2:
                os.utime(path, ns=(result.st_atime_ns, result.st_mtime_ns + 1_000_000_000))
                return original_stat(target, *args, **kwargs)
        return result

    monkeypatch.setattr(os, "stat", stat_with_rewrite)

    assert prune_oauth_state(tmp_path, 0, now=NOW.timestamp()).removed == 0
    assert path.exists()


def test_pruner_disabled_without_interval(tmp_path):
    assert start_oauth_state_pruner(tmp_path, 0, 86400) is None


def test_pruner_thread_removes_expired_entry(tmp_path):
    expired = write_entry(
        tmp_path / "mcp-authorization-codes", "code.json", expires_at=NOW - timedelta(days=1)
    )

    thread = start_oauth_state_pruner(tmp_path, 3600, 0)

    assert thread is not None and thread.daemon
    deadline = time.monotonic() + 5
    while expired.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not expired.exists()


def test_prunes_entries_written_by_the_real_file_store(tmp_path):
    file_store = FileTreeStore(
        data_directory=tmp_path,
        key_sanitization_strategy=FileTreeV1KeySanitizationStrategy(tmp_path),
        collection_sanitization_strategy=FileTreeV1CollectionSanitizationStrategy(tmp_path),
    )
    store = FernetEncryptionWrapper(key_value=file_store, fernet=Fernet(Fernet.generate_key()))

    async def populate():
        await store.put("short", {"v": 1}, collection="tokens", ttl=1)
        await store.put("long", {"v": 1}, collection="tokens", ttl=3600)
        await store.put("client", {"v": 1}, collection="clients")

    asyncio.run(populate())

    assert prune_oauth_state(tmp_path, 0, now=time.time() + 60).removed == 1
    assert len(list(tmp_path.rglob("*.json"))) == 4  # 2 collection infos + 2 entries


def test_one_pruner_per_root(tmp_path):
    first = start_oauth_state_pruner(tmp_path, 3600, 0)

    assert start_oauth_state_pruner(tmp_path, 3600, 0) is first


def test_prunes_every_fingerprint_directory_under_root(tmp_path):
    expired = [
        write_entry(
            tmp_path / fingerprint / "mcp-jti-mappings",
            "expired.json",
            expires_at=NOW - timedelta(days=1),
        )
        for fingerprint in ("current", "rotated-away")
    ]

    assert prune_oauth_state(tmp_path, 0, now=NOW.timestamp()).removed == 2
    assert not any(path.exists() for path in expired)


def test_naive_timestamps_are_treated_as_utc(tmp_path):
    directory = tmp_path / "mcp-jti-mappings"
    directory.mkdir()
    path = directory / "naive.json"
    path.write_text(json.dumps({"expires_at": "2026-10-12T00:00:00", "value": {}}))

    assert prune_oauth_state(tmp_path, 0, now=NOW.timestamp()).removed == 1
    assert not path.exists()


def test_entry_without_any_timestamp_is_kept(tmp_path):
    directory = tmp_path / "mcp-oauth-proxy-clients"
    directory.mkdir()
    path = directory / "bare.json"
    path.write_text(json.dumps({"value": {}}))

    assert prune_oauth_state(tmp_path, 86400, now=NOW.timestamp()).removed == 0
    assert path.exists()


def test_stale_temp_files_are_removed_and_fresh_ones_kept(tmp_path):
    directory = tmp_path / "mcp-jti-mappings"
    directory.mkdir()
    stale = directory / "tmpold.tmp"
    fresh = directory / "tmpnew.tmp"
    stale.write_text("{")
    fresh.write_text("{")
    now = time.time()
    os.utime(stale, (now - 7200, now - 7200))

    assert prune_oauth_state(tmp_path, 0, now=now).removed == 1
    assert not stale.exists()
    assert fresh.exists()


def test_stops_after_first_read_only_error(tmp_path, monkeypatch, caplog):
    directory = tmp_path / "mcp-jti-mappings"
    for index in range(3):
        write_entry(directory, f"expired{index}.json", expires_at=NOW - timedelta(days=1))

    def read_only_unlink(path, *args, **kwargs):
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(os, "unlink", read_only_unlink)

    with caplog.at_level(logging.WARNING, logger="mcp-clickhouse"):
        result = prune_oauth_state(tmp_path, 0, now=NOW.timestamp())

    assert result.removed == 0
    assert len([r for r in caplog.records if "Could not prune" in r.message]) == 1


def test_warns_when_no_entry_has_a_parseable_expiry(tmp_path, monkeypatch, caplog):
    directory = tmp_path / "mcp-jti-mappings"
    for index in range(oauth_state._FORMAT_CHANGE_CANARY_FILES):
        path = directory / f"entry{index}.json"
        directory.mkdir(exist_ok=True)
        path.write_text(json.dumps({"value": {}, "ttl_deadline": "soon"}))

    def stop_after_one_pass(_seconds):
        raise SystemExit

    monkeypatch.setattr(oauth_state.time, "sleep", stop_after_one_pass)

    with caplog.at_level(logging.WARNING, logger="mcp-clickhouse"):
        try:
            oauth_state._prune_forever(tmp_path, 3600, 0)
        except SystemExit:
            pass

    assert any("format may have changed" in record.message for record in caplog.records)
