"""Ingestion -> storage -> detection -> alert storage -> correlation, on the local store."""

import gzip
import json
from datetime import datetime, timezone

import pytest

from honeytrap.models import DataOrigin
from honeytrap.notify import LogNotifier
from honeytrap.pipeline import correlate, process_batch
from honeytrap.storage import repository as repo
from honeytrap.storage.store import LocalStore


@pytest.fixture
def store(tmp_path):
    return LocalStore(tmp_path / "store")


def test_process_batch_end_to_end(store, fixture_lines, redactor):
    notifier = LogNotifier()
    result = process_batch(store, fixture_lines, origin=DataOrigin.SIMULATION, batch_id="b1", redactor=redactor,
                           notifier=notifier)
    assert result["events"] == len(fixture_lines)
    assert result["alerts_new"] == result["alerts_total"] > 0
    keys = list(store.list_keys("processed/events/origin=simulation/"))
    assert keys and keys[0].endswith("b1.json.gz")
    stored = gzip.decompress(store.get_bytes(keys[0])).decode()
    assert "hunter2" not in stored, "processed layer must not contain clear-text passwords"

    alerts = repo.read_alerts(store)
    assert {a.rule_id for a in alerts} >= {"HT-AUTH-001", "HT-AUTH-006", "HT-DL-002", "HT-NET-003"}
    assert all(a.data_origin == "simulation" for a in alerts)
    assert {a.rule_id for a in notifier.sent} >= {"HT-DL-001", "HT-DL-002", "HT-CMD-003"}
    assert all(a.severity in ("High", "Critical") for a in notifier.sent)


def test_reprocessing_is_idempotent(store, fixture_lines, redactor):
    process_batch(store, fixture_lines, origin="simulation", batch_id="b1", redactor=redactor)
    notifier = LogNotifier()
    again = process_batch(store, fixture_lines, origin="simulation", batch_id="b1", redactor=redactor,
                          notifier=notifier)
    assert again["alerts_new"] == 0 and again["alerts_updated"] == again["alerts_total"]
    assert notifier.sent == [], "unchanged alerts must not re-notify"
    assert len(repo.read_events(store)) == len(fixture_lines)


def test_correlation_spans_batches(store, log, redactor):
    for i in range(6):
        log.login("root", f"a{i}")
    first = log.lines()
    for i in range(6):
        log.login("root", f"b{i}")
    second = log.lines()[6:]
    process_batch(store, first, origin="live", batch_id="p1", redactor=redactor)
    process_batch(store, second, origin="live", batch_id="p2", redactor=redactor)
    # Each batch alone has 6 failures, below the threshold of 10.
    assert not any(a.rule_id == "HT-AUTH-001" for a in repo.read_alerts(store))
    result = correlate(store, hours=48, now=datetime(2026, 10, 30, 13, tzinfo=timezone.utc))
    assert result["events"] == 12
    bf = [a for a in repo.read_alerts(store) if a.rule_id == "HT-AUTH-001"]
    assert len(bf) == 1 and bf[0].evidence["failed_logins"] == 12
    profiles = json.loads(store.get_bytes("processed/profiles/origin=live/latest.json"))
    assert profiles[0]["src_ip"] == "203.0.113.5" and profiles[0]["failed_logins"] == 12


def test_local_store_rejects_path_traversal(store):
    with pytest.raises(ValueError):
        store.put_bytes("../../etc/evil", b"x")


def test_origin_from_key():
    assert repo.origin_from_key("raw/origin=live/sensor=a/dt=2026-10-30/x.json.gz") == DataOrigin.LIVE
    with pytest.raises(ValueError):
        repo.origin_from_key("raw/sensor=a/x.json")
    with pytest.raises(ValueError):
        repo.origin_from_key("raw/origin=prod/x.json")


def test_live_batches_drop_sensor_self_checks(store, redactor):
    from tests.conftest import CowrieLog

    log = CowrieLog()
    for i in range(40):  # the Docker HEALTHCHECK, every 30 s
        log.connect(ip="127.0.0.1", session=f"hc{i}", seconds=30)
    log.connect(ip="203.0.113.9", session="a1")
    log.login("root", "123456", ip="203.0.113.9", session="a1")
    live = process_batch(store, log.lines(), origin=DataOrigin.LIVE, batch_id="live", redactor=redactor)
    assert live["events"] == 2 and live["self_checks_dropped"] == 40
    assert {e.src_ip for e in repo.read_events(store, origins=["live"])} == {"203.0.113.9"}
    assert not any(a.src_ip == "127.0.0.1" for a in repo.read_alerts(store))
    # Simulations legitimately come from loopback and are kept.
    sim = process_batch(store, log.lines(), origin=DataOrigin.SIMULATION, batch_id="sim", redactor=redactor)
    assert sim["self_checks_dropped"] == 0 and sim["events"] == 42
