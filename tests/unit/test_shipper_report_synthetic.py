import gzip
import ipaddress
import json
import os
import time

import pytest
import shipper

from honeytrap.detection.engine import evaluate
from honeytrap.ingestion.parser import parse_lines
from honeytrap.reporting.report import build_report, render_markdown
from honeytrap.synthetic import generate

# ----------------------------------------------------------------- shipper


def test_read_new_lines_holds_back_partial_line(tmp_path):
    f = tmp_path / "cowrie.json"
    f.write_bytes(b'{"a":1}\n{"b":2}\n{"c":')
    chunk, offset = shipper.read_new_lines(f, 0)
    assert chunk == b'{"a":1}\n{"b":2}\n' and offset == len(chunk)
    with f.open("ab") as fh:
        fh.write(b"3}\n")
    chunk, offset2 = shipper.read_new_lines(f, offset)
    assert chunk == b'{"c":3}\n'


def test_read_new_lines_handles_truncation(tmp_path):
    f = tmp_path / "cowrie.json"
    f.write_bytes(b"x\n")
    chunk, offset = shipper.read_new_lines(f, 500)
    assert chunk == b"x\n" and offset == 2


def test_ship_logs_uploads_once_with_partitioned_key(tmp_path):
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    (log_dir / "cowrie.json.2026-10-29").write_bytes(b'{"old":1}\n')
    (log_dir / "cowrie.json").write_bytes(b'{"new":1}\n{"new":2}\n')
    uploads = []
    state = {"logs": {}, "evidence": []}

    def upload(body, key):
        uploads.append((key, gzip.decompress(body)))

    n = shipper.ship_logs(log_dir, state, upload, origin="live", sensor="s1", host="h", now=lambda: 1793354400)
    assert n == 3 and len(uploads) == 2
    assert all(k.startswith("raw/origin=live/sensor=s1/dt=2026-10-30/h-1793354400-") for k, _ in uploads)
    assert shipper.ship_logs(log_dir, state, upload, origin="live", sensor="s1", host="h") == 0
    assert len(uploads) == 2


def test_failed_upload_does_not_advance_offset(tmp_path):
    log_dir = tmp_path / "log"
    log_dir.mkdir()
    (log_dir / "cowrie.json").write_bytes(b'{"a":1}\n')
    state = {"logs": {}, "evidence": []}

    def broken(body, key):
        raise RuntimeError("network")

    with pytest.raises(RuntimeError):
        shipper.ship_logs(log_dir, state, broken, origin="live", sensor="s", host="h")
    assert state["logs"] == {}


def test_ship_evidence_waits_for_file_to_settle(tmp_path):
    tty = tmp_path / "tty"
    tty.mkdir()
    f = tty / "abc"
    f.write_bytes(b"rec")
    uploads, state = [], {"logs": {}, "evidence": []}
    up = lambda body, key: uploads.append(key)  # noqa: E731
    assert shipper.ship_evidence(tty, "evidence/tty/s", state, up, min_age=60) == 0
    old = time.time() - 120
    os.utime(f, (old, old))
    assert shipper.ship_evidence(tty, "evidence/tty/s", state, up, min_age=60) == 1
    assert shipper.ship_evidence(tty, "evidence/tty/s", state, up, min_age=60) == 0
    assert uploads == ["evidence/tty/s/abc"]


def test_state_roundtrip(tmp_path):
    path = tmp_path / "state" / "s.json"
    shipper.save_state(path, {"logs": {"a": 1}, "evidence": []})
    assert shipper.load_state(path)["logs"] == {"a": 1}
    assert shipper.load_state(tmp_path / "missing.json") == {"logs": {}, "evidence": []}


# ----------------------------------------------------------------- report


def test_report_is_labelled_and_redacted(fixture_lines, redactor):
    events = list(parse_lines(fixture_lines, origin="simulation", redactor=redactor))
    alerts = evaluate(events)
    report = build_report("127.0.0.1", events, alerts)
    md = render_markdown(report)
    assert "SIMULATION" in md and "Not real attacker activity" in md
    assert "hunter2" not in md and "Welcome2026!" not in md
    assert "T1105" in md and "Ingress Tool Transfer" in md
    assert report["profile"]["actor_type"] == "Malware dropper / bot loader"
    assert "http://198.51.100.23/bins/x86_64" in report["iocs"]["urls"]


def test_report_unknown_ip(fixture_lines, redactor):
    events = list(parse_lines(fixture_lines, origin="simulation", redactor=redactor))
    with pytest.raises(ValueError):
        build_report("203.0.113.250", events, [])


# ----------------------------------------------------------------- synthetic data


def test_synthetic_is_deterministic_and_safe():
    from datetime import datetime, timezone

    now = datetime(2026, 10, 30, tzinfo=timezone.utc)
    lines_a, enr_a = generate(days=2, seed=7, now=now)
    lines_b, _ = generate(days=2, seed=7, now=now)
    assert lines_a == lines_b
    docs = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for line in lines_a:
        rec = json.loads(line)
        assert any(ipaddress.ip_address(rec["src_ip"]) in n for n in docs)
        for url in [rec.get("url")] if rec.get("url") else []:
            assert "198.51.100." in url
    assert all(r["status"] == "synthetic" for r in enr_a.values())
    assert all(not ipaddress.ip_address(ip).is_global for ip in enr_a)
