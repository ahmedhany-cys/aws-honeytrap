import json

import pytest

from honeytrap.ingestion.parser import ParseError, normalise_timestamp, parse_lines, parse_record
from honeytrap.ingestion.redaction import Redactor
from honeytrap.models import DataOrigin


def test_login_failure_is_redacted(log, redactor):
    log.login("root", "S3cretPassw0rd")
    (event,) = log.events(redactor=redactor)
    assert event.event_type == "cowrie.login.failed"
    assert event.category == "authentication"
    assert event.username == "root"
    assert event.login_success is False
    assert event.password_masked == "S************d"
    assert event.password_length == 14
    assert len(event.password_fingerprint) == 16
    dumped = json.dumps(event.to_dict())
    assert "S3cretPassw0rd" not in dumped, "clear-text password must never reach processed data"


def test_cowrie_message_with_password_is_replaced(redactor):
    record = {"eventid": "cowrie.login.success", "timestamp": "2026-10-30T10:00:00Z", "src_ip": "198.51.100.9",
              "session": "x", "username": "root", "password": "hunter2",
              "message": "login attempt [root/hunter2] succeeded"}
    event = parse_record(record, origin="live", redactor=redactor)
    assert "hunter2" not in event.message
    assert event.login_success is True


def test_credential_fingerprint_distinguishes_pairs(redactor):
    assert redactor.credential_fingerprint("root", "a") != redactor.credential_fingerprint("admin", "a")
    assert redactor.credential_fingerprint("root", "a") == redactor.credential_fingerprint("root", "a")


def test_command_download_and_tunnel_events(log, redactor):
    log.cmd("uname -a")
    log.add("cowrie.session.file_download", url="http://198.51.100.1/a.sh", shasum="ab" * 32)
    log.add("cowrie.direct-tcpip.request", dst_ip="198.51.100.10", dst_port=443)
    cmd, dl, tunnel = log.events(redactor=redactor)
    assert cmd.command == "uname -a" and cmd.category == "command"
    assert dl.category == "download" and dl.url.endswith("a.sh") and dl.file_sha256 == "ab" * 32
    assert tunnel.category == "tunnel" and tunnel.tunnel_destination == "198.51.100.10:443"
    assert tunnel.dst_port is None


def test_redirection_write_is_not_a_download(log, redactor):
    log.add("cowrie.session.file_download", destfile="/root/.ssh/authorized_keys", shasum="cd" * 32,
            outfile="var/lib/cowrie/downloads/x")
    (event,) = log.events(redactor=redactor)
    assert event.event_type == "cowrie.session.file_write"
    assert event.category == "file_write"
    assert event.file_path == "/root/.ssh/authorized_keys"
    assert event.url is None


def test_malformed_lines_are_skipped_or_raise(redactor):
    lines = ["not json", "[]", '{"eventid": "cowrie.session.connect"}', "",
             '{"eventid":"cowrie.session.connect","timestamp":"2026-10-30T10:00:00Z","src_ip":"198.51.100.2"}']
    events = list(parse_lines(lines, origin="live", redactor=redactor))
    assert len(events) == 1
    with pytest.raises(ParseError):
        list(parse_lines(lines[:1], origin="live", redactor=redactor, strict=True))


def test_event_id_is_stable_content_hash(log, redactor):
    log.connect()
    a = log.events(redactor=redactor)[0]
    b = log.events(redactor=redactor)[0]
    assert a.event_id == b.event_id


@pytest.mark.parametrize("value,expected", [
    ("2026-10-30T10:00:00Z", "2026-10-30T10:00:00.000000Z"),
    ("2026-10-30T12:00:00+02:00", "2026-10-30T10:00:00.000000Z"),
    ("2026-10-30T10:00:00.5", "2026-10-30T10:00:00.500000Z"),
    (1793354400, "2026-10-30T10:00:00.000000Z"),
])
def test_timestamp_normalisation(value, expected):
    assert normalise_timestamp(value) == expected


def test_origin_label_is_carried(log, redactor):
    log.connect()
    assert log.events(origin="simulation", redactor=redactor)[0].data_origin == DataOrigin.SIMULATION.value
    with pytest.raises(ValueError):
        log.events(origin="production", redactor=redactor)


def test_real_cowrie_fixture_parses_completely(fixture_lines, redactor):
    events = list(parse_lines(fixture_lines, origin="simulation", redactor=redactor))
    assert len(events) == len(fixture_lines)
    assert {e.category for e in events} >= {"connection", "authentication", "command", "tunnel", "file_write"}
    for raw, event in zip(fixture_lines, events, strict=True):
        record = json.loads(raw)
        if "password" in record:
            pw = record["password"]
            values = [str(v) for k, v in event.to_dict().items() if k not in ("username", "message") and v is not None]
            assert pw not in values or len(pw) <= 1
            assert f"/{pw}]" not in (event.message or "")


@pytest.mark.parametrize("value,masked", [("", ""), ("a", "*"), ("ab", "**"), ("abc", "a**"), ("abcd", "a***"),
                                          ("abcde", "a***e"), ("123456", "1****6")])
def test_mask(value, masked):
    assert Redactor.mask(value) == masked


def test_hmac_is_keyed():
    assert Redactor("k1").fingerprint("123456") != Redactor("k2").fingerprint("123456")
