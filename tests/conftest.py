from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "backend", ROOT / "lambda", ROOT / "dashboard", ROOT / "honeypot" / "shipper", ROOT):
    sys.path.insert(0, str(p))

from honeytrap.config import load_config  # noqa: E402
from honeytrap.ingestion.parser import parse_lines  # noqa: E402
from honeytrap.ingestion.redaction import Redactor  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "cowrie-simulation-sample.json"
BASE = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def redactor() -> Redactor:
    return Redactor("unit-test-key")


@pytest.fixture
def config() -> dict:
    return load_config()


@pytest.fixture
def fixture_lines() -> list[str]:
    return FIXTURE.read_text().splitlines()


class CowrieLog:
    """Builds Cowrie-format JSON lines for tests."""

    def __init__(self) -> None:
        self.records: list[dict] = []
        self.t = BASE

    def add(self, eventid: str, ip: str = "203.0.113.5", session: str = "s1", seconds: float = 1.0, **fields) -> dict:
        self.t += timedelta(seconds=seconds)
        rec = {"eventid": eventid, "timestamp": self.t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "src_ip": ip,
               "session": session, "sensor": "test", "protocol": fields.pop("protocol", "ssh"), **fields}
        self.records.append(rec)
        return rec

    def connect(self, ip="203.0.113.5", session="s1", **kw):
        return self.add("cowrie.session.connect", ip, session, src_port=40000, dst_port=2222, **kw)

    def login(self, user, password, ok=False, ip="203.0.113.5", session="s1", **kw):
        return self.add("cowrie.login.success" if ok else "cowrie.login.failed", ip, session,
                        username=user, password=password, **kw)

    def cmd(self, command, ip="203.0.113.5", session="s1", **kw):
        return self.add("cowrie.command.input", ip, session, input=command, **kw)

    def lines(self) -> list[str]:
        return [json.dumps(r) for r in self.records]

    def events(self, origin="live", redactor=None):
        return list(parse_lines(self.lines(), origin=origin, redactor=redactor or Redactor("unit-test-key")))


@pytest.fixture
def log() -> CowrieLog:
    return CowrieLog()
