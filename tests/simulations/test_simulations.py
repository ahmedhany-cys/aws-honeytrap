"""Controlled attack simulations against a running local Cowrie (pytest -m simulation)."""

import os
import socket

import pytest

from tests.simulations.runner import main
from tests.simulations.scenarios import UnauthorizedTarget, assert_authorized_target

pytestmark = pytest.mark.simulation


def _listening(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def test_refuses_public_targets(monkeypatch):
    monkeypatch.delenv("HONEYTRAP_AUTHORIZED_TARGET", raising=False)
    with pytest.raises(UnauthorizedTarget):
        assert_authorized_target("1.1.1.1")
    with pytest.raises(UnauthorizedTarget):
        assert_authorized_target("1.1.1.1", authorized="1.1.1.1")  # flag alone is not enough
    assert_authorized_target("127.0.0.1")
    assert_authorized_target("10.0.0.5")


def test_all_scenarios_trigger_expected_detections(tmp_path):
    if not _listening(int(os.environ.get("HONEYTRAP_SSH_PORT", "2222"))):
        pytest.skip("no honeypot on 127.0.0.1:2222 - run scripts/honeypot_local.sh start or docker compose up")
    log = os.environ.get("HONEYTRAP_COWRIE_LOG", "honeypot/runtime/var/log/cowrie/cowrie.json")
    rc = main(["--log", log, "--store", str(tmp_path / "store"), "--report", str(tmp_path / "results.json")])
    assert rc == 0, (tmp_path / "results.json").read_text()
