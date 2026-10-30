"""Parse Cowrie JSON log lines into normalised :class:`Event` records."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from honeytrap.ingestion.redaction import Redactor
from honeytrap.models import EVENT_CATEGORIES, DataOrigin, Event

log = logging.getLogger(__name__)


class ParseError(ValueError):
    pass


def normalise_timestamp(value: str | float | int) -> str:
    """Return an ISO-8601 UTC timestamp with microseconds and a Z suffix."""
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        text = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _int(value) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def parse_record(
    record: dict,
    *,
    origin: DataOrigin | str,
    redactor: Redactor,
    raw_line: str | None = None,
) -> Event:
    """Normalise one decoded Cowrie JSON record."""
    try:
        event_type = record["eventid"]
        src_ip = record["src_ip"]
        timestamp = normalise_timestamp(record["timestamp"])
    except KeyError as exc:
        raise ParseError(f"missing required field {exc}") from exc
    except ValueError as exc:
        raise ParseError(f"bad timestamp: {exc}") from exc

    canonical = raw_line if raw_line is not None else json.dumps(record, sort_keys=True)
    event = Event(
        event_id=hashlib.sha256(canonical.encode()).hexdigest()[:24],
        timestamp=timestamp,
        event_type=event_type,
        category=EVENT_CATEGORIES.get(event_type, "other"),
        session_id=record.get("session"),
        src_ip=src_ip,
        src_port=_int(record.get("src_port")),
        dst_port=_int(record.get("dst_port")),
        protocol=record.get("protocol"),
        sensor=record.get("sensor"),
        data_origin=DataOrigin(origin).value,
        message=(record.get("message") if isinstance(record.get("message"), str) else None),
    )

    if event_type in ("cowrie.login.failed", "cowrie.login.success"):
        username = str(record.get("username", ""))
        password = record.get("password")
        event.username = username
        event.login_success = event_type == "cowrie.login.success"
        if password is not None:
            password = str(password)
            event.password_masked = redactor.mask(password)
            event.password_length = len(password)
            event.password_fingerprint = redactor.fingerprint(password)
            event.credential_fingerprint = redactor.credential_fingerprint(username, password)
        # Cowrie copies the password into the human-readable message; drop it.
        event.message = f"login attempt [{username}/<redacted>] {'succeeded' if event.login_success else 'failed'}"
    elif event_type.startswith("cowrie.command."):
        event.command = record.get("input")
    elif event_type.startswith("cowrie.session.file_"):
        event.url = record.get("url")
        event.file_sha256 = record.get("shasum")
        event.file_path = record.get("destfile") or record.get("filename")
        if event_type == "cowrie.session.file_download" and not event.url and record.get("destfile"):
            # "Saved redir contents": a file written with shell redirection (echo ... > file),
            # not a network transfer. Keep it as evidence but do not treat it as a download.
            event.event_type = "cowrie.session.file_write"
            event.category = "file_write"
        elif event.url is None and record.get("filename"):
            event.url = f"upload:{record['filename']}"
    elif event_type == "cowrie.session.closed":
        try:
            event.duration_seconds = float(record.get("duration"))
        except (TypeError, ValueError):
            pass
    elif event_type == "cowrie.client.version":
        event.client_version = str(record.get("version", ""))[:200]
    elif event_type == "cowrie.client.kex":
        event.hassh = record.get("hassh")
    elif event_type.startswith("cowrie.direct-tcpip."):
        dst = record.get("dst_ip")
        port = record.get("dst_port")
        event.tunnel_destination = f"{dst}:{port}" if dst else None
        event.dst_port = None  # here dst_port is the tunnel target, not our listener
    return event


def parse_lines(
    lines: Iterable[str],
    *,
    origin: DataOrigin | str,
    redactor: Redactor | None = None,
    strict: bool = False,
) -> Iterator[Event]:
    """Parse NDJSON lines; malformed lines are skipped (and counted) unless strict."""
    redactor = redactor or Redactor()
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ParseError("record is not an object")
            yield parse_record(record, origin=origin, redactor=redactor, raw_line=line)
        except (json.JSONDecodeError, ParseError) as exc:
            if strict:
                raise ParseError(str(exc)) from exc
            skipped += 1
    if skipped:
        log.warning("skipped %d malformed line(s)", skipped)
