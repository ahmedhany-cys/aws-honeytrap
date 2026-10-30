"""Read/write events, alerts, enrichment and profiles using the shared key layout."""

from __future__ import annotations

import gzip
import json
import re
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

from honeytrap.models import Alert, DataOrigin, Event
from honeytrap.storage.store import Store

EVENTS_PREFIX = "processed/events/"
ALERTS_PREFIX = "processed/alerts/"
ENRICHMENT_PREFIX = "processed/enrichment/"
PROFILES_PREFIX = "processed/profiles/"

_DT = re.compile(r"/dt=(\d{4}-\d{2}-\d{2})/")
_ORIGIN = re.compile(r"origin=([a-z]+)/")


def origin_from_key(key: str) -> DataOrigin:
    match = _ORIGIN.search(key)
    if not match:
        raise ValueError(f"no origin=<...> partition in key {key!r}")
    return DataOrigin(match.group(1))


def _dates(since: datetime | None, until: datetime | None) -> set[str] | None:
    if since is None:
        return None
    until = until or datetime.now(timezone.utc)
    days, day = set(), since.date()
    while day <= until.date():
        days.add(day.isoformat())
        day += timedelta(days=1)
    return days


def _keys(store: Store, prefix: str, origins: Iterable[str] | None, dates: set[str] | None) -> list[str]:
    keys = []
    for origin in (origins or [o.value for o in DataOrigin]):
        for key in store.list_keys(f"{prefix}origin={origin}/"):
            match = _DT.search(key)
            if dates is not None and (not match or match.group(1) not in dates):
                continue
            keys.append(key)
    return keys


# ----------------------------------------------------------------------------- events

def write_events(store: Store, events: list[Event], batch_id: str) -> list[str]:
    grouped: dict[tuple[str, str], list[Event]] = defaultdict(list)
    for e in events:
        grouped[(e.data_origin, e.timestamp[:10])].append(e)
    keys = []
    for (origin, day), evs in sorted(grouped.items()):
        key = f"{EVENTS_PREFIX}origin={origin}/dt={day}/{batch_id}.json.gz"
        body = "\n".join(json.dumps(e.to_dict(), sort_keys=True) for e in evs) + "\n"
        store.put_bytes(key, gzip.compress(body.encode()), "application/x-ndjson")
        keys.append(key)
    return keys


def read_events(store: Store, *, origins: Iterable[str] | None = None,
                since: datetime | None = None, until: datetime | None = None) -> list[Event]:
    events: dict[str, Event] = {}
    lo = since.strftime("%Y-%m-%dT%H:%M:%S") if since else None
    hi = until.strftime("%Y-%m-%dT%H:%M:%S.999999Z") if until else None
    for key in _keys(store, EVENTS_PREFIX, origins, _dates(since, until)):
        raw = store.get_bytes(key)
        if raw is None:
            continue
        text = gzip.decompress(raw).decode() if key.endswith(".gz") else raw.decode()
        for line in text.splitlines():
            if not line.strip():
                continue
            e = Event.from_dict(json.loads(line))
            if (lo and e.timestamp < lo) or (hi and e.timestamp > hi):
                continue
            events[e.event_id] = e
    return sorted(events.values(), key=lambda e: (e.timestamp, e.event_id))


# ----------------------------------------------------------------------------- alerts

def alert_key(alert: Alert) -> str:
    return f"{ALERTS_PREFIX}origin={alert.data_origin}/dt={alert.first_seen[:10]}/{alert.alert_id}.json"


def write_alert(store: Store, alert: Alert) -> tuple[bool, Alert | None]:
    """Upsert an alert. Returns (is_new, previous_version)."""
    key = alert_key(alert)
    previous_raw = store.get_bytes(key)
    previous = Alert.from_dict(json.loads(previous_raw)) if previous_raw else None
    store.put_bytes(key, json.dumps(alert.to_dict(), sort_keys=True).encode())
    return previous is None, previous


def read_alerts(store: Store, *, origins: Iterable[str] | None = None,
                since: datetime | None = None) -> list[Alert]:
    alerts = []
    for key in _keys(store, ALERTS_PREFIX, origins, _dates(since, None)):
        raw = store.get_bytes(key)
        if raw:
            alerts.append(Alert.from_dict(json.loads(raw)))
    return sorted(alerts, key=lambda a: (a.first_seen, a.rule_id))


# ----------------------------------------------------------------------------- enrichment cache

class StoreCache:
    """Enrichment cache backed by the store (S3 in AWS, a directory locally)."""

    def __init__(self, store: Store) -> None:
        self.store = store

    def _key(self, ip: str) -> str:
        return f"{ENRICHMENT_PREFIX}{ip.replace(':', '_')}.json"

    def get(self, ip: str) -> dict[str, Any] | None:
        raw = self.store.get_bytes(self._key(ip))
        return json.loads(raw) if raw else None

    def put(self, ip: str, value: dict[str, Any]) -> None:
        self.store.put_bytes(self._key(ip), json.dumps(value, sort_keys=True).encode())


def read_enrichment(store: Store) -> dict[str, dict[str, Any]]:
    out = {}
    for key in store.list_keys(ENRICHMENT_PREFIX):
        raw = store.get_bytes(key)
        if raw:
            record = json.loads(raw)
            out[record["ip"]] = record
    return out


# ----------------------------------------------------------------------------- profiles

def write_profiles(store: Store, profiles: list[dict[str, Any]], origin: str) -> str:
    key = f"{PROFILES_PREFIX}origin={origin}/latest.json"
    store.put_bytes(key, json.dumps(profiles, sort_keys=True, default=str).encode())
    return key
