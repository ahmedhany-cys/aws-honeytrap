"""End-to-end processing used by both Lambdas and the local CLI.

process_batch  - one new raw Cowrie log object: parse, store, detect, enrich, alert.
correlate      - periodic pass over the last N hours to catch patterns that span batches.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from honeytrap.config import default_config
from honeytrap.detection.engine import apply_enrichment, build_profiles, evaluate, should_notify
from honeytrap.enrichment.service import EnrichmentService
from honeytrap.ingestion.parser import parse_lines
from honeytrap.ingestion.redaction import Redactor
from honeytrap.models import Alert, DataOrigin, Event, Severity
from honeytrap.storage import repository as repo
from honeytrap.storage.store import Store

log = logging.getLogger(__name__)


def _is_self_check(event: Event) -> bool:
    """The sensor's own Docker HEALTHCHECK connects from loopback every 30 s."""
    try:
        return ipaddress.ip_address(event.src_ip).is_loopback
    except ValueError:
        return False


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...


def _enrich_and_store(
    store: Store,
    events: list[Event],
    alerts: list[Alert],
    *,
    config: dict,
    enrichment: EnrichmentService | None,
    notifier: Notifier | None,
    lookup_limit: int,
) -> dict[str, Any]:
    min_sev = Severity.parse(config["enrichment"]["min_severity"])
    ips = sorted({a.src_ip for a in alerts if a.src_ip and a.severity_level >= min_sev})
    enriched = enrichment.enrich_many(ips, limit=lookup_limit) if enrichment else {}
    apply_enrichment(alerts, enriched, config)

    new = updated = notified = 0
    for alert in alerts:
        is_new, previous = repo.write_alert(store, alert)
        if is_new:
            new += 1
        else:
            updated += 1
        crossed = previous is None or previous.severity_level < alert.severity_level
        if notifier and crossed and should_notify(alert, config):
            notifier.notify(alert)
            notified += 1
    return {"alerts_total": len(alerts), "alerts_new": new, "alerts_updated": updated,
            "notifications": notified, "enriched_ips": len(enriched)}


def process_batch(
    store: Store,
    lines: list[str],
    *,
    origin: DataOrigin | str,
    batch_id: str,
    redactor: Redactor | None = None,
    enrichment: EnrichmentService | None = None,
    notifier: Notifier | None = None,
    config: dict | None = None,
    lookup_limit: int = 25,
) -> dict[str, Any]:
    config = config or default_config()
    events = list(parse_lines(lines, origin=origin, redactor=redactor))
    self_checks = 0
    if DataOrigin(origin) is DataOrigin.LIVE:
        # Nothing on the internet reaches a live sensor from loopback; the raw object
        # keeps these lines, the processed views and detections do not.
        kept = [e for e in events if not _is_self_check(e)]
        self_checks, events = len(events) - len(kept), kept
    keys = repo.write_events(store, events, batch_id)
    alerts = evaluate(events, config)
    result = _enrich_and_store(store, events, alerts, config=config, enrichment=enrichment,
                               notifier=notifier, lookup_limit=lookup_limit)
    result.update({"events": len(events), "self_checks_dropped": self_checks, "event_objects": keys,
                   "origin": DataOrigin(origin).value})
    log.info("processed batch %s: %s", batch_id, {k: v for k, v in result.items() if k != "event_objects"})
    return result


def correlate(
    store: Store,
    *,
    hours: float = 24,
    now: datetime | None = None,
    origins: list[str] | None = None,
    enrichment: EnrichmentService | None = None,
    notifier: Notifier | None = None,
    config: dict | None = None,
    lookup_limit: int = 25,
) -> dict[str, Any]:
    config = config or default_config()
    now = now or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)
    events = repo.read_events(store, origins=origins, since=since, until=now)
    alerts = evaluate(events, config)
    result = _enrich_and_store(store, events, alerts, config=config, enrichment=enrichment,
                               notifier=notifier, lookup_limit=lookup_limit)

    # Profiles cover all stored alerts for the window, not only the ones recomputed now.
    all_alerts = [a for a in repo.read_alerts(store, origins=origins, since=since) if a.last_seen >= since.strftime("%Y-%m-%dT%H:%M:%S")]
    enrichment_records = repo.read_enrichment(store)
    profiles = build_profiles(events, all_alerts, enrichment_records)
    for origin in sorted({p["data_origin"] for p in profiles}):
        repo.write_profiles(store, [p for p in profiles if p["data_origin"] == origin], origin)
    result.update({"events": len(events), "profiles": len(profiles), "window_hours": hours})
    log.info("correlation pass: %s", result)
    return result
