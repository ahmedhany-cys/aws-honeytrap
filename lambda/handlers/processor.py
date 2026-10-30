"""Processor Lambda: triggered by EventBridge when the shipper uploads a raw Cowrie log batch.

S3 (raw/origin=<o>/...) --Object Created--> EventBridge --> this function
    -> parse + redact -> processed/events -> detection -> enrichment -> processed/alerts -> SNS
"""

from __future__ import annotations

import gzip
import logging
import urllib.parse

from handlers.bootstrap import context, emit_metrics
from honeytrap.pipeline import process_batch
from honeytrap.storage.repository import origin_from_key

log = logging.getLogger()

MAX_OBJECT_BYTES = 50 * 1024 * 1024  # refuse to load anything unexpectedly large into memory


def handler(event, _context):
    ctx = context()
    detail = event.get("detail", {})
    bucket = detail.get("bucket", {}).get("name")
    key = urllib.parse.unquote_plus(detail.get("object", {}).get("key", ""))
    size = int(detail.get("object", {}).get("size", 0) or 0)

    if bucket != ctx["bucket"] or not key.startswith("raw/"):
        log.warning("ignoring object outside raw/ in the telemetry bucket: s3://%s/%s", bucket, key)
        return {"status": "ignored"}
    if size > MAX_OBJECT_BYTES:
        log.error("object too large (%d bytes): %s", size, key)
        return {"status": "rejected", "reason": "too large"}

    origin = origin_from_key(key)
    body = ctx["store"].get_bytes(key)
    if body is None:
        return {"status": "missing"}
    if key.endswith(".gz"):
        body = gzip.decompress(body)
    lines = body.decode("utf-8", "replace").splitlines()
    batch_id = key.rsplit("/", 1)[-1].split(".")[0]

    result = process_batch(ctx["store"], lines, origin=origin, batch_id=batch_id, redactor=ctx["redactor"],
                           enrichment=ctx["enrichment"], notifier=ctx["notifier"],
                           lookup_limit=ctx["lookup_limit"])
    emit_metrics("processor", {"EventsProcessed": result["events"], "AlertsNew": result["alerts_new"],
                               "Notifications": result["notifications"]})
    return {"status": "ok", **{k: v for k, v in result.items() if k != "event_objects"}}
