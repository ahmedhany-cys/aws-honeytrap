"""Correlator Lambda: hourly EventBridge schedule.

Re-evaluates the last CORRELATION_HOURS of processed events so threshold rules
see activity that was split across shipper batches, then refreshes attacker
profiles for the dashboard.
"""

from __future__ import annotations

import os

from handlers.bootstrap import context, emit_metrics
from honeytrap.pipeline import correlate


def handler(_event, _context):
    ctx = context()
    result = correlate(ctx["store"], hours=float(os.environ.get("CORRELATION_HOURS", "24")),
                       enrichment=ctx["enrichment"], notifier=ctx["notifier"], lookup_limit=ctx["lookup_limit"])
    emit_metrics("correlator", {"EventsCorrelated": result["events"], "AlertsNew": result["alerts_new"],
                                "Notifications": result["notifications"]})
    return {"status": "ok", **result}
