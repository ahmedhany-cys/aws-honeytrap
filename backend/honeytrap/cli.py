"""Command-line interface: ``honeytrap <command>`` (or ``python -m honeytrap.cli``)."""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from honeytrap.detection.rules import rule_catalog
from honeytrap.enrichment.service import EnrichmentService
from honeytrap.models import DataOrigin
from honeytrap.notify import LogNotifier
from honeytrap.pipeline import correlate, process_batch
from honeytrap.reporting.report import build_report, render_json, render_markdown
from honeytrap.storage import repository as repo
from honeytrap.storage.store import store_from_uri


def _read_lines(path: Path) -> list[str]:
    data = path.read_bytes()
    if path.suffix == ".gz":
        data = gzip.decompress(data)
    return data.decode("utf-8", "replace").splitlines()


def _enrichment(store, args) -> EnrichmentService | None:
    if getattr(args, "no_enrichment", False):
        return None
    return EnrichmentService(cache=repo.StoreCache(store))


def cmd_ingest(args) -> int:
    store = store_from_uri(args.store)
    origin = DataOrigin(args.origin)
    notifier = LogNotifier()
    total = {"events": 0, "alerts_new": 0}
    for path in args.input:
        lines = _read_lines(Path(path))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        batch_id = args.batch_id or f"{Path(path).name.split('.')[0]}-{stamp}"
        raw_key = f"raw/origin={origin.value}/sensor={args.sensor}/dt={stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}/{batch_id}.json.gz"
        store.put_bytes(raw_key, gzip.compress("\n".join(lines).encode()), "application/x-ndjson")
        result = process_batch(store, lines, origin=origin, batch_id=batch_id,
                               enrichment=_enrichment(store, args), notifier=notifier)
        total["events"] += result["events"]
        total["alerts_new"] += result["alerts_new"]
        print(json.dumps({k: v for k, v in result.items() if k != "event_objects"}))
    if args.correlate:
        print(json.dumps(correlate(store, hours=args.hours, enrichment=_enrichment(store, args), notifier=notifier)))
    print(f"notifications (>= notify threshold): {len(notifier.sent)}")
    return 0


def cmd_correlate(args) -> int:
    store = store_from_uri(args.store)
    origins = [args.origin] if args.origin else None
    print(json.dumps(correlate(store, hours=args.hours, origins=origins,
                               enrichment=_enrichment(store, args), notifier=LogNotifier())))
    return 0


def cmd_synth(args) -> int:
    from honeytrap.synthetic import SENSOR, generate

    store = store_from_uri(args.store)
    lines, enrichment = generate(days=args.days, seed=args.seed)
    cache = repo.StoreCache(store)
    for ip, record in enrichment.items():
        cache.put(ip, record)
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    store.put_bytes(f"raw/origin=synthetic/sensor={SENSOR}/dt={day}/synthetic-seed{args.seed}.json.gz",
                    gzip.compress("\n".join(lines).encode()), "application/x-ndjson")
    result = process_batch(store, lines, origin=DataOrigin.SYNTHETIC, batch_id=f"synthetic-seed{args.seed}",
                           enrichment=None)
    print(json.dumps({k: v for k, v in result.items() if k != "event_objects"}))
    print(json.dumps(correlate(store, hours=args.days * 24 + 24, origins=["synthetic"], enrichment=None)))
    return 0


def cmd_report(args) -> int:
    store = store_from_uri(args.store)
    events = repo.read_events(store)
    alerts = repo.read_alerts(store)
    report = build_report(args.ip, events, alerts, repo.read_enrichment(store))
    text = render_markdown(report) if args.format == "md" else render_json(report)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text)
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def cmd_rules(args) -> int:
    for r in rule_catalog():
        print(f"{r['rule_id']:<12} {r['name']:<45} {', '.join(r['techniques'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = argparse.ArgumentParser(prog="honeytrap", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="process Cowrie JSON log file(s)")
    p.add_argument("--input", nargs="+", required=True)
    p.add_argument("--origin", required=True, choices=[o.value for o in DataOrigin])
    p.add_argument("--store", default="data/local")
    p.add_argument("--sensor", default="local-cowrie")
    p.add_argument("--batch-id")
    p.add_argument("--correlate", action="store_true", help="run a correlation pass afterwards")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--no-enrichment", action="store_true")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("correlate", help="cross-batch correlation over the last N hours")
    p.add_argument("--store", default="data/local")
    p.add_argument("--hours", type=float, default=24)
    p.add_argument("--origin", choices=[o.value for o in DataOrigin])
    p.add_argument("--no-enrichment", action="store_true")
    p.set_defaults(func=cmd_correlate)

    p = sub.add_parser("synth", help="generate and process SYNTHETIC demo data")
    p.add_argument("--store", default="data/demo")
    p.add_argument("--days", type=int, default=7)
    p.add_argument("--seed", type=int, default=1337)
    p.set_defaults(func=cmd_synth)

    p = sub.add_parser("report", help="incident report for one source IP")
    p.add_argument("--store", default="data/local")
    p.add_argument("--ip", required=True)
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.add_argument("--out")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("rules", help="list detection rules")
    p.set_defaults(func=cmd_rules)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
