"""Run simulation scenarios against a local honeypot and verify the expected detections fire.

    python -m tests.simulations.runner --log honeypot/runtime/var/log/cowrie/cowrie.json

Every captured event is labelled data_origin=simulation.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from honeytrap.detection.engine import evaluate  # noqa: E402
from honeytrap.ingestion.parser import parse_lines  # noqa: E402
from honeytrap.models import DataOrigin  # noqa: E402
from honeytrap.notify import LogNotifier  # noqa: E402
from honeytrap.pipeline import correlate, process_batch  # noqa: E402
from honeytrap.storage.store import LocalStore  # noqa: E402
from tests.simulations.scenarios import SCENARIOS, Target, assert_authorized_target  # noqa: E402


def _read_from(path: Path, offset: int) -> tuple[list[str], int]:
    with path.open("rb") as fh:
        fh.seek(offset)
        data = fh.read()
    return data.decode("utf-8", "replace").splitlines(), offset + len(data)


def run(args) -> dict:
    assert_authorized_target(args.host, args.authorized_target)
    log_path = Path(args.log)
    selected = [s for s in SCENARIOS if not args.only or s.name in args.only]
    linux = platform.system() == "Linux"
    results, all_lines = [], []
    offset = log_path.stat().st_size if log_path.exists() else 0

    for scenario in selected:
        target = Target(host=args.host, ssh_port=args.ssh_port, telnet_port=args.telnet_port,
                        source_address=f"127.0.0.{scenario.source_suffix}" if linux and args.host == "127.0.0.1" else None)
        started = datetime.now(timezone.utc)
        error = None
        try:
            scenario.run(target)
        except Exception as exc:  # noqa: BLE001 - record and continue with the next scenario
            error = f"{type(exc).__name__}: {exc}"
        time.sleep(args.settle)
        lines, offset = _read_from(log_path, offset)
        all_lines += lines
        events = list(parse_lines(lines, origin=DataOrigin.SIMULATION))
        alerts = evaluate(events)
        fired = sorted({a.rule_id for a in alerts})
        techniques = sorted({t.technique_id for a in alerts for t in a.techniques})
        missing_rules = sorted(set(scenario.expected_rules) - set(fired))
        missing_techniques = sorted(set(scenario.expected_techniques) - set(techniques))
        passed = not missing_rules and not missing_techniques and error is None
        results.append({
            "scenario": scenario.name, "title": scenario.title, "description": scenario.description,
            "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "events_captured": len(events),
            "event_types": sorted({e.event_type for e in events}),
            "source_ips": sorted({e.src_ip for e in events}),
            "expected_rules": scenario.expected_rules, "fired_rules": fired,
            "expected_techniques": scenario.expected_techniques, "mapped_techniques": techniques,
            "missing_rules": missing_rules, "missing_techniques": missing_techniques,
            "alerts": [{"rule_id": a.rule_id, "severity": a.severity, "summary": a.summary} for a in alerts],
            "error": error, "passed": passed,
        })
        print(f"[{'PASS' if passed else 'FAIL'}] {scenario.name:<20} events={len(events):<4} fired={','.join(fired)}"
              + (f" missing={missing_rules + missing_techniques}" if not passed else "") + (f" error={error}" if error else ""))

    if args.store and all_lines:
        store = LocalStore(args.store)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        process_batch(store, all_lines, origin=DataOrigin.SIMULATION, batch_id=f"simulation-{stamp}",
                      notifier=LogNotifier())
        correlate(store, hours=24 * 30, origins=["simulation"])

    summary = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "data_origin": "simulation",
        "target": f"{args.host}:{args.ssh_port}/{args.telnet_port}",
        "platform": platform.platform(),
        "passed": sum(r["passed"] for r in results), "total": len(results), "scenarios": results,
    }
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--ssh-port", type=int, default=2222)
    p.add_argument("--telnet-port", type=int, default=2223)
    p.add_argument("--log", default=str(ROOT / "honeypot/runtime/var/log/cowrie/cowrie.json"))
    p.add_argument("--store", default=str(ROOT / "data/simulation"))
    p.add_argument("--report", default=str(ROOT / "docs/evidence/simulation-results.json"))
    p.add_argument("--only", nargs="*")
    p.add_argument("--settle", type=float, default=2.0, help="seconds to wait for Cowrie to flush its log")
    p.add_argument("--authorized-target", help="non-private host you own; must also be set in HONEYTRAP_AUTHORIZED_TARGET")
    summary = run(p.parse_args(argv))
    print(f"{summary['passed']}/{summary['total']} scenarios passed")
    return 0 if summary["passed"] == summary["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
