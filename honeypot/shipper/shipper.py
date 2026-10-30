#!/usr/bin/env python3
"""HoneyTrap log shipper - runs on the honeypot HOST (never inside the Cowrie container).

Every run (systemd timer, default 5 min) it uploads, to the telemetry bucket:
  * new complete lines of cowrie.json (and rotated cowrie.json.YYYY-MM-DD files)
      -> raw/origin=<origin>/sensor=<sensor>/dt=<date>/<host>-<epoch>-<seq>.json.gz
  * new TTY session recordings -> evidence/tty/<sensor>/<name>
  * new captured files         -> evidence/files/<sensor>/<sha256>

Design constraints:
  * standard library only + the AWS CLI that ships with Amazon Linux 2023;
  * credentials come from the instance profile via IMDSv2 (hop limit 1, so the
    container cannot reach them);
  * at-least-once delivery: offsets are committed only after a successful
    upload; downstream processing is idempotent (event IDs are content hashes).
"""

from __future__ import annotations

import argparse
import gzip
import json
import logging
import os
import socket
import subprocess  # noqa: S404 - fixed argv, no shell
import sys
import time
from collections.abc import Callable
from pathlib import Path

log = logging.getLogger("honeytrap-shipper")
MAX_CHUNK = 20 * 1024 * 1024

Uploader = Callable[[bytes, str], None]


def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {"logs": {}, "evidence": []}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    os.replace(tmp, path)


def read_new_lines(path: Path, offset: int) -> tuple[bytes, int]:
    """Return complete new lines after offset, and the new offset. A partial last line waits for the next run."""
    size = path.stat().st_size
    if size < offset:  # truncated or replaced
        offset = 0
    with path.open("rb") as fh:
        fh.seek(offset)
        data = fh.read(MAX_CHUNK)
    cut = data.rfind(b"\n")
    if cut < 0:
        return b"", offset
    return data[: cut + 1], offset + cut + 1


def log_files(log_dir: Path) -> list[Path]:
    files = sorted(p for p in log_dir.glob("cowrie.json.*") if not p.name.endswith((".gz", ".tmp")))
    current = log_dir / "cowrie.json"
    return files + ([current] if current.exists() else [])


def ship_logs(log_dir: Path, state: dict, upload: Uploader, *, origin: str, sensor: str, host: str,
              now: Callable[[], float] = time.time) -> int:
    shipped = 0
    for seq, path in enumerate(log_files(log_dir)):
        key_id = f"{path.name}:{path.stat().st_ino}"
        offset = state["logs"].get(key_id, 0)
        chunk, new_offset = read_new_lines(path, offset)
        if not chunk:
            continue
        stamp = now()
        day = time.strftime("%Y-%m-%d", time.gmtime(stamp))
        key = f"raw/origin={origin}/sensor={sensor}/dt={day}/{host}-{int(stamp)}-{seq}.json.gz"
        upload(gzip.compress(chunk), key)
        state["logs"][key_id] = new_offset
        shipped += chunk.count(b"\n")
    live = {f"{p.name}:{p.stat().st_ino}" for p in log_files(log_dir)}
    state["logs"] = {k: v for k, v in state["logs"].items() if k in live}
    return shipped


def ship_evidence(directory: Path, prefix: str, state: dict, upload: Uploader, min_age: float = 60,
                  now: Callable[[], float] = time.time) -> int:
    shipped = 0
    seen = set(state.setdefault("evidence", []))
    if not directory.exists():
        return 0
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name.startswith(".") or str(path) in seen:
            continue
        if now() - path.stat().st_mtime < min_age:  # still being written
            continue
        if path.stat().st_size > MAX_CHUNK:
            log.warning("skipping oversized evidence file %s", path)
            seen.add(str(path))
            continue
        upload(path.read_bytes(), f"{prefix}/{path.name}")
        seen.add(str(path))
        shipped += 1
    state["evidence"] = sorted(seen)[-5000:]
    return shipped


def s3_uploader(bucket: str, aws_cli: str = "aws") -> Uploader:
    def upload(body: bytes, key: str) -> None:
        subprocess.run(  # noqa: S603
            [aws_cli, "s3", "cp", "-", f"s3://{bucket}/{key}", "--sse", "AES256", "--only-show-errors",
             "--content-type", "application/octet-stream"],
            input=body, check=True, timeout=120)
    return upload


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bucket", default=os.environ.get("HONEYTRAP_BUCKET"))
    p.add_argument("--cowrie-var", default=os.environ.get("COWRIE_VAR", "/opt/honeytrap/cowrie/var"))
    p.add_argument("--state", default="/var/lib/honeytrap-shipper/state.json")
    p.add_argument("--origin", default=os.environ.get("HONEYTRAP_ORIGIN", "live"),
                   choices=["live", "simulation"])
    p.add_argument("--sensor", default=os.environ.get("HONEYTRAP_SENSOR", "honeytrap-aws"))
    args = p.parse_args(argv)
    if not args.bucket:
        p.error("--bucket or HONEYTRAP_BUCKET is required")

    var = Path(args.cowrie_var)
    state_path = Path(args.state)
    state = load_state(state_path)
    upload = s3_uploader(args.bucket)
    host = socket.gethostname().split(".")[0]
    try:
        lines = ship_logs(var / "log/cowrie", state, upload, origin=args.origin, sensor=args.sensor, host=host)
        tty = ship_evidence(var / "lib/cowrie/tty", f"evidence/tty/{args.sensor}", state, upload)
        files = ship_evidence(var / "lib/cowrie/downloads", f"evidence/files/{args.sensor}", state, upload)
    finally:
        save_state(state_path, state)
    log.info("shipped %d log lines, %d tty recordings, %d captured files", lines, tty, files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
