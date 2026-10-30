#!/usr/bin/env bash
# Run Cowrie natively (no Docker) for local development and simulations.
# Listeners are bound to 127.0.0.1 only: SSH on 2222, Telnet on 2223.
#
#   scripts/honeypot_local.sh start|stop|status|logs
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUNTIME="$ROOT/honeypot/runtime"
VENV="${VENV:-$ROOT/.venv}"
COWRIE="$VENV/bin/cowrie"

prepare() {
  mkdir -p "$RUNTIME/etc" "$RUNTIME/var/log/cowrie" "$RUNTIME/var/lib/cowrie/tty" \
           "$RUNTIME/var/lib/cowrie/downloads" "$RUNTIME/var/run"
  cp "$ROOT/honeypot/cowrie/etc/cowrie.cfg" "$RUNTIME/etc/cowrie.cfg"
  cp "$ROOT/honeypot/cowrie/etc/userdb.txt" "$RUNTIME/etc/userdb.txt"
  "$VENV/bin/python" "$ROOT/honeypot/configuration/build_fs.py" "$RUNTIME/etc/fs.pickle"
}

case "${1:-start}" in
  start)
    [ -x "$COWRIE" ] || { echo "cowrie not installed: $VENV/bin/pip install -r requirements-honeypot.txt"; exit 1; }
    prepare
    cd "$RUNTIME"
    export COWRIE_SSH_LISTEN_ENDPOINTS="tcp:2222:interface=127.0.0.1"
    export COWRIE_TELNET_LISTEN_ENDPOINTS="tcp:2223:interface=127.0.0.1"
    export COWRIE_HONEYPOT_SENSOR_NAME="honeytrap-local"
    export PATH="$VENV/bin:$PATH"
    "$COWRIE" start
    for _ in $(seq 1 30); do
      if nc -z 127.0.0.1 2222 2>/dev/null; then echo "cowrie listening on 127.0.0.1:2222 (ssh) and 127.0.0.1:2223 (telnet)"; exit 0; fi
      sleep 1
    done
    echo "cowrie did not open port 2222; see $RUNTIME/var/log/cowrie/cowrie.log"; exit 1
    ;;
  stop)   cd "$RUNTIME" && "$COWRIE" stop ;;
  status) cd "$RUNTIME" && "$COWRIE" status ;;
  logs)   tail -n 50 "$RUNTIME/var/log/cowrie/cowrie.json" ;;
  *) echo "usage: $0 start|stop|status|logs"; exit 2 ;;
esac
