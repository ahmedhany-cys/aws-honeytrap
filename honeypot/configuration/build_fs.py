#!/usr/bin/env python3
"""Build the decoy filesystem (fs.pickle) for the fictional Northwind Freight database server.

Starts from Cowrie's bundled Debian 12 pickle and layers on a believable
persona: hostname, a 'deploy' user, an application directory with decoy config
and shell history. Every "secret" written here is a documented decoy value
(see docs/security.md) and is not valid anywhere. Contents live inside the
pickle, so nothing touches the real host filesystem.

Usage: python honeypot/configuration/build_fs.py <output fs.pickle>
"""

from __future__ import annotations

import os
import pickle  # noqa: S403 - Cowrie's own trusted fs.pickle format
import sys
import time

import cowrie.data

T_DIR, T_FILE = 1, 2
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS = range(8)
NOW = int(time.time()) - 86400 * 41  # files look ~6 weeks old

HOSTNAME = "nwf-db-prod-02"

DECOY_FILES: dict[str, tuple[int, int, int, str]] = {
    # path: (uid, gid, mode, contents)
    "/etc/hostname": (0, 0, 0o100644, f"{HOSTNAME}\n"),
    "/etc/motd": (0, 0, 0o100644,
                  "\nNorthwind Freight - Billing Database (PROD)\n"
                  "Authorised access only. Activity is monitored.\n"
                  "Change ticket required for any maintenance: https://itsm.northwind-freight.example/\n\n"),
    "/etc/issue.net": (0, 0, 0o100644, "Debian GNU/Linux 12\n"),
    "/opt/nwf-billing/config/app.env": (1000, 1000, 0o100640,
        "# Northwind billing API - production\n"
        "APP_ENV=production\n"
        "DB_HOST=10.42.3.15\n"
        "DB_PORT=5432\n"
        "DB_NAME=billing\n"
        "DB_USER=billing_app\n"
        "DB_PASSWORD=decoy-nwf-billing-0000\n"   # decoy, not valid anywhere
        "S3_EXPORT_BUCKET=nwf-billing-exports-prod\n"
        "INVOICE_SIGNING_KEY=decoy-signing-key-0000\n"),  # decoy
    "/opt/nwf-billing/README.md": (1000, 1000, 0o100644,
        "# nwf-billing\n\nInvoice batch exporter. Runs nightly from cron as `deploy`.\n"
        "Restart: `sudo systemctl restart nwf-billing`\n"),
    "/opt/nwf-billing/bin/export.sh": (1000, 1000, 0o100755,
        "#!/bin/bash\nset -euo pipefail\nsource /opt/nwf-billing/config/app.env\n"
        "pg_dump -h \"$DB_HOST\" -U \"$DB_USER\" \"$DB_NAME\" | gzip > /var/backups/billing-$(date +%F).sql.gz\n"),
    "/root/.bash_history": (0, 0, 0o100600,
        "apt update && apt -y upgrade\nsystemctl status postgresql\njournalctl -u nwf-billing --since today\n"
        "df -h\ncd /opt/nwf-billing && git pull\nsystemctl restart nwf-billing\nexit\n"),
    "/home/deploy/.bash_history": (1000, 1000, 0o100600,
        "cd /opt/nwf-billing\n./bin/export.sh\nls -la /var/backups\npsql -h 10.42.3.15 -U billing_app billing\nexit\n"),
}

DECOY_DIRS = ["/opt/nwf-billing", "/opt/nwf-billing/config", "/opt/nwf-billing/bin", "/home/deploy/.ssh",
              "/var/backups"]


def _children(node):
    return node[A_CONTENTS]


def _find(root, path):
    node = root
    for part in [p for p in path.split("/") if p]:
        node = next((c for c in _children(node) if c[A_NAME] == part), None)
        if node is None:
            return None
    return node


def _mkdir(root, path, uid=0, gid=0):
    node = root
    for part in [p for p in path.split("/") if p]:
        child = next((c for c in _children(node) if c[A_NAME] == part), None)
        if child is None:
            child = [part, T_DIR, uid, gid, 4096, 0o40755, NOW, [], None, None]
            _children(node).append(child)
        node = child
    return node


def _write(root, path, uid, gid, mode, text):
    parent_path, name = path.rsplit("/", 1)
    parent = _mkdir(root, parent_path or "/")
    data = text.encode()
    existing = next((c for c in _children(parent) if c[A_NAME] == name), None)
    entry = [name, T_FILE, uid, gid, len(data), mode, NOW, data, None, None]
    if existing is not None:
        _children(parent).remove(existing)
    _children(parent).append(entry)


def build(output: str) -> None:
    source = os.path.join(os.path.dirname(cowrie.data.__file__), "fs.pickle")
    with open(source, "rb") as fh:
        root = pickle.load(fh)  # noqa: S301 - Cowrie's bundled, trusted file

    phil = _find(root, "/home/phil")
    if phil is not None:
        phil[A_NAME] = "deploy"
    for d in DECOY_DIRS:
        owner = 1000 if d.startswith(("/opt", "/home")) else 0
        _mkdir(root, d, owner, owner)

    passwd = _find(root, "/etc/passwd")[A_CONTENTS].decode()
    passwd = passwd.replace("phil:x:1000:1000:Phil California,,,:/home/phil:/bin/bash",
                            "deploy:x:1000:1000:Deploy User,,,:/home/deploy:/bin/bash")
    if "postgres:" not in passwd:
        passwd += "postgres:x:110:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash\n"
    DECOY_FILES["/etc/passwd"] = (0, 0, 0o100644, passwd)

    for path, (uid, gid, mode, text) in DECOY_FILES.items():
        _write(root, path, uid, gid, mode, text)

    with open(output, "wb") as fh:
        pickle.dump(root, fh)
    print(f"wrote {output} ({len(DECOY_FILES)} decoy files, hostname {HOSTNAME})")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "fs.pickle")
