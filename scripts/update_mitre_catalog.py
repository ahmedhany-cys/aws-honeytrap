#!/usr/bin/env python3
"""Regenerate backend/honeytrap/mitre/catalog.json from the official ATT&CK STIX bundle.

The detection engine only maps behaviour to the techniques listed in TECHNIQUES
below. Names, tactics and descriptions are pulled from MITRE's published STIX
data instead of being typed by hand, and the script fails loudly if any ID has
been revoked or deprecated (ATT&CK v20 revoked T1562.004, for example).

Usage:
    curl -sSL -o /tmp/enterprise-attack.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python scripts/update_mitre_catalog.py /tmp/enterprise-attack.json
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

TECHNIQUES = [
    "T1003.008", "T1016", "T1018", "T1033", "T1037.004", "T1046", "T1049", "T1053.003",
    "T1057", "T1059.004", "T1070.003", "T1070.004", "T1078", "T1078.001", "T1082",
    "T1083", "T1087.001", "T1090", "T1098", "T1098.004", "T1105", "T1110", "T1110.001",
    "T1110.003", "T1110.004", "T1136.001", "T1140", "T1222.002", "T1496.001", "T1518.001",
    "T1531", "T1543.002", "T1552.001", "T1572", "T1595", "T1685", "T1686", "T1690",
]

OUT = Path(__file__).resolve().parents[1] / "backend" / "honeytrap" / "mitre" / "catalog.json"


def first_sentence(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    text = re.sub(r"</?code>", "", text)
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = " ".join(text.split())
    match = re.match(r"(.+?\.)(\s|$)", text)
    return (match.group(1) if match else text)[:400]


def main(bundle_path: str) -> int:
    bundle = json.loads(Path(bundle_path).read_text())
    objects = bundle["objects"]
    tactics = {o["x_mitre_shortname"]: o["name"] for o in objects if o.get("type") == "x-mitre-tactic"}
    version = next(o["x_mitre_version"] for o in objects if o.get("type") == "x-mitre-collection")

    found: dict[str, dict] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or ref["external_id"] not in TECHNIQUES:
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            print(f"ERROR: {ref['external_id']} is revoked or deprecated in ATT&CK {version}", file=sys.stderr)
            return 1
        found[ref["external_id"]] = {
            "id": ref["external_id"],
            "name": obj["name"],
            "tactics": [tactics[p["phase_name"]] for p in obj.get("kill_chain_phases", [])],
            "url": ref["url"],
            "description": first_sentence(obj.get("description", "")),
        }

    missing = sorted(set(TECHNIQUES) - set(found))
    if missing:
        print(f"ERROR: not found in ATT&CK {version}: {missing}", file=sys.stderr)
        return 1

    catalog = {
        "attack_version": version,
        "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack)",
        "attribution": "MITRE ATT&CK(R) content (c) The MITRE Corporation, reproduced under the ATT&CK Terms of Use.",
        "techniques": dict(sorted(found.items())),
    }
    OUT.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"wrote {len(found)} techniques from ATT&CK {version} to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
