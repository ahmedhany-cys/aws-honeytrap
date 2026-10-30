"""Lookup of ATT&CK techniques generated from MITRE's official STIX bundle.

catalog.json is produced by scripts/update_mitre_catalog.py; nothing in it is
typed by hand. A mapping is only produced when a detection supplies evidence.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from honeytrap.models import TechniqueMapping

CATALOG_PATH = Path(__file__).with_name("catalog.json")
CONFIDENCE_LEVELS = ("high", "medium", "low")


@lru_cache(maxsize=1)
def load_catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text())


def attack_version() -> str:
    return load_catalog()["attack_version"]


def get_technique(technique_id: str) -> dict:
    try:
        return load_catalog()["techniques"][technique_id]
    except KeyError as exc:
        raise KeyError(f"{technique_id} is not in the HoneyTrap ATT&CK catalog") from exc


def map_technique(technique_id: str, *, confidence: str, evidence: list[str]) -> TechniqueMapping:
    if confidence not in CONFIDENCE_LEVELS:
        raise ValueError(f"confidence must be one of {CONFIDENCE_LEVELS}")
    if not evidence:
        raise ValueError(f"refusing to map {technique_id} without supporting evidence")
    info = get_technique(technique_id)
    return TechniqueMapping(
        technique_id=technique_id,
        name=info["name"],
        tactics=list(info["tactics"]),
        url=info["url"],
        confidence=confidence,
        evidence=[e[:300] for e in evidence[:10]],
    )
