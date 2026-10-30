"""Detection configuration: packaged defaults merged with an optional TOML override file."""

from __future__ import annotations

import copy
import os
import tomllib
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULTS_PATH = Path(__file__).parent / "detection" / "thresholds.toml"
ENV_VAR = "HONEYTRAP_DETECTION_CONFIG"


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(override_path: str | os.PathLike | None = None) -> dict[str, Any]:
    with DEFAULTS_PATH.open("rb") as fh:
        config = tomllib.load(fh)
    path = override_path or os.environ.get(ENV_VAR)
    if path:
        with Path(path).open("rb") as fh:
            config = _deep_merge(config, tomllib.load(fh))
    return config


@lru_cache(maxsize=1)
def default_config() -> dict[str, Any]:
    return load_config()
