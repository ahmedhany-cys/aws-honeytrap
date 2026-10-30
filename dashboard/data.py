"""Data access for the dashboard. Reads the same store layout the Lambdas write.

HONEYTRAP_DATA is a comma-separated list of stores (local directories or
s3://bucket). Default: the local simulation store and the synthetic demo store.
Nothing here fabricates numbers: every figure on the dashboard is computed from
these stores, and every row carries its data_origin.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from honeytrap.detection.engine import build_profiles  # noqa: E402
from honeytrap.enrichment.service import summarise  # noqa: E402
from honeytrap.models import Alert, Event, Severity  # noqa: E402
from honeytrap.reporting.pseudonymize import IPPseudonymizer  # noqa: E402
from honeytrap.storage import repository as repo  # noqa: E402
from honeytrap.storage.store import LocalStore, store_from_uri  # noqa: E402

DEFAULT_STORES = "data/simulation,data/demo"
SEVERITY_ORDER = [s.label for s in Severity]  # Informational .. Critical
ORIGIN_LABEL = {"live": "LIVE", "simulation": "SIMULATION", "synthetic": "SYNTHETIC DEMO"}


@dataclass
class Dataset:
    events: pd.DataFrame
    alerts: pd.DataFrame
    alert_objects: list
    event_objects: list
    profiles: pd.DataFrame
    enrichment: dict
    sources: list[str]
    redacted: bool = False


def _resolve(uri: str):
    uri = uri.strip()
    if uri.startswith("s3://"):
        return store_from_uri(uri)
    path = Path(uri)
    return LocalStore(path if path.is_absolute() else ROOT / path)


def load(stores: str | None = None) -> Dataset:
    uris = [u for u in (stores or os.environ.get("HONEYTRAP_DATA", DEFAULT_STORES)).split(",") if u.strip()]
    events, alerts, enrichment = [], [], {}
    for uri in uris:
        store = _resolve(uri)
        events += repo.read_events(store)
        alerts += repo.read_alerts(store)
        enrichment.update(repo.read_enrichment(store))

    redacted = os.environ.get("HONEYTRAP_REDACT_IPS", "").lower() in ("1", "true", "yes")
    if redacted:
        # Public attacker IPs are personal data in some jurisdictions; pseudonymise before display.
        p = IPPseudonymizer()
        events = [Event.from_dict(p.obj(e.to_dict())) for e in events]
        alerts = [Alert.from_dict(p.obj(a.to_dict())) for a in alerts]
        enrichment = p.obj(enrichment)

    ev = pd.DataFrame([e.to_dict() for e in events])
    if not ev.empty:
        ev["ts"] = pd.to_datetime(ev["timestamp"], utc=True, format="ISO8601")
    al = pd.DataFrame([{**a.to_dict(), "techniques": [t.technique_id for t in a.techniques],
                        "technique_names": [f"{t.technique_id} {t.name}" for t in a.techniques]} for a in alerts])
    if not al.empty:
        al["ts"] = pd.to_datetime(al["first_seen"], utc=True, format="ISO8601")
        al["severity"] = pd.Categorical(al["severity"], categories=SEVERITY_ORDER, ordered=True)
        al["ip_or_related"] = al.apply(lambda r: r["src_ip"] or ", ".join(r["related_ips"][:3]), axis=1)

    profiles = pd.DataFrame(build_profiles(events, alerts, enrichment))
    return Dataset(events=ev, alerts=al, alert_objects=alerts, event_objects=events, profiles=profiles,
                   enrichment=enrichment, sources=uris, redacted=redacted)


def enrichment_frame(enrichment: dict) -> pd.DataFrame:
    rows = [{"src_ip": ip, **summarise(rec)} for ip, rec in enrichment.items()]
    return pd.DataFrame(rows)


def filter_events(df: pd.DataFrame, f: dict) -> pd.DataFrame:
    if df.empty:
        return df
    mask = df["data_origin"].isin(f["origins"])
    mask &= (df["ts"].dt.date >= f["start"]) & (df["ts"].dt.date <= f["end"])
    if f["ip"]:
        mask &= df["src_ip"].str.contains(f["ip"], regex=False)
    if f["event_types"]:
        mask &= df["event_type"].isin(f["event_types"])
    return df[mask]


def filter_alerts(df: pd.DataFrame, f: dict) -> pd.DataFrame:
    if df.empty:
        return df
    mask = df["data_origin"].isin(f["origins"])
    mask &= (df["ts"].dt.date >= f["start"]) & (df["ts"].dt.date <= f["end"])
    if f["ip"]:
        mask &= df["src_ip"].fillna("").str.contains(f["ip"], regex=False) | \
            df["related_ips"].apply(lambda ips: any(f["ip"] in ip for ip in ips))
    if f["severities"]:
        mask &= df["severity"].astype(str).isin(f["severities"])
    if f["classifications"]:
        mask &= df["classification"].isin(f["classifications"])
    return df[mask]
