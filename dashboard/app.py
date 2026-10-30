"""AWS HoneyTrap - security dashboard.

    streamlit run dashboard/app.py
    HONEYTRAP_DATA=s3://<telemetry-bucket> streamlit run dashboard/app.py   # deployed data
"""

from __future__ import annotations

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent))

import data  # noqa: E402
import ui  # noqa: E402
from views import attack_intel, detections, evidence, investigation, mitre, overview, platform  # noqa: E402

st.set_page_config(page_title="HoneyTrap | Threat Intelligence", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="expanded")
st.markdown(ui.CSS, unsafe_allow_html=True)


@st.cache_data(ttl=300, show_spinner="Loading telemetry…")
def _load(stores: str | None):
    return data.load(stores)


ds = _load(None)

# ------------------------------------------------------------------ global filters
with st.sidebar:
    st.markdown("### 🛡️ AWS HoneyTrap")
    st.caption("Cloud deception & threat intelligence")

pages = {
    "Operations": [
        st.Page(lambda: overview.render(ctx), title="Overview", icon="📊", default=True),
        st.Page(lambda: attack_intel.render(ctx), title="Attack Intelligence", icon="🌐", url_path="attack-intelligence"),
        st.Page(lambda: detections.render(ctx), title="Detection Center", icon="🚨", url_path="detections"),
        st.Page(lambda: mitre.render(ctx), title="MITRE ATT&CK", icon="🧭", url_path="mitre"),
    ],
    "Investigation": [
        st.Page(lambda: investigation.render(ctx), title="Attacker Investigation", icon="🔎", url_path="investigation"),
        st.Page(lambda: evidence.render(ctx), title="Evidence Explorer", icon="🗂️", url_path="evidence"),
    ],
    "Platform": [
        st.Page(lambda: platform.render(ctx), title="Architecture & Validation", icon="🏗️", url_path="platform"),
    ],
}
nav = st.navigation(pages)

with st.sidebar:
    st.divider()
    st.markdown("**Filters**")
    origins_available = sorted(ds.events["data_origin"].unique()) if not ds.events.empty else []
    origins = st.multiselect("Data origin", origins_available, default=origins_available,
                             format_func=lambda o: data.ORIGIN_LABEL.get(o, o))
    if not ds.events.empty:
        lo, hi = ds.events["ts"].min().date(), ds.events["ts"].max().date()
    else:
        import datetime as _dt
        lo = hi = _dt.date.today()
    dates = st.date_input("Date range (UTC)", value=(lo, hi), min_value=lo, max_value=hi)
    start, end = (dates if isinstance(dates, tuple) and len(dates) == 2 else (lo, hi))
    ip = st.text_input("Source IP contains", placeholder="e.g. 203.0.113.")
    severities = st.multiselect("Alert severity", data.SEVERITY_ORDER, default=[])
    classifications = st.multiselect(
        "Attack classification",
        sorted(ds.alerts["classification"].unique()) if not ds.alerts.empty else [])
    event_types = st.multiselect(
        "Event type", sorted(ds.events["event_type"].unique()) if not ds.events.empty else [])
    st.divider()
    st.caption("Sources: " + ", ".join(f"`{s}`" for s in ds.sources))
    if st.button("Reload data", use_container_width=True):
        _load.clear()
        st.rerun()

filters = {"origins": origins, "start": start, "end": end, "ip": ip.strip(), "severities": severities,
           "classifications": classifications, "event_types": event_types}
ctx = {
    "ds": ds,
    "filters": filters,
    "events": data.filter_events(ds.events, filters),
    "alerts": data.filter_alerts(ds.alerts, filters),
}

nav.run()
