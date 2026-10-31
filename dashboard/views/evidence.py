from __future__ import annotations

import json

import pandas as pd
import streamlit as st

import ui

COLUMNS = ["timestamp", "data_origin", "event_type", "src_ip", "session_id", "username", "password_masked", "command",
           "url", "file_path", "file_sha256", "protocol", "src_port", "client_version", "sensor", "event_id"]


def render(ctx) -> None:
    ev, al = ctx["events"], ctx["alerts"]
    ui.header("Evidence Explorer", "Inspect normalised event records and export investigation data")
    ui.origin_banner(ev["data_origin"].value_counts().to_dict() if not ev.empty else {})
    if ev.empty:
        ui.empty()
        return

    c1, c2, c3 = st.columns([2, 1, 1])
    query = c1.text_input("Search command / URL / username / session", placeholder="wget, authorized_keys, root …")
    categories = c2.multiselect("Category", sorted(ev["category"].unique()))
    classification = c3.selectbox("Only events behind alerts of class", ["(any)"] + sorted(al["classification"].unique())
                                  if not al.empty else ["(any)"])
    view = ev
    if query:
        q = query.lower()
        hay = (view["command"].fillna("") + " " + view["url"].fillna("") + " " + view["username"].fillna("") + " "
               + view["session_id"].fillna("")).str.lower()
        view = view[hay.str.contains(q, regex=False)]
    if categories:
        view = view[view["category"].isin(categories)]
    if classification != "(any)":
        ids = {i for ids in al[al["classification"] == classification]["evidence_event_ids"] for i in ids}
        view = view[view["event_id"].isin(ids)]

    st.caption(f"{len(view):,} of {len(ev):,} filtered events")
    table = view.sort_values("timestamp", ascending=False)[COLUMNS].head(5000)
    sel = st.dataframe(table, hide_index=True, use_container_width=True, height=420, on_select="rerun",
                       selection_mode="single-row",
                       column_config={"command": st.column_config.TextColumn(width="large"),
                                      "data_origin": "Origin", "event_type": "Event"})
    rows = sel.selection.rows if sel and sel.selection else []

    c1, c2 = st.columns([1.2, 1])
    with c1:
        st.markdown("##### Event record")
        if rows:
            record = table.iloc[rows[0]].to_dict()
            obj = next(e for e in ctx["ds"].event_objects if e.event_id == record["event_id"])
            st.code(json.dumps({k: v for k, v in obj.to_dict().items() if v is not None}, indent=2,
                               ensure_ascii=False), language="json")
            linked = al[al["evidence_event_ids"].apply(lambda ids: record["event_id"] in ids)] if not al.empty else al
            if not linked.empty:
                st.markdown("**Referenced by alerts:** " + ", ".join(
                    f"`{r.rule_id}` ({r.severity})" for r in linked.itertuples()))
        else:
            ui.empty("Select a row to see the full normalised record and the alerts that cite it.")
    with c2:
        st.markdown("##### Export")
        export = view.drop(columns=["ts"])
        st.download_button("Filtered events (CSV)", export.to_csv(index=False), "honeytrap-events.csv", "text/csv",
                           use_container_width=True)
        st.download_button("Filtered events (JSON Lines)", export.to_json(orient="records", lines=True),
                           "honeytrap-events.jsonl", "application/x-ndjson", use_container_width=True)
        alerts_export = al.drop(columns=["ts"]).assign(severity=al["severity"].astype(str)) if not al.empty else al
        st.download_button("Filtered alerts (JSON)", alerts_export.to_json(orient="records", indent=2),
                           "honeytrap-alerts.json", "application/json", use_container_width=True)
        st.download_button("Investigation summary (Markdown)", _summary_md(view, al), "honeytrap-summary.md",
                           "text/markdown", use_container_width=True)
        st.caption("Exports contain masked passwords and HMAC fingerprints only.")


def _summary_md(ev: pd.DataFrame, al: pd.DataFrame) -> str:
    origins = ", ".join(sorted(ev["data_origin"].unique()))
    lines = [
        "# HoneyTrap investigation summary", "",
        f"Data origin(s): **{origins}**. Time range: {ev['timestamp'].min()} → {ev['timestamp'].max()}.", "",
        f"- Events: {len(ev):,}", f"- Source IPs: {ev['src_ip'].nunique():,}",
        f"- Sessions: {ev['session_id'].nunique():,}", f"- Alerts: {len(al):,}", "",
        "## Alerts by severity", "",
    ]
    if not al.empty:
        for sev, n in al["severity"].astype(str).value_counts().items():
            lines.append(f"- {sev}: {n}")
        lines += ["", "## Top alerting rules", ""]
        for (rid, name), n in al.groupby(["rule_id", "rule_name"]).size().sort_values(ascending=False).head(10).items():
            lines.append(f"- {rid} {name}: {n}")
    lines += ["", "## Top source IPs", ""]
    for ip, n in ev["src_ip"].value_counts().head(10).items():
        lines.append(f"- `{ip}`: {n} events")
    return "\n".join(lines) + "\n"
