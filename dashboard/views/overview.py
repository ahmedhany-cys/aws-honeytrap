from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

import ui


def render(ctx) -> None:
    ev, al = ctx["events"], ctx["alerts"]
    ui.header("Overview", "Honeypot activity at a glance")
    ui.origin_banner(ev["data_origin"].value_counts().to_dict() if not ev.empty else {})
    if ev.empty:
        ui.empty()
        return

    logins = ev[ev["event_type"].isin(["cowrie.login.failed", "cowrie.login.success"])]
    success = ev[ev["event_type"] == "cowrie.login.success"]
    sev = al["severity"].astype(str).value_counts() if not al.empty else pd.Series(dtype=int)
    ui.kpi_row([
        ("Attack events", len(ev), f"{ev['session_id'].nunique():,} sessions"),
        ("Unique source IPs", ev["src_ip"].nunique(), "distinct attackers"),
        ("Login attempts", len(logins), f"{(logins['protocol'] == 'ssh').sum():,} SSH · {(logins['protocol'] == 'telnet').sum():,} Telnet"),
        ("Successful decoy logins", len(success), "emulated shell, no real access"),
        ("Critical alerts", int(sev.get("Critical", 0)), f"{int(sev.get('High', 0)):,} high · {len(al):,} total"),
    ])
    st.write("")

    left, right = st.columns([2, 1])
    with left:
        hourly = (ev.set_index("ts").groupby([pd.Grouper(freq="1h"), "category"]).size()
                  .rename("events").reset_index())
        top_cats = ev["category"].value_counts().index[:5].tolist()
        hourly = hourly[hourly["category"].isin(top_cats)]
        fig = px.line(hourly, x="ts", y="events", color="category", category_orders={"category": top_cats},
                      title="Events per hour by category", labels={"ts": "", "events": "events / hour"})
        fig.update_traces(line_width=2, hovertemplate="%{x|%b %d %H:00}<br>%{y:,} events")
        fig.update_layout(height=340, hovermode="x unified", legend_title_text="", margin=dict(t=70),
                          legend=dict(y=1.0, yanchor="bottom"))
        st.plotly_chart(fig, use_container_width=True)
    with right:
        # Cowrie records its container port (2222/2223); the service is what the attacker reached.
        svc = ev[ev["event_type"] == "cowrie.session.connect"].assign(
            service=lambda d: d["protocol"].map({"ssh": "SSH (22)", "telnet": "Telnet (23)"}).fillna("other"))
        counts = svc["service"].value_counts().rename_axis("service").reset_index(name="connections")
        fig = px.bar(counts, x="connections", y="service", orientation="h", title="Most targeted services",
                     color_discrete_sequence=[ui.ACCENT], text="connections")
        fig.update_traces(texttemplate="%{text:,}", textposition="outside", cliponaxis=False,
                          hovertemplate="%{y}: %{x:,} connections<extra></extra>")
        fig.update_layout(height=340, yaxis_title="", xaxis_title="")
        st.plotly_chart(ui.style_bar(fig, horizontal=True), use_container_width=True)

    left, right = st.columns([1, 2])
    with left:
        if al.empty:
            ui.empty("No alerts for the current filters.")
        else:
            order = [s for s in ui.SEVERITY_COLORS if s in sev.index]  # reversed axis puts Critical on top
            sdf = pd.DataFrame({"severity": order, "alerts": [int(sev[s]) for s in order]})
            fig = px.bar(sdf, x="alerts", y="severity", orientation="h", color="severity",
                         color_discrete_map=ui.SEVERITY_COLORS, title="Alerts by severity", text="alerts",
                         category_orders={"severity": order})
            fig.update_traces(textposition="outside", cliponaxis=False,
                              hovertemplate="%{y}: %{x:,} alerts<extra></extra>")
            fig.update_layout(height=320, xaxis_title="", yaxis_title="", margin=dict(r=40))
            st.plotly_chart(ui.style_bar(fig, horizontal=True), use_container_width=True)
    with right:
        st.markdown("##### Highest-risk attackers")
        prof = ctx["ds"].profiles
        if prof.empty:
            ui.empty()
        else:
            prof = prof[prof["data_origin"].isin(ctx["filters"]["origins"])]
            if ctx["filters"]["ip"]:
                prof = prof[prof["src_ip"].str.contains(ctx["filters"]["ip"], regex=False)]
            st.dataframe(
                prof.head(10)[["src_ip", "data_origin", "risk_score", "risk_level", "actor_type", "sessions",
                               "login_attempts", "commands", "alerts", "max_severity", "country_code"]],
                hide_index=True, use_container_width=True, height=320,
                column_config={
                    "src_ip": "Source IP", "data_origin": "Origin",
                    "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d"),
                    "risk_level": "Level", "actor_type": "Actor type", "login_attempts": "Logins",
                    "max_severity": "Max severity", "country_code": "Country",
                })
