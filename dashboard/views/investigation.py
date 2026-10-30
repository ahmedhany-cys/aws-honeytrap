from __future__ import annotations

import html

import pandas as pd
import plotly.express as px
import streamlit as st

import ui
from honeytrap.enrichment.service import is_public_ip
from honeytrap.reporting.report import build_report, render_json, render_markdown


def render(ctx) -> None:
    ds = ctx["ds"]
    ui.header("Attacker Investigation", "Pivot on one source IP across sessions, credentials, commands and alerts")
    prof = ds.profiles
    if prof.empty:
        ui.empty()
        return
    prof = prof[prof["data_origin"].isin(ctx["filters"]["origins"])]
    if ctx["filters"]["ip"]:
        prof = prof[prof["src_ip"].str.contains(ctx["filters"]["ip"], regex=False)]
    if prof.empty:
        ui.empty()
        return

    options = prof["src_ip"].tolist()
    labels = {r.src_ip: f"{r.src_ip}  ·  risk {r.risk_score}  ·  {r.actor_type}" for r in prof.itertuples()}
    default = st.query_params.get("ip")
    ip = st.selectbox("Attacker IP (sorted by risk score)", options, format_func=labels.get,
                      index=options.index(default) if default in options else 0)
    st.query_params["ip"] = ip
    p = prof[prof["src_ip"] == ip].iloc[0]

    events = [e for e in ds.event_objects if e.src_ip == ip]
    report = build_report(ip, events, ds.alert_objects, ds.enrichment)
    st.markdown(f"{ui.origin_badge(p['data_origin'])} &nbsp; {ui.severity_label(p['max_severity'])} "
                f"<span class='ht-muted'>max alert severity</span>", unsafe_allow_html=True)
    ui.kpi_row([
        ("Risk score", f"{p['risk_score']}/100", p["risk_level"]),
        ("Actor type", p["actor_type"], ""),
        ("Sessions", int(p["sessions"]), f"{p['first_seen'][:16]} → {p['last_seen'][:16]}"),
        ("Logins (fail / ok)", f"{int(p['failed_logins'])} / {int(p['successful_logins'])}", ""),
        ("Commands · transfers", f"{int(p['commands'])} · {int(p['downloads'])}", ""),
    ])
    st.write("")

    c1, c2 = st.columns([1.6, 1])
    with c1:
        ev = ds.events[ds.events["src_ip"] == ip]
        fig = px.scatter(ev, x="ts", y="category", color="category", hover_data=["event_type", "session_id", "command"],
                         title="Activity timeline", category_orders={"category": sorted(ev["category"].unique())})
        fig.update_traces(marker=dict(size=9, line=dict(width=1, color=ui.SURFACE)))
        fig.update_layout(height=300, xaxis_title="", yaxis_title="", showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        st.markdown("##### Threat intelligence")
        enr = report["enrichment"]
        status = enr.get("enrichment_status")
        if status == "none" and not is_public_ip(ip):
            status = "skipped_non_public"
        if status in (None, "none", "not_configured", "skipped_non_public", "unavailable", "deferred"):
            ui.empty(f"No enrichment (status: {status}). Private/simulated addresses are never looked up, and nothing "
                     "is assumed without a real lookup.")
        else:
            if enr.get("synthetic_enrichment"):
                st.markdown(ui.origin_badge("synthetic") + " <span class='ht-muted'>demo enrichment, not a real lookup</span>",
                            unsafe_allow_html=True)
            rows = {"AbuseIPDB confidence": enr.get("abuse_confidence_score"),
                    "AbuseIPDB reports": enr.get("abuse_total_reports"),
                    "VirusTotal malicious": enr.get("vt_malicious"),
                    "Country": enr.get("country") or enr.get("country_code"), "ISP / AS": enr.get("isp")}
            st.dataframe(pd.DataFrame([(k, "—" if v is None else str(v)) for k, v in rows.items()],
                                      columns=["Field", "Value"]), hide_index=True, use_container_width=True)
        st.markdown("##### ATT&CK techniques")
        if report["techniques"]:
            st.markdown(" ".join(f'<a href="{t["url"]}" target="_blank"><code>{t["technique_id"]}</code></a> '
                                 f'{html.escape(t["name"])}<br>' for t in report["techniques"]), unsafe_allow_html=True)
        else:
            ui.empty("No technique supported by the evidence.")

    tabs = st.tabs(["Alerts", "Sessions", "Login attempts", "Commands", "Timeline", "Report"])
    with tabs[0]:
        rel = pd.DataFrame(report["alerts"])
        if rel.empty:
            ui.empty("No alerts for this IP.")
        else:
            st.dataframe(rel[["severity", "rule_id", "rule_name", "summary", "first_seen", "last_seen"]],
                         hide_index=True, use_container_width=True)
    with tabs[1]:
        ev = ds.events[ds.events["src_ip"] == ip]
        sessions = ev.groupby("session_id").agg(
            start=("timestamp", "min"), end=("timestamp", "max"), protocol=("protocol", "first"),
            events=("event_id", "size"),
            logins=("event_type", lambda s: int(s.isin(["cowrie.login.failed", "cowrie.login.success"]).sum())),
            success=("event_type", lambda s: bool((s == "cowrie.login.success").any())),
            commands=("event_type", lambda s: int((s == "cowrie.command.input").sum())),
            client=("client_version", lambda s: next((x for x in s if isinstance(x, str)), ""))).reset_index()
        st.dataframe(sessions.sort_values("start"), hide_index=True, use_container_width=True)
    with tabs[2]:
        logins = ev[ev["category"] == "authentication"][["timestamp", "session_id", "protocol", "username",
                                                          "password_masked", "password_fingerprint", "login_success"]]
        st.dataframe(logins, hide_index=True, use_container_width=True, height=320)
        st.caption("Passwords masked; full values exist only in the restricted raw log.")
    with tabs[3]:
        cmds = pd.DataFrame(report["commands"])
        if cmds.empty:
            ui.empty("No commands executed.")
        else:
            st.dataframe(cmds, hide_index=True, use_container_width=True,
                         column_config={"command": st.column_config.TextColumn(width="large")})
    with tabs[4]:
        st.dataframe(pd.DataFrame(report["timeline"]), hide_index=True, use_container_width=True, height=360)
    with tabs[5]:
        md = render_markdown(report)
        c1, c2 = st.columns(2)
        c1.download_button("Download report (Markdown)", md, file_name=f"honeytrap-report-{ip}.md",
                           mime="text/markdown", use_container_width=True)
        c2.download_button("Download report (JSON)", render_json(report), file_name=f"honeytrap-report-{ip}.json",
                           mime="application/json", use_container_width=True)
        st.markdown(md)
