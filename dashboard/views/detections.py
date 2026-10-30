from __future__ import annotations

import json

import plotly.express as px
import streamlit as st

import ui


def render(ctx) -> None:
    al = ctx["alerts"]
    ui.header("Detection Center", "Alerts produced by the HoneyTrap rule engine")
    ui.origin_banner(al["data_origin"].value_counts().to_dict() if not al.empty else {}, "alerts")
    if al.empty:
        ui.empty("No alerts for the current filters.")
        return

    sev = al["severity"].astype(str).value_counts()
    ui.kpi_row([(s, int(sev.get(s, 0)), "alerts") for s in reversed(list(ui.SEVERITY_COLORS))])
    st.write("")

    c1, c2 = st.columns([1.4, 1])
    with c1:
        timeline = al.assign(sev=al["severity"].astype(str))
        fig = px.strip(timeline, x="ts", y="sev", color="sev", color_discrete_map=ui.SEVERITY_COLORS,
                       category_orders={"sev": list(reversed(list(ui.SEVERITY_COLORS)))},
                       hover_data={"rule_id": True, "summary": True, "sev": False, "ts": "|%b %d %H:%M"},
                       title="Alert timeline")
        fig.update_traces(marker=dict(size=9, line=dict(width=1, color=ui.SURFACE)), jitter=0.6)
        fig.update_layout(height=430, xaxis_title="", yaxis_title="", showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    with c2:
        rules = (al.groupby(["rule_id", "rule_name"]).size().rename("alerts").reset_index()
                 .sort_values("alerts", ascending=False))
        rules["rule"] = rules["rule_id"] + "  " + rules["rule_name"].str.slice(0, 30)
        fig = px.bar(rules, x="alerts", y="rule", orientation="h", title="Detection rules triggered",
                     color_discrete_sequence=[ui.ACCENT], text="alerts")
        fig.update_traces(textposition="outside", cliponaxis=False)
        fig.update_layout(height=430, xaxis_title="", yaxis_title="", yaxis=dict(tickfont=dict(size=11)), margin=dict(r=40))
        st.plotly_chart(ui.style_bar(fig, horizontal=True), use_container_width=True)

    st.markdown("##### Alert queue")
    st.caption("Select a row to inspect the supporting evidence and ATT&CK mapping.")
    queue = al.sort_values(["severity", "ts"], ascending=[False, False])
    view = queue[["severity", "rule_id", "rule_name", "summary", "ip_or_related", "first_seen", "data_origin",
                  "technique_names", "alert_id"]].copy()
    view["severity"] = view["severity"].astype(str).map(lambda s: f"{ui.SEVERITY_ICON[s]} {s}")
    selection = st.dataframe(
        view, hide_index=True, use_container_width=True, height=380, on_select="rerun", selection_mode="single-row",
        column_config={"severity": "Severity", "rule_id": "Rule", "rule_name": "Detection",
                       "summary": st.column_config.TextColumn("Summary", width="large"),
                       "ip_or_related": "Source", "first_seen": "First seen", "data_origin": "Origin",
                       "technique_names": st.column_config.ListColumn("ATT&CK"), "alert_id": "Alert ID"})
    rows = selection.selection.rows if selection and selection.selection else []
    alert = queue.iloc[rows[0]] if rows else queue.iloc[0]
    _detail(ctx, alert["alert_id"])


def _detail(ctx, alert_id: str) -> None:
    obj = next(a for a in ctx["ds"].alert_objects if a.alert_id == alert_id)
    st.markdown("---")
    c1, c2 = st.columns([1.2, 1])
    with c1:
        st.markdown(f"#### {obj.rule_id} · {obj.rule_name}")
        st.markdown(f"{ui.severity_label(obj.severity)} &nbsp; {ui.origin_badge(obj.data_origin)} &nbsp;"
                    f"<span class='ht-muted'>alert `{obj.alert_id}`</span>", unsafe_allow_html=True)
        st.write(obj.summary)
        st.markdown(f"**Window:** {obj.first_seen} → {obj.last_seen}  \n"
                    f"**Entity:** `{obj.entity}`  \n"
                    f"**Severity rationale:** {'; '.join(obj.severity_reasons)}  \n"
                    f"**Sessions:** {', '.join(obj.session_ids[:6]) or '—'}")
        st.markdown("**Evidence**")
        st.code(json.dumps(obj.evidence, indent=2, default=str), language="json")
    with c2:
        st.markdown("**MITRE ATT&CK mapping**")
        if not obj.techniques:
            ui.empty("No technique mapped: the evidence does not support one (behavioural alert).")
        for t in obj.techniques:
            ev = "<br>".join(f"<code>{_esc(e)}</code>" for e in t.evidence[:4])
            st.markdown(f'<div class="ht-tech"><b><a href="{t.url}" target="_blank">{t.technique_id}</a> {_esc(t.name)}</b>'
                        f' <small>· {", ".join(t.tactics)} · confidence {t.confidence}</small><br>'
                        f'<small>{ev}</small></div>', unsafe_allow_html=True)
        events = ctx["ds"].events
        if not events.empty:
            ev_rows = events[events["event_id"].isin(obj.evidence_event_ids)]
            st.markdown(f"**Evidence events** ({len(ev_rows)} of {len(obj.evidence_event_ids)} referenced)")
            st.dataframe(ev_rows[["timestamp", "event_type", "username", "password_masked", "command", "url"]]
                         .head(25), hide_index=True, use_container_width=True, height=240)


def _esc(text: str) -> str:
    import html
    return html.escape(str(text))

