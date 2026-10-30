from __future__ import annotations

import html
from collections import defaultdict

import pandas as pd
import streamlit as st

import ui
from honeytrap.detection.rules import rule_catalog
from honeytrap.mitre.catalog import attack_version, load_catalog

TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Stealth",
                "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Command and Control",
                "Impact"]
# Sequential blue ramp (light -> dark) for cell intensity.
RAMP = ["#184f95", "#1c5cab", "#256abf", "#2a78d6", "#3987e5", "#5598e7"]


def render(ctx) -> None:
    al = ctx["alerts"]
    ui.header("MITRE ATT&CK Mapping", f"Enterprise ATT&CK v{attack_version()} · evidence-based mappings only")
    ui.origin_banner(al["data_origin"].value_counts().to_dict() if not al.empty else {}, "alerts")
    if al.empty:
        ui.empty("No alerts for the current filters.")
        return

    stats: dict[str, dict] = defaultdict(lambda: {"alerts": 0, "ips": set(), "rules": set(), "conf": set(), "evidence": []})
    objs = {a.alert_id: a for a in ctx["ds"].alert_objects}
    for alert_id in al["alert_id"]:
        a = objs[alert_id]
        for t in a.techniques:
            s = stats[t.technique_id]
            s["alerts"] += 1
            s["ips"].update([a.src_ip] if a.src_ip else a.related_ips)
            s["rules"].add(a.rule_id)
            s["conf"].add(t.confidence)
            if len(s["evidence"]) < 3:
                s["evidence"] += [e for e in t.evidence[:1] if e not in s["evidence"]]

    catalog = load_catalog()["techniques"]
    max_alerts = max((s["alerts"] for s in stats.values()), default=1)
    columns = []
    for tactic in TACTIC_ORDER:
        cells = [(tid, s) for tid, s in stats.items() if tactic in catalog[tid]["tactics"]]
        if not cells:
            continue
        cells.sort(key=lambda x: -x[1]["alerts"])
        cards = []
        for tid, s in cells:
            shade = RAMP[min(len(RAMP) - 1, int((s["alerts"] / max_alerts) ** 0.5 * (len(RAMP) - 1)))]
            cards.append(
                f'<a href="{catalog[tid]["url"]}" target="_blank" style="text-decoration:none">'
                f'<div style="background:{shade};border-radius:8px;padding:.45rem .55rem;margin-bottom:.35rem;'
                f'color:#f0f6fc;font-size:.78rem;line-height:1.25">'
                f'<b>{tid}</b><br>{html.escape(catalog[tid]["name"])}'
                f'<div style="opacity:.85;font-size:.72rem;margin-top:.2rem">{s["alerts"]:,} alerts · '
                f'{len(s["ips"]):,} IPs</div></div></a>')
        columns.append(f'<div style="min-width:0"><div style="color:#8b949e;font-size:.72rem;'
                       f'text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem;border-bottom:1px solid '
                       f'#2a3441;padding-bottom:.3rem">{tactic}</div>{"".join(cards)}</div>')
    st.markdown('<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:.9rem .6rem;'
                'padding-bottom:.5rem">' + "".join(columns)
                + "</div>", unsafe_allow_html=True)
    st.caption("Cell shade = alert volume (darker is fewer). Click a technique to open it on attack.mitre.org.")

    st.markdown("##### Technique evidence")
    rows = [{"Technique": f"{tid} {catalog[tid]['name']}", "Tactics": ", ".join(catalog[tid]["tactics"]),
             "Alerts": s["alerts"], "Source IPs": len(s["ips"]), "Rules": ", ".join(sorted(s["rules"])),
             "Confidence": " / ".join(c for c in ("high", "medium", "low") if c in s["conf"]),
             "Example evidence": " | ".join(s["evidence"])} for tid, s in stats.items()]
    st.dataframe(pd.DataFrame(rows).sort_values("Alerts", ascending=False), hide_index=True,
                 use_container_width=True, height=360,
                 column_config={"Example evidence": st.column_config.TextColumn(width="large")})

    with st.expander("Detection rule → technique catalogue"):
        st.dataframe(pd.DataFrame(rule_catalog()), hide_index=True, use_container_width=True,
                     column_config={"techniques": st.column_config.ListColumn("Techniques"),
                                    "description": st.column_config.TextColumn(width="large")})
        st.caption("Confidence: high = the command or event is direct evidence of the technique; medium = strong "
                   "indicator; low = pattern-consistent but not provable from honeypot data alone (e.g. T1110.004).")
