"""Shared look-and-feel: theme tokens, Plotly template, KPI tiles, origin banner."""

from __future__ import annotations

import html

import plotly.graph_objects as go
import plotly.io as pio
import streamlit as st

# Palette validated with the dataviz validator against the chart surface #121821
# (CVD dE >= 12.6, normal-vision dE >= 15.6 between adjacent severities).
SURFACE = "#121821"
SEVERITY_COLORS = {
    "Informational": "#9aa3ad",
    "Low": "#3987e5",
    "Medium": "#f5c518",
    "High": "#e8742c",
    "Critical": "#d42a4c",
}
SEVERITY_ICON = {"Informational": "○", "Low": "◔", "Medium": "◑", "High": "◕", "Critical": "●"}
SERIES = ["#3987e5", "#d95926", "#199e70", "#c98500", "#d55181", "#008300", "#9085e9", "#e66767"]
ACCENT = "#3987e5"
ORIGIN_STYLE = {
    "live": ("LIVE", "#0f5132", "#75e0a7"),
    "simulation": ("SIMULATION", "#4a3200", "#f5c518"),
    "synthetic": ("SYNTHETIC DEMO", "#3b1f5c", "#c4b5fd"),
}

pio.templates["honeytrap"] = go.layout.Template(
    layout=go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor=SURFACE,
        font=dict(family="Inter, system-ui, sans-serif", size=12, color="#c9d1d9"),
        colorway=SERIES,
        margin=dict(l=8, r=8, t=36, b=8),
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False, linecolor="#2a3441"),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False, linecolor="#2a3441"),
        hoverlabel=dict(bgcolor="#0b1017", bordercolor="#2a3441", font=dict(color="#e6edf3")),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, bgcolor="rgba(0,0,0,0)"),
        title=dict(font=dict(size=14, color="#e6edf3"), x=0, xanchor="left"),
        bargap=0.25,
    )
)
pio.templates.default = "honeytrap"

CSS = """
<style>
  .block-container {padding-top: 3rem; padding-bottom: 2rem; max-width: 1500px;}
  [data-testid="stSidebar"] {background: #0b1017; border-right: 1px solid #1f2937;}
  h1, h2, h3 {letter-spacing: -0.01em;}
  .ht-header {display:flex; align-items:baseline; gap:.8rem; margin-bottom:.2rem;}
  .ht-header h1 {font-size:1.7rem !important; font-weight:700 !important; margin:0 !important; padding:0 !important; color:#e6edf3;}
  .ht-header span {color:#8b949e; font-size:.95rem;}
  .ht-banner {display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; padding:.55rem .8rem;
              border:1px solid #2a3441; border-radius:10px; background:#0f141c; margin:.4rem 0 1rem 0;
              font-size:.85rem; color:#c9d1d9;}
  .ht-badge {padding:.12rem .55rem; border-radius:999px; font-weight:600; font-size:.75rem; letter-spacing:.04em;}
  .ht-kpi {border:1px solid #1f2937; background:linear-gradient(180deg,#121821 0%,#0f141c 100%);
           border-radius:12px; padding:.85rem 1rem; height:100%;}
  .ht-kpi .label {color:#8b949e; font-size:.78rem; text-transform:uppercase; letter-spacing:.06em;}
  .ht-kpi .value {color:#e6edf3; font-size:1.75rem; font-weight:650; line-height:1.25; font-variant-numeric: tabular-nums;}
  .ht-kpi .sub {color:#8b949e; font-size:.78rem;}
  .ht-sev {display:inline-flex; gap:.3rem; align-items:center; font-weight:600;}
  .ht-card {border:1px solid #1f2937; border-radius:12px; padding:1rem; background:#0f141c;}
  .ht-muted {color:#8b949e; font-size:.85rem;}
  .ht-tech {border:1px solid #2a3441; border-radius:8px; padding:.45rem .6rem; margin-bottom:.4rem; background:#121821;}
  .ht-tech b {color:#e6edf3;} .ht-tech small {color:#8b949e;}
</style>
"""


def header(title: str, subtitle: str) -> None:
    st.markdown(f'<div class="ht-header"><h1>{html.escape(title)}</h1><span>{html.escape(subtitle)}</span></div>',
                unsafe_allow_html=True)


def origin_badge(origin: str) -> str:
    label, bg, fg = ORIGIN_STYLE.get(origin, (origin.upper(), "#1f2937", "#e6edf3"))
    return f'<span class="ht-badge" style="background:{bg};color:{fg}">{label}</span>'


def origin_banner(counts: dict[str, int], noun: str = "events") -> None:
    if not counts:
        st.warning("No data for the selected filters.")
        return
    parts = [f"{origin_badge(o)} {n:,} {noun}" for o, n in sorted(counts.items())]
    note = []
    if "synthetic" in counts:
        note.append("Synthetic demo data is generated offline from documentation IP ranges (RFC 5737).")
    if "simulation" in counts:
        note.append("Simulation data was captured by Cowrie from HoneyTrap's own controlled attack scripts.")
    if "live" not in counts:
        note.append("No live internet telemetry is shown.")
    st.markdown(f'<div class="ht-banner"><b>Data origin</b>&nbsp; {" &nbsp; ".join(parts)}'
                f'<span class="ht-muted">&nbsp;— {" ".join(note)}</span></div>', unsafe_allow_html=True)


def kpi(label: str, value, sub: str = "") -> str:
    text = isinstance(value, str) and not any(c.isdigit() for c in value)
    value = f"{value:,}" if isinstance(value, int) else html.escape(str(value))
    style = ' style="font-size:1.15rem;padding-top:.3rem"' if text else ""
    return (f'<div class="ht-kpi"><div class="label">{html.escape(label)}</div>'
            f'<div class="value"{style}>{value}</div><div class="sub">{html.escape(sub)}</div></div>')


def kpi_row(items: list[tuple[str, object, str]]) -> None:
    cols = st.columns(len(items))
    for col, (label, value, sub) in zip(cols, items, strict=True):
        col.markdown(kpi(label, value, sub), unsafe_allow_html=True)


def severity_label(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#9aa3ad")
    return f'<span class="ht-sev" style="color:{color}">{SEVERITY_ICON.get(sev, "")} {html.escape(sev)}</span>'


def style_bar(fig: go.Figure, horizontal: bool = False) -> go.Figure:
    fig.update_traces(marker_line_width=0, selector=dict(type="bar"))
    if horizontal:
        fig.update_yaxes(autorange="reversed", gridcolor="rgba(0,0,0,0)")
    fig.update_layout(showlegend=fig.layout.showlegend if fig.layout.showlegend is not None else False)
    return fig


def empty(msg: str = "Nothing matches the current filters.") -> None:
    st.markdown(f'<div class="ht-card ht-muted">{html.escape(msg)}</div>', unsafe_allow_html=True)
