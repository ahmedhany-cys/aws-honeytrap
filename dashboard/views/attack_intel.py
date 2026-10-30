from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

import data
import ui


def _hbar(df: pd.DataFrame, x: str, y: str, title: str, height: int = 360, hover: str | None = None):
    fig = px.bar(df, x=x, y=y, orientation="h", title=title, color_discrete_sequence=[ui.ACCENT], text=x,
                 hover_data=[hover] if hover else None)
    fig.update_traces(texttemplate="%{text:,}", textposition="outside", cliponaxis=False)
    fig.update_layout(height=height, xaxis_title="", yaxis_title="", margin=dict(r=48))
    return ui.style_bar(fig, horizontal=True)


def render(ctx) -> None:
    ev = ctx["events"]
    ui.header("Attack Intelligence", "Who is attacking, from where, and with what")
    ui.origin_banner(ev["data_origin"].value_counts().to_dict() if not ev.empty else {})
    if ev.empty:
        ui.empty()
        return

    daily = (ev.assign(day=ev["ts"].dt.floor("D"))
             .groupby("day").agg(events=("event_id", "size"), attackers=("src_ip", "nunique")).reset_index())
    c1, c2 = st.columns(2)
    with c1:
        fig = px.bar(daily, x="day", y="events", title="Attack events per day", color_discrete_sequence=[ui.ACCENT])
        fig.update_traces(hovertemplate="%{x|%b %d}: %{y:,} events<extra></extra>")
        fig.update_layout(height=300, xaxis_title="", yaxis_title="")
        st.plotly_chart(ui.style_bar(fig), use_container_width=True)
    with c2:
        fig = px.bar(daily, x="day", y="attackers", title="Unique attacking IPs per day",
                     color_discrete_sequence=[ui.SERIES[2]])
        fig.update_traces(hovertemplate="%{x|%b %d}: %{y:,} IPs<extra></extra>")
        fig.update_layout(height=300, xaxis_title="", yaxis_title="")
        st.plotly_chart(ui.style_bar(fig), use_container_width=True)

    c1, c2 = st.columns([1, 1.3])
    with c1:
        top = ev["src_ip"].value_counts().head(12).rename_axis("src_ip").reset_index(name="events")
        st.plotly_chart(_hbar(top, "events", "src_ip", "Top attacking IPs (events)", 420), use_container_width=True)
    with c2:
        enr = data.enrichment_frame(ctx["ds"].enrichment)
        ips = ev.groupby("src_ip").size().rename("events").reset_index()
        geo = ips.merge(enr, on="src_ip", how="left") if not enr.empty else ips.assign(country_code=None)
        located = geo.dropna(subset=["country_code"]) if "country_code" in geo else geo.iloc[0:0]
        if located.empty:
            st.markdown("##### Geographic distribution")
            ui.empty("No GeoIP / AbuseIPDB enrichment for these IPs (private, simulated, or no API key configured). "
                     "Nothing is inferred without a real lookup.")
        else:
            by_country = located.groupby(["country_code", "country"], dropna=False).agg(
                attackers=("src_ip", "nunique"), events=("events", "sum")).reset_index()
            iso3 = _iso3(by_country["country_code"])
            by_country["iso3"] = iso3
            synthetic = located.get("synthetic_enrichment", pd.Series(dtype=bool)).fillna(False).all()
            fig = px.choropleth(by_country, locations="iso3", color="attackers", hover_name="country",
                                hover_data={"iso3": False, "events": ":,", "attackers": ":,"},
                                # On a dark surface "more" must mean more contrast, so the ramp runs dark -> light.
                                color_continuous_scale=["#0d366b", "#1c5cab", "#3987e5", "#86b6ef", "#cde2fb"],
                                title="Attacking IPs by country" + (" — SYNTHETIC demo enrichment" if synthetic else ""))
            fig.update_geos(bgcolor="rgba(0,0,0,0)", showframe=False, showcoastlines=False, landcolor="#1b2330",
                            showcountries=True, countrycolor="#2a3441", projection_type="natural earth")
            fig.update_layout(height=420, coloraxis_colorbar=dict(title="IPs", thickness=10))
            st.plotly_chart(fig, use_container_width=True)
            st.caption(f"{len(located):,} of {len(ips):,} IPs have location data. "
                       + ("Locations come from the synthetic demo generator, not a real GeoIP lookup."
                          if synthetic else "Source: GeoIP / AbuseIPDB enrichment."))

    logins = ev[ev["category"] == "authentication"]
    c1, c2, c3 = st.columns(3)
    with c1:
        users = logins["username"].value_counts().head(12).rename_axis("username").reset_index(name="attempts")
        st.plotly_chart(_hbar(users, "attempts", "username", "Most attempted usernames", 400), use_container_width=True)
    with c2:
        pw = (logins.dropna(subset=["password_fingerprint"])
              .groupby(["password_fingerprint", "password_masked", "password_length"]).size()
              .rename("attempts").reset_index().sort_values("attempts", ascending=False).head(12))
        pw["label"] = pw["password_masked"] + "  ·  " + pw["password_fingerprint"].str[:6]
        fig = _hbar(pw, "attempts", "label", "Most attempted passwords (masked)", 400, hover="password_length")
        st.plotly_chart(fig, use_container_width=True)
        st.caption("Passwords are masked; the suffix is a keyed HMAC fingerprint so reuse can be correlated "
                   "without storing clear text.")
    with c3:
        clients = (ev["client_version"].dropna().value_counts().head(12)
                   .rename_axis("client").reset_index(name="sessions"))
        st.plotly_chart(_hbar(clients, "sessions", "client", "SSH client versions", 400), use_container_width=True)

    cmds = ev[ev["event_type"] == "cowrie.command.input"]
    st.markdown("##### Most common commands")
    if cmds.empty:
        ui.empty("No commands executed in the selected data.")
    else:
        top_cmds = (cmds.groupby("command").agg(executions=("event_id", "size"), attackers=("src_ip", "nunique"))
                    .sort_values("executions", ascending=False).head(20).reset_index())
        st.dataframe(top_cmds, hide_index=True, use_container_width=True,
                     column_config={"command": st.column_config.TextColumn("Command", width="large"),
                                    "executions": st.column_config.NumberColumn("Executions", format="%d"),
                                    "attackers": st.column_config.NumberColumn("Distinct IPs", format="%d")})


_ISO = {"CN": "CHN", "US": "USA", "RU": "RUS", "BR": "BRA", "IN": "IND", "VN": "VNM", "DE": "DEU", "NL": "NLD",
        "KR": "KOR", "ID": "IDN", "SG": "SGP", "FR": "FRA", "IR": "IRN", "TW": "TWN", "GB": "GBR", "HK": "HKG",
        "UA": "UKR", "BG": "BGR", "JP": "JPN", "CA": "CAN", "AU": "AUS", "TR": "TUR", "PL": "POL", "IT": "ITA",
        "ES": "ESP", "MX": "MEX", "AR": "ARG", "ZA": "ZAF", "TH": "THA", "PK": "PAK", "BD": "BGD", "RO": "ROU",
        "SE": "SWE", "CH": "CHE", "PH": "PHL", "MY": "MYS", "EG": "EGY", "NG": "NGA", "CO": "COL", "CL": "CHL"}


def _iso3(codes: pd.Series) -> pd.Series:
    return codes.map(lambda c: _ISO.get(str(c).upper(), None))
