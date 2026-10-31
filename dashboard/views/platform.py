"""Architecture diagram plus the validation evidence collected by scripts/collect_evidence.sh.

Everything here is read from files in docs/evidence/ produced by real tool runs;
if a file is missing the page says so instead of showing placeholder results.
"""

from __future__ import annotations

import base64
import json
import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own pytest JUnit output
from pathlib import Path

import pandas as pd
import streamlit as st

import ui

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "docs" / "evidence"
DIAGRAM = ROOT / "architecture" / "diagrams" / "architecture.svg"


def render(ctx) -> None:
    ui.header("Architecture & Validation", "Design, infrastructure checks and automated test evidence")
    tab_arch, tab_tests, tab_iac, tab_sim = st.tabs(
        ["AWS architecture", "Automated tests", "Terraform & IaC security", "Attack simulations"])

    with tab_arch:
        if DIAGRAM.exists():
            b64 = base64.b64encode(DIAGRAM.read_bytes()).decode()
            st.markdown(f'<div class="ht-card" style="background:#0f141c"><img src="data:image/svg+xml;base64,{b64}" '
                        f'style="width:100%;height:auto" alt="HoneyTrap AWS architecture"/></div>', unsafe_allow_html=True)
        st.caption("Design diagram of the Terraform-defined architecture (terraform/). It shows what `terraform apply` "
                   "creates; it is not a screenshot of a deployed account.")
        _deploy_status()

    with tab_tests:
        _tests()

    with tab_iac:
        _iac()

    with tab_sim:
        _simulations()


def _load(name: str):
    path = EVIDENCE / name
    if not path.exists():
        return None
    return json.loads(path.read_text()) if path.suffix == ".json" else path.read_text()


def _missing(name: str) -> None:
    ui.empty(f"docs/evidence/{name} not found - run scripts/collect_evidence.sh to produce it.")


def _deploy_status() -> None:
    meta = _load("deployment-status.json")
    if meta:
        st.markdown(f"**Deployment status:** {meta.get('status')} — {meta.get('detail', '')}")


def _tests() -> None:
    xml = EVIDENCE / "pytest-junit.xml"
    if not xml.exists():
        _missing("pytest-junit.xml")
        return
    root = ET.parse(xml).getroot()  # noqa: S314 - our own file
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    cases = []
    for tc in suite.iter("testcase"):
        status = "failed" if tc.find("failure") is not None or tc.find("error") is not None else \
            "skipped" if tc.find("skipped") is not None else "passed"
        cls = tc.get("classname", "")
        layer = cls.split(".")[1] if cls.startswith("tests.") and len(cls.split(".")) > 2 else "other"
        cases.append({"layer": layer, "test": f"{cls.split('.')[-1]}::{tc.get('name')}", "status": status,
                      "seconds": round(float(tc.get("time", 0)), 3)})
    df = pd.DataFrame(cases)
    total, passed = len(df), int((df["status"] == "passed").sum())
    failed, skipped = int((df["status"] == "failed").sum()), int((df["status"] == "skipped").sum())
    cov = _load("coverage.json")
    ui.kpi_row([
        ("Tests passed", f"{passed}/{total}", f"{failed} failed · {skipped} skipped"),
        ("Unit", int((df["layer"] == "unit").sum()), "tests"),
        ("Integration", int((df["layer"] == "integration").sum()), "moto-backed AWS tests"),
        ("Security", int((df["layer"] == "security").sum()), "IaC / IAM / secrets checks"),
        ("Line coverage", f"{cov['totals']['percent_covered']:.0f}%" if cov else "n/a", "backend + lambda"),
    ])
    # pytest writes local time, with an offset in recent versions; show UTC when the offset is known.
    ran = pd.Timestamp(suite.get("timestamp")) if suite.get("timestamp") else None
    when = "" if ran is None else (f"run {ran.tz_convert('UTC'):%Y-%m-%d %H:%M:%S} UTC, " if ran.tzinfo
                                   else f"run {ran:%Y-%m-%d %H:%M:%S} local time, ")
    st.caption(f"Source: docs/evidence/pytest-junit.xml ({when}{float(suite.get('time', 0)):.1f}s).")
    by_layer = df.groupby(["layer", "status"]).size().unstack(fill_value=0).reset_index()
    st.dataframe(by_layer, hide_index=True, use_container_width=True)
    st.dataframe(df, hide_index=True, use_container_width=True, height=360)


def _iac() -> None:
    validate = _load("terraform-validate.txt")
    fmt = _load("terraform-fmt.txt")
    tflint = _load("tflint.txt")
    checkov = _load("checkov-summary.json")
    gitleaks = _load("gitleaks-summary.json")
    plan = _load("terraform-plan-summary.json")
    status = _load("deployment-status.json")
    if plan:
        ui.kpi_row([("terraform plan", plan["plan"].replace("Plan: ", "").split(",")[0],
                     f"0 change · 0 destroy · Terraform {plan['terraform_version']}"),
                    ("Resources", plan["resources_to_create"], f"{len(plan['by_type'])} resource types"),
                    ("Applied", "No" if not plan.get("applied") else "Yes",
                     (status or {}).get("status", "")),
                    ("Checkov", f"{checkov['failed']} failed" if checkov else "n/a",
                     f"{checkov['passed']} passed · {checkov['skipped']} justified skips" if checkov else "")])
        if status:
            st.info(status["detail"])
        st.write("")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("##### terraform fmt / validate")
        if validate is None:
            _missing("terraform-validate.txt")
        else:
            st.code(((fmt or "") + "\n" + validate).strip(), language="text")
        st.markdown("##### tflint")
        st.code(tflint.strip() or "no issues", language="text") if tflint is not None else _missing("tflint.txt")
        if plan:
            st.markdown("##### Planned resources by type")
            st.dataframe(pd.DataFrame(sorted(plan["by_type"].items(), key=lambda kv: -kv[1]),
                                      columns=["Resource type", "Count"]), hide_index=True,
                         use_container_width=True, height=300)
    with c2:
        st.markdown("##### Checkov (IaC security scan)")
        if checkov is None:
            _missing("checkov-summary.json")
        else:
            st.markdown(f"Checkov {checkov['checkov_version']} over {checkov['resources']} resources: "
                        f"**{checkov['passed']} passed, {checkov['failed']} failed, {checkov['skipped']} skipped** "
                        "(each skip carries an in-code justification).")
            if checkov.get("skipped_checks"):
                skipped = pd.DataFrame(checkov["skipped_checks"])[["check", "justification", "resource"]]
                st.dataframe(skipped, hide_index=True, use_container_width=True, height=300,
                             column_config={"justification": st.column_config.TextColumn(width="large")})
            if checkov.get("failed_checks"):
                st.markdown("**Open findings**")
                st.dataframe(pd.DataFrame(checkov["failed_checks"]), hide_index=True, use_container_width=True)
        st.markdown("##### Secret scanning (gitleaks)")
        if gitleaks is None:
            _missing("gitleaks-summary.json")
        else:
            st.markdown(f"**{gitleaks['findings']} findings** in {gitleaks.get('scope', 'repository')} "
                        f"(gitleaks {gitleaks.get('version', '')}).")


def _simulations() -> None:
    sim = _load("simulation-results.json")
    if sim is None:
        _missing("simulation-results.json")
        return
    ui.kpi_row([("Scenarios passed", f"{sim['passed']}/{sim['total']}", "expected detections fired"),
                ("Target", sim["target"].split(":")[0], "SSH 2222 · Telnet 2223 · loopback only"),
                ("Run at", sim["generated_at"].replace("T", " ")[:16], "UTC"),
                ("Data origin", "SIMULATION", "never reported as live")])
    rows = [{"Scenario": s["title"], "Result": "PASS" if s["passed"] else "FAIL", "Events": s["events_captured"],
             "Expected rules": ", ".join(s["expected_rules"]), "Fired rules": ", ".join(s["fired_rules"]),
             "Techniques mapped": ", ".join(s["mapped_techniques"])} for s in sim["scenarios"]]
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.caption("Each scenario's events are evaluated in isolation, so a PASS means that scenario alone triggered "
               "every expected rule and ATT&CK technique.")
