"""DepSentry — Brutalist Security Lab UI with Live n8n Supply-Chain Workflow."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from agents.orchestrator import DEFAULT_REQUIREMENTS, DepSentryArchitect
from agents.workflow_viz import render_n8n_workflow

st.set_page_config(
    page_title="DepSentry | Autonomous Supply-Chain & CVE Guardian",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

SAMPLES = {
    "Legacy Vulnerable Stack (Default)": {"repo": "", "req": DEFAULT_REQUIREMENTS},
    "PyData & HTTP Stack (Old Pins)": {"repo": "", "req": "urllib3==1.26.5\nnumpy==1.21.0\njinja2==3.0.1\nrequests==2.25.1"},
    "Public GitHub Repo: pallets/flask": {"repo": "pallets/flask", "req": DEFAULT_REQUIREMENTS},
    "Public GitHub Repo: psf/requests": {"repo": "psf/requests", "req": DEFAULT_REQUIREMENTS},
}

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Fira+Code:wght@400;600&display=swap');
html, body, [class*="css"] { font-family: 'Plus Jakarta Sans', sans-serif; color: #0F172A; }
code, pre, .mono { font-family: 'Fira Code', monospace !important; }
.stApp { background: #F8FAFC; }
@keyframes popIn { from { opacity:0; transform:translateY(6px);} to { opacity:1; transform:translateY(0);} }
.sec-banner {
    animation: popIn .4s ease-out;
    background: #FFFFFF;
    border: 2px solid #0F172A;
    box-shadow: 6px 6px 0px #0F172A;
    border-radius: 6px;
    padding: 1rem 1.35rem;
    margin-bottom: 1rem;
}
.brutal-card {
    background: #FFFFFF;
    border: 2px solid #0F172A;
    box-shadow: 4px 4px 0px #2563EB;
    border-radius: 6px;
    padding: 0.8rem 0.95rem;
    transition: transform .18s ease, box-shadow .18s ease;
}
.brutal-card:hover { transform: translate(-2px,-2px); box-shadow: 6px 6px 0px #0F172A; }
</style>
""",
    unsafe_allow_html=True,
)

if "dep_repo" not in st.session_state:
    st.session_state.dep_repo = ""
    st.session_state.dep_req = DEFAULT_REQUIREMENTS


def _apply_dep_sample() -> None:
    s = SAMPLES[st.session_state.dep_sample]
    st.session_state.dep_repo = s["repo"]
    st.session_state.dep_req = s["req"]
    st.session_state.dep_force = True


with st.sidebar:
    st.markdown("### Sample Audit Scenarios")
    st.selectbox("Load Sample Stack", list(SAMPLES.keys()), key="dep_sample", on_change=_apply_dep_sample)
    st.markdown("### Audit Target")
    gh_repo = st.text_input("Public GitHub Repo (owner/repo)", key="dep_repo", placeholder="e.g., pallets/flask")
    req_input = st.text_area("requirements.txt", key="dep_req", height=130)
    with st.expander("AI Brain Keys (Optional)"):
        gemini_key = st.text_input("Gemini API Key Override", type="password")
        groq_key = st.text_input("Groq API Key Override", type="password")
    run_btn = st.button("Run CVE Audit", type="primary", width="stretch")
    st.caption("Mukundraj Bhosale · BTCOC701")

if "depsentry_res" not in st.session_state or run_btn or st.session_state.pop("dep_force", False):
    with st.spinner("Querying PyPI JSON & Google OSV.dev batch advisories..."):
        st.session_state.depsentry_res = DepSentryArchitect().run_audit(
            requirements_text=req_input,
            github_repo=gh_repo,
            gemini_key=gemini_key,
            groq_key=groq_key,
        )

res = st.session_state.depsentry_res
df = pd.DataFrame(res["audited_rows"])
crit_count = int((df["status"] == "CRITICAL").sum()) if not df.empty else 0
msgs = res["messages"]

st.markdown(
    f"""
<div class="sec-banner">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.7rem;">
    <div>
      <h2 style="margin:0; font-weight:800;">DepSentry — Supply-Chain &amp; CVE Guardian</h2>
      <div class="mono" style="color:#475569; font-size:0.82rem;">Target: {res['target_label']} · PyPI Registry · Google OSV.dev · Levenshtein Guard</div>
    </div>
    <div class="mono" style="background:{'#DC2626' if res['total_vulns']>0 else '#059669'}; color:#FFFFFF; padding:0.35rem 0.8rem; font-weight:700; border:2px solid #0F172A;">
      RISK {res['overall_risk']}/100 · {res['total_vulns']} CVEs
    </div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

c1, c2, c3, c4 = st.columns(4)
c1.markdown(f'<div class="brutal-card"><div style="font-size:0.72rem;color:#475569;font-weight:700;">PACKAGES</div><div style="font-size:1.45rem;font-weight:800;">{len(df)}</div></div>', unsafe_allow_html=True)
c2.markdown(f'<div class="brutal-card"><div style="font-size:0.72rem;color:#475569;font-weight:700;">CRITICAL</div><div style="font-size:1.45rem;font-weight:800;color:#DC2626;">{crit_count}</div></div>', unsafe_allow_html=True)
c3.markdown(f'<div class="brutal-card"><div style="font-size:0.72rem;color:#475569;font-weight:700;">AUDITS RUN</div><div style="font-size:1.45rem;font-weight:800;">{res["memory"]["total_audits"]}</div></div>', unsafe_allow_html=True)
c4.markdown(f'<div class="brutal-card"><div style="font-size:0.72rem;color:#475569;font-weight:700;">AI ENGINE</div><div style="font-size:1.05rem;font-weight:800;padding-top:0.2rem;">{res["synthesis"]["model"]}</div></div>', unsafe_allow_html=True)

st.markdown("")
wf_nodes = [
    {"title": "DepSentry Lead", "role": "Orchestrator", "phase": "TRIGGER", "metric": f"{len(df)} pkgs", "payload": f"Auditing target '{res['target_label']}' against state/cve_memory.json", "confidence": 0.99, "color": "#2563EB", "icon": "🔐"},
    {"title": "SBOMManifestScout", "role": "Scout 1", "phase": "PYPI", "metric": f"{len(df)} resolved", "payload": msgs[0]["content"] if len(msgs) > 0 else "Parsed requirements + PyPI metadata", "confidence": msgs[0]["confidence"] if len(msgs) > 0 else 0.95, "color": "#0284C7", "icon": "📦"},
    {"title": "OSVVulnHunter", "role": "Scout 2", "phase": "OSV.DEV", "metric": f"{res['total_vulns']} CVEs", "payload": msgs[1]["content"] if len(msgs) > 1 else "Submitted OSV batch query", "confidence": msgs[1]["confidence"] if len(msgs) > 1 else 0.96, "color": "#DC2626", "icon": "🛡️"},
    {"title": "LicenseTypoCritic", "role": "Critic", "phase": "CRITIQUE", "metric": f"Risk {res['overall_risk']}/100", "payload": msgs[2]["content"] if len(msgs) > 2 else "Checked typosquatting + license", "confidence": msgs[2]["confidence"] if len(msgs) > 2 else 0.92, "color": "#F59E0B", "icon": "⚖️"},
    {"title": "PatchPlanner", "role": "Planner", "phase": "PATCH", "metric": "Manifest Ready", "payload": msgs[3]["content"] if len(msgs) > 3 else "Generated patched requirements.txt", "confidence": msgs[3]["confidence"] if len(msgs) > 3 else 0.94, "color": "#059669", "icon": "🩹"},
    {"title": "CVE Cache + Lab UI", "role": "Memory", "phase": "PERSIST", "metric": res["synthesis"]["provider"].split()[0], "payload": f"Cached advisories across {res['memory']['total_audits']} audits", "confidence": 0.98, "color": "#2563EB", "icon": "💾"},
]
render_n8n_workflow(
    wf_nodes,
    theme={"mode": "light", "bg": "#F1F5F9", "card_bg": "#FFFFFF", "border": "#0F172A", "accent": "#2563EB", "text": "#0F172A", "muted": "#475569", "bar_bg": "#FFFFFF"},
    engine_label=f"DepSentry AppSec DAG · {res['synthesis']['provider']}",
)

t1, t2, t3 = st.tabs(["Risk Charts & Patched Manifest", "Vulnerability Matrix", "Agent Bus & Memory"])

with t1:
    g1, g2 = st.columns([1.35, 1])
    with g1:
        if not df.empty:
            fig = px.bar(df, x="package", y="risk_score", color="status", text="cve_count", color_discrete_map={"CRITICAL": "#DC2626", "REVIEW": "#F59E0B", "CLEAN": "#059669"}, title="Risk Score & CVE Count per Package")
            fig.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#F8FAFC", height=300, margin=dict(l=10, r=10, t=35, b=10))
            st.plotly_chart(fig, width="stretch")
    with g2:
        if not df.empty:
            status_counts = df["status"].value_counts().reset_index()
            status_counts.columns = ["status", "count"]
            fig_d = px.pie(status_counts, names="status", values="count", hole=0.55, color="status", color_discrete_map={"CRITICAL": "#DC2626", "REVIEW": "#F59E0B", "CLEAN": "#059669"}, title="Dependency Severity Mix")
            fig_d.update_layout(paper_bgcolor="#FFFFFF", height=300, margin=dict(l=10, r=10, t=35, b=10))
            st.plotly_chart(fig_d, width="stretch")

    c_patch, c_brief = st.columns([1.2, 1])
    with c_patch:
        st.markdown("#### Auto-Hardened `requirements.txt`")
        st.code(res["patched_requirements"], language="text")
        st.download_button("Download Patched requirements.txt", data=res["patched_requirements"], file_name="requirements.patched.txt", mime="text/plain", width="stretch")
    with c_brief:
        st.markdown("#### Overall Security Gauge")
        gauge = go.Figure(go.Indicator(mode="gauge+number", value=float(res["overall_risk"]), title={"text": "Supply-Chain Risk Index"}, gauge={"axis": {"range": [0, 100]}, "bar": {"color": "#DC2626" if res["overall_risk"] >= 50 else "#059669"}}))
        gauge.update_layout(paper_bgcolor="#FFFFFF", height=230, margin=dict(l=15, r=15, t=35, b=10))
        st.plotly_chart(gauge, width="stretch")
        with st.expander(f"AI Dossier ({res['synthesis']['provider']})", expanded=False):
            st.write(res["synthesis"]["text"])

with t2:
    if not df.empty:
        st.dataframe(
            df,
            width="stretch",
            hide_index=True,
            column_config={
                "risk_score": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%d/100"),
                "cve_count": st.column_config.NumberColumn("CVEs", format="%d"),
            },
        )

with t3:
    mdf = pd.DataFrame(msgs)
    if not mdf.empty:
        st.plotly_chart(px.bar(mdf, x="sender", y="confidence", color="phase", title="Sub-Agent Execution Confidence", height=240).update_layout(paper_bgcolor="#FFFFFF"), width="stretch")
        st.dataframe(mdf[["phase", "sender", "recipient", "confidence", "content"]], width="stretch", hide_index=True)
    if res["memory"].get("audit_history"):
        st.dataframe(pd.DataFrame(res["memory"]["audit_history"]), width="stretch", hide_index=True)
    st.table(pd.DataFrame([{"PEAS": "P", "Spec": "CVE recall & clean patch manifest"}, {"PEAS": "E", "Spec": "PyPI, Google OSV.dev, GitHub Raw"}, {"PEAS": "A", "Spec": "Security UI, Patched Manifest, CVE Cache"}, {"PEAS": "S", "Spec": "Pinned packages, PyPI metadata, OSV advisories"}]))
