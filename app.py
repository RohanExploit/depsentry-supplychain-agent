"""DepSentry — Brutalist Neo-Editorial Security Lab UI (Crisp Light Mode)."""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from agents.orchestrator import DEFAULT_REQUIREMENTS, DepSentryArchitect

st.set_page_config(
    page_title="DepSentry | Autonomous Supply-Chain & CVE Guardian",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;700;800&family=Fira+Code:wght@400;600&display=swap');

html, body, [class*="css"] { font-family: 'Plus Jakarta Sans', sans-serif; color: #0F172A; }
code, pre, .mono { font-family: 'Fira Code', monospace !important; }
.stApp { background: #F8FAFC; }
.sec-banner {
    background: #FFFFFF;
    border: 2px solid #0F172A;
    box-shadow: 6px 6px 0px #0F172A;
    border-radius: 6px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.2rem;
}
.brutal-card {
    background: #FFFFFF;
    border: 2px solid #0F172A;
    box-shadow: 4px 4px 0px #2563EB;
    border-radius: 6px;
    padding: 0.9rem 1rem;
}
.bus-row {
    background: #FFFFFF;
    border: 1.5px solid #0F172A;
    border-left: 5px solid #2563EB;
    padding: 0.7rem 0.95rem;
    margin-bottom: 0.55rem;
}
</style>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("### Audit Target")
    gh_repo = st.text_input("Optional Public GitHub Repo (pulls requirements.txt)", placeholder="e.g., pallets/flask")
    req_input = st.text_area("Or Paste requirements.txt", value=DEFAULT_REQUIREMENTS, height=160)
    with st.expander("AI Brain Keys (Optional — 90% Keyless)"):
        gemini_key = st.text_input("Gemini API Key Override", type="password")
        groq_key = st.text_input("Groq API Key Override", type="password")
    run_btn = st.button("Run Autonomous CVE Audit", type="primary", use_container_width=True)
    st.caption("Built by Mukundraj Bhosale | BTCOC701 CAS Activity-I")

if "depsentry_res" not in st.session_state or run_btn:
    with st.spinner("DepSentry auditing PyPI metadata & Google OSV.dev batch CVEs..."):
        st.session_state.depsentry_res = DepSentryArchitect().run_audit(
            requirements_text=req_input,
            github_repo=gh_repo,
            gemini_key=gemini_key,
            groq_key=groq_key,
        )

res = st.session_state.depsentry_res
df = pd.DataFrame(res["audited_rows"])
crit_count = int((df["status"] == "CRITICAL").sum()) if not df.empty else 0

st.markdown(
    f"""
<div class="sec-banner">
  <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.8rem;">
    <div>
      <h2 style="margin:0; font-weight:800; letter-spacing:-0.02em;">DepSentry — Autonomous Supply-Chain &amp; CVE Guardian</h2>
      <div style="color:#475569; margin-top:0.25rem;">Live cross-verification across PyPI Registry, Google OSV.dev Vulnerability Batch API &amp; GitHub Repos</div>
    </div>
    <div class="mono" style="background:#DC2626; color:#FFFFFF; padding:0.35rem 0.75rem; font-weight:600; border:2px solid #0F172A;">
      RISK {res['overall_risk']}/100 · {res['total_vulns']} CVEs
    </div>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f'<div class="brutal-card"><div style="font-size:0.75rem;color:#475569;font-weight:700;">PACKAGES AUDITED</div><div style="font-size:1.5rem;font-weight:800;">{len(df)}</div></div>', unsafe_allow_html=True)
with c2:
    st.markdown(f'<div class="brutal-card"><div style="font-size:0.75rem;color:#475569;font-weight:700;">CRITICAL PACKAGES</div><div style="font-size:1.5rem;font-weight:800;color:#DC2626;">{crit_count}</div></div>', unsafe_allow_html=True)
with c3:
    st.markdown(f'<div class="brutal-card"><div style="font-size:0.75rem;color:#475569;font-weight:700;">MEMORY AUDITS</div><div style="font-size:1.5rem;font-weight:800;">{res["memory"]["total_audits"]}</div></div>', unsafe_allow_html=True)
with c4:
    st.markdown(f'<div class="brutal-card"><div style="font-size:0.75rem;color:#475569;font-weight:700;">10% AI LAYER</div><div style="font-size:1.05rem;font-weight:800;padding-top:0.25rem;">{res["synthesis"]["provider"]}</div></div>', unsafe_allow_html=True)

st.markdown("")
t1, t2, t3 = st.tabs(["SBOM Risk & Patch Generator", "Sub-Agent Security Trace", "PEAS & CVE Memory"])

with t1:
    left, right = st.columns([1.3, 1])
    with left:
        st.subheader("Package Risk Breakdown")
        if not df.empty:
            fig = px.bar(
                df,
                x="package",
                y="risk_score",
                color="status",
                color_discrete_map={"CRITICAL": "#DC2626", "REVIEW": "#F59E0B", "CLEAN": "#059669"},
                title="Composite Supply-Chain Risk per Dependency",
            )
            fig.update_layout(paper_bgcolor="#FFFFFF", plot_bgcolor="#F8FAFC", height=300, margin=dict(l=10, r=10, t=35, b=10))
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(df, use_container_width=True, hide_index=True)

    with right:
        st.subheader("Security Architect Dossier")
        st.warning(res["synthesis"]["text"])
        st.subheader("Auto-Generated Patched Manifest")
        st.code(res["patched_requirements"], language="text")
        st.download_button(
            "Download Patched requirements.txt",
            data=res["patched_requirements"],
            file_name="requirements.patched.txt",
            mime="text/plain",
            use_container_width=True,
        )

with t2:
    st.subheader("Inter-Agent Audit Pipeline")
    for m in res["messages"]:
        st.markdown(
            f'<div class="bus-row"><div class="mono" style="font-size:0.78rem;color:#2563EB;font-weight:600;">[{m["phase"]}] {m["sender"]} → {m["recipient"]} (conf={m["confidence"]})</div><div style="margin-top:0.2rem;">{m["content"]}</div></div>',
            unsafe_allow_html=True,
        )

with t3:
    st.subheader("PEAS Specification")
    st.table(
        pd.DataFrame(
            [
                {"Component": "P — Performance Measure", "Description": "CVE detection recall via OSV.dev, zero false-clean verdicts, safe upgrade manifest generation."},
                {"Component": "E — Environment", "Description": "PyPI JSON registry, Google OSV.dev API, GitHub raw manifests, Streamlit Cloud & GitHub Actions."},
                {"Component": "A — Actuators", "Description": "Interactive risk dossier, downloadable patched requirements.txt, CVE baseline cache updater."},
                {"Component": "S — Sensors", "Description": "Pinned manifest specs, PyPI release metadata, OSV batch advisories, state/cve_memory.json."},
            ]
        )
    )
    if res["memory"].get("audit_history"):
        st.dataframe(pd.DataFrame(res["memory"]["audit_history"]), use_container_width=True, hide_index=True)
