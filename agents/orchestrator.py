"""Lead DepSentry Supply-Chain Architect orchestrating SBOM, OSV, Critic & Patch agents."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .llm_router import SynthesisResult, synthesize_with_fallback
from .memory import CVEMemoryStore
from .subagents import (
    BusFactorLicenseCriticAgent,
    OSVVulnerabilityHunterAgent,
    PatchRemediationPlannerAgent,
    SBOMManifestScoutAgent,
    SupplyChainContext,
)
from .tools import fetch_github_requirements

DEFAULT_REQUIREMENTS = """requests==2.25.1
urllib3==1.26.4
pillow==9.0.0
pyyaml==5.4.1
flask==2.0.1
streamlit==1.39.0
"""


def _universal_sec_fallback(ctx: SupplyChainContext) -> str:
    crit = [r for r in ctx.audited_rows if r["status"] == "CRITICAL"]
    total_cves = sum(r["cve_count"] for r in ctx.audited_rows)
    top_pkg = ctx.audited_rows[0] if ctx.audited_rows else {}
    return (
        f"### DepSentry Supply-Chain Security Dossier (Risk {ctx.overall_risk}/100)\n"
        f"- **Vulnerability Exposure**: Detected `{total_cves}` live OSV advisories across `{len(ctx.audited_rows)}` packages (`{len(crit)}` CRITICAL).\n"
        f"- **Highest Risk Dependency**: `{top_pkg.get('package', 'N/A')}` pinned at `{top_pkg.get('pinned', '')}` → latest `{top_pkg.get('latest', '')}` ({top_pkg.get('advisories', 'None')}).\n"
        f"- **Remediation Action**: Apply the generated patched `requirements.txt` and run regression tests before merging."
    )


class DepSentryArchitect:
    """Goal-Based + Model-Based + Utility-Based Software Supply-Chain Agent."""

    def __init__(self, memory_store: CVEMemoryStore | None = None) -> None:
        self.memory = memory_store or CVEMemoryStore()
        self.subagents = [
            SBOMManifestScoutAgent(),
            OSVVulnerabilityHunterAgent(),
            BusFactorLicenseCriticAgent(),
            PatchRemediationPlannerAgent(),
        ]

    def run_audit(
        self,
        requirements_text: str = DEFAULT_REQUIREMENTS,
        github_repo: str = "",
        gemini_key: str | None = None,
        groq_key: str | None = None,
    ) -> dict[str, Any]:
        target_label = "Custom Manifest"
        manifest = requirements_text.strip() or DEFAULT_REQUIREMENTS
        if github_repo.strip():
            pulled = fetch_github_requirements(github_repo)
            if pulled:
                manifest = pulled
                target_label = f"GitHub:{github_repo.strip()}"

        state = self.memory.load()
        ctx = SupplyChainContext(
            raw_requirements=manifest,
            seen_advisory_ids=set(state.get("seen_advisory_ids", [])),
        )
        ctx.emit(
            "DepSentry Architect",
            "SBOMManifestScoutAgent",
            "DELEGATE",
            f"Initiating autonomous SBOM + OSV CVE audit on `{target_label}`.",
            confidence=0.98,
        )

        for agent in self.subagents:
            agent.run(ctx)

        all_advisories = [v["id"] for vlist in ctx.osv_hits.values() for v in vlist]
        total_vulns = sum(r["cve_count"] for r in ctx.audited_rows)

        prompt = (
            f"You are DepSentry Supply-Chain Security Architect. Summarize this dependency audit in 3 crisp AppSec bullets "
            f"(Critical CVEs, Upgrade Priority, Governance Check) under 110 words.\n"
            f"Overall Risk: {ctx.overall_risk}/100\nRows: {ctx.audited_rows[:5]}"
        )
        synthesis: SynthesisResult = synthesize_with_fallback(
            prompt=prompt,
            system_instruction="Be accurate, AppSec-focused, and never fabricate CVE numbers.",
            universal_fallback_fn=lambda: _universal_sec_fallback(ctx),
            gemini_key=gemini_key,
            groq_key=groq_key,
        )

        updated_state = self.memory.update_after_audit(
            target_label=target_label,
            advisory_ids=all_advisories,
            overall_risk=ctx.overall_risk,
            vuln_count=total_vulns,
            summary=synthesis.text,
        )

        return {
            "target_label": target_label,
            "audited_rows": ctx.audited_rows,
            "overall_risk": ctx.overall_risk,
            "total_vulns": total_vulns,
            "patched_requirements": ctx.patched_requirements,
            "messages": [asdict(m) for m in ctx.messages],
            "synthesis": asdict(synthesis),
            "memory": updated_state,
        }
