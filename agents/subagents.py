"""Four specialized Supply-Chain Sub-Agents under DepSentry Architect."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

from .tools import (
    POPULAR_PYPI,
    fetch_pypi_metadata,
    levenshtein_distance,
    parse_requirements_text,
    query_osv_batch,
)


@dataclass
class SecurityBusMessage:
    sender: str
    recipient: str
    phase: str
    content: str
    confidence: float


@dataclass
class SupplyChainContext:
    raw_requirements: str
    seen_advisory_ids: set[str]
    packages: list[dict[str, Any]] = field(default_factory=list)
    osv_hits: dict[str, list[dict[str, str]]] = field(default_factory=dict)
    audited_rows: list[dict[str, Any]] = field(default_factory=list)
    patched_requirements: str = ""
    overall_risk: float = 0.0
    messages: list[SecurityBusMessage] = field(default_factory=list)

    def emit(self, sender: str, recipient: str, phase: str, content: str, confidence: float = 0.92) -> None:
        self.messages.append(SecurityBusMessage(sender, recipient, phase, content, round(confidence, 2)))


class SBOMManifestScoutAgent:
    """Sub-Agent 1: Parses manifest and enriches packages via live PyPI JSON metadata in parallel."""

    name = "SBOMManifestScoutAgent"

    def run(self, ctx: SupplyChainContext) -> None:
        specs = parse_requirements_text(ctx.raw_requirements)
        with ThreadPoolExecutor(max_workers=8) as pool:
            metas = list(pool.map(lambda s: fetch_pypi_metadata(s["name"]), specs))
        ctx.packages = [{**spec, **meta} for spec, meta in zip(specs, metas)]

        ctx.emit(
            self.name,
            "OSVVulnerabilityHunterAgent",
            "SENSE-SBOM",
            f"Resolved {len(ctx.packages)} packages against live PyPI registry.",
            confidence=0.96,
        )


class OSVVulnerabilityHunterAgent:
    """Sub-Agent 2: Queries Google OSV.dev batch API for live CVE/PYSEC advisories."""

    name = "OSVVulnerabilityHunterAgent"

    def run(self, ctx: SupplyChainContext) -> None:
        ctx.osv_hits = query_osv_batch(ctx.packages)
        total_cves = sum(len(v) for v in ctx.osv_hits.values())
        unseen = sum(1 for vlist in ctx.osv_hits.values() for v in vlist if v["id"] not in ctx.seen_advisory_ids)
        ctx.emit(
            self.name,
            "BusFactorLicenseCriticAgent",
            "HUNT-OSV",
            f"OSV.dev batch scan found {total_cves} advisories ({unseen} newly discovered vs cache).",
            confidence=0.95,
        )


class BusFactorLicenseCriticAgent:
    """Sub-Agent 3: Evaluates license conflicts, typosquatting proximity, and version drift."""

    name = "BusFactorLicenseCriticAgent"

    def run(self, ctx: SupplyChainContext) -> None:
        rows: list[dict[str, Any]] = []
        for pkg in ctx.packages:
            name = pkg["name"]
            vulns = ctx.osv_hits.get(name, [])
            vuln_ids = [v["id"] for v in vulns]
            pinned = pkg.get("pinned_version") or ""
            latest = pkg.get("latest_version") or "unknown"
            outdated = bool(pinned and latest != "unknown" and pinned != latest)

            typo_flag = ""
            if name not in POPULAR_PYPI:
                for popular in POPULAR_PYPI:
                    if levenshtein_distance(name, popular) == 1:
                        typo_flag = f"1-edit from `{popular}`"
                        break

            lic = (pkg.get("license") or "").upper()
            copyleft = any(tag in lic for tag in ("GPL", "AGPL"))

            score = 5.0
            score += min(65.0, len(vulns) * 24.0)
            score += 12.0 if outdated else 0.0
            score += 20.0 if typo_flag else 0.0
            score += 10.0 if copyleft else 0.0
            score = round(min(99.0, score), 1)

            status = "CRITICAL" if len(vulns) > 0 or typo_flag else ("REVIEW" if outdated or copyleft else "CLEAN")
            rows.append(
                {
                    "package": name,
                    "pinned": pinned or "unpinned",
                    "latest": latest,
                    "cve_count": len(vulns),
                    "advisories": ", ".join(vuln_ids[:3]) if vuln_ids else "None",
                    "license": pkg.get("license", "Unknown"),
                    "typo_alert": typo_flag or "None",
                    "risk_score": score,
                    "status": status,
                }
            )

        rows.sort(key=lambda r: r["risk_score"], reverse=True)
        ctx.audited_rows = rows
        ctx.overall_risk = round(max((r["risk_score"] for r in rows), default=0.0) * 0.65 + (sum(r["risk_score"] for r in rows) / max(len(rows), 1)) * 0.35, 1)

        crit_cnt = sum(1 for r in rows if r["status"] == "CRITICAL")
        ctx.emit(
            self.name,
            "PatchRemediationPlannerAgent",
            "CRITIQUE",
            f"Supply-chain risk={ctx.overall_risk}/100 ({crit_cnt} CRITICAL packages flagged).",
            confidence=0.93,
        )


class PatchRemediationPlannerAgent:
    """Sub-Agent 4: Generates drop-in upgraded requirements.txt to remediate CVEs."""

    name = "PatchRemediationPlannerAgent"

    def run(self, ctx: SupplyChainContext) -> None:
        lines = ["# Patched by DepSentry Autonomous Supply-Chain Guardian"]
        for row in ctx.audited_rows:
            if row["latest"] != "unknown":
                lines.append(f"{row['package']}>={row['latest']}  # was {row['pinned']} ({row['status']})")
            else:
                lines.append(f"{row['package']}  # verify manually")
        ctx.patched_requirements = "\n".join(lines)
        ctx.emit(
            self.name,
            "DepSentry Architect",
            "REMEDIATE",
            f"Compiled hardened upgrade manifest covering {len(ctx.audited_rows)} dependencies.",
            confidence=0.96,
        )
