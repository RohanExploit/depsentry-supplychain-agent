"""Headless autonomous runner for nightly DepSentry CVE & supply-chain scans."""

from __future__ import annotations

import json
import os

from agents.orchestrator import DEFAULT_REQUIREMENTS, DepSentryArchitect


def main() -> None:
    repo = os.environ.get("DEPSENTRY_REPO", "")
    res = DepSentryArchitect().run_audit(requirements_text=DEFAULT_REQUIREMENTS, github_repo=repo)
    print(
        json.dumps(
            {
                "target": res["target_label"],
                "overall_risk": res["overall_risk"],
                "total_vulns": res["total_vulns"],
                "provider": res["synthesis"]["provider"],
                "total_audits": res["memory"]["total_audits"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
