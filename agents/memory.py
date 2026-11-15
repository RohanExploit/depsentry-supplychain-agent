"""Model-based persistent memory for DepSentry CVE watchlists and audit history."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_STATE: dict[str, Any] = {
    "agent_name": "DepSentry Supply-Chain Architect",
    "seen_advisory_ids": [],
    "audit_history": [],
    "total_audits": 0,
    "last_audit_utc": None,
}


class CVEMemoryStore:
    """Stores deduplicated OSV advisory IDs and historical SBOM audit risk scores."""

    def __init__(self, state_path: Path | str | None = None) -> None:
        base_dir = Path(__file__).resolve().parent.parent
        self.path = Path(state_path) if state_path else base_dir / "state" / "cve_memory.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return json.loads(json.dumps(DEFAULT_STATE))
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for key, val in DEFAULT_STATE.items():
                data.setdefault(key, json.loads(json.dumps(val)))
            return data
        except Exception:
            return json.loads(json.dumps(DEFAULT_STATE))

    def save(self, state: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def update_after_audit(
        self,
        target_label: str,
        advisory_ids: list[str],
        overall_risk: float,
        vuln_count: int,
        summary: str,
    ) -> dict[str, Any]:
        state = self.load()
        seen = set(state.get("seen_advisory_ids", []))
        new_ids = [aid for aid in advisory_ids if aid not in seen]
        state["seen_advisory_ids"] = (state.get("seen_advisory_ids", []) + new_ids)[-300:]

        now_iso = datetime.now(timezone.utc).isoformat()
        state["total_audits"] = int(state.get("total_audits", 0)) + 1
        state["last_audit_utc"] = now_iso
        state["audit_history"].append(
            {
                "timestamp_utc": now_iso,
                "target": target_label,
                "overall_risk": round(overall_risk, 1),
                "vulnerabilities": vuln_count,
                "new_cves_detected": len(new_ids),
                "summary": summary[:200],
            }
        )
        state["audit_history"] = state["audit_history"][-30:]
        self.save(state)
        return state
