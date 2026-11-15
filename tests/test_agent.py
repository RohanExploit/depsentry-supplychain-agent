"""Automated pytest suite for DepSentry supply-chain guardian."""

from __future__ import annotations

from pathlib import Path

from agents.memory import CVEMemoryStore
from agents.orchestrator import DepSentryArchitect
from agents.tools import levenshtein_distance, parse_requirements_text


def test_parse_requirements_extracts_pins() -> None:
    parsed = parse_requirements_text("requests==2.25.1\n# comment\nFlask>=2.0.0\n")
    assert len(parsed) == 2
    assert parsed[0]["name"] == "requests"
    assert parsed[0]["pinned_version"] == "2.25.1"
    assert parsed[1]["name"] == "flask"


def test_typosquatting_distance() -> None:
    assert levenshtein_distance("reqeusts", "requests") == 2
    assert levenshtein_distance("request", "requests") == 1


def test_cve_memory_deduplicates(tmp_path: Path) -> None:
    store = CVEMemoryStore(tmp_path / "cve.json")
    s1 = store.update_after_audit("repo", ["PYSEC-1", "GHSA-2"], 75.0, 2, "warn")
    s2 = store.update_after_audit("repo", ["GHSA-2", "PYSEC-3"], 40.0, 1, "ok")
    assert s1["seen_advisory_ids"] == ["PYSEC-1", "GHSA-2"]
    assert s2["seen_advisory_ids"] == ["PYSEC-1", "GHSA-2", "PYSEC-3"]


def test_full_audit_mocked(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "agents.subagents.fetch_pypi_metadata",
        lambda name: {"name": name, "latest_version": "2.32.3", "license": "MIT", "author": "psf", "release_count": 10, "latest_release_date": "2026-01-01", "github_url": "", "source": "mock"},
    )
    monkeypatch.setattr(
        "agents.subagents.query_osv_batch",
        lambda pkgs: {p["name"]: [{"id": "PYSEC-2023-74", "modified": "2024-01-01"}] for p in pkgs},
    )
    out = DepSentryArchitect(CVEMemoryStore(tmp_path / "cve.json")).run_audit("requests==2.25.1", gemini_key="", groq_key="")
    assert out["total_vulns"] == 1
    assert "requests>=2.32.3" in out["patched_requirements"]
    assert len(out["messages"]) == 5
