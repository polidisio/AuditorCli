"""Tests for CheckRegistry."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from auditor.knowledge import CheckEntry, CheckRegistry


SEED_INDEX = {
    "_meta": {"skills_commit": "abc123", "generated_at": "2026-01-01T00:00:00+00:00"},
    "checks": {
        "M365-CA-001": {
            "skill_name": "auditing-entra-id-with-aadinternals",
            "mitre_id": "T1078.004",
            "mitre_tactic": "Initial Access",
            "remediation": "Create CA policy to block legacy auth.",
            "nist_csf": "PR.AC-05",
            "tags": ["entra-id", "mfa"],
        },
        "SPO-001": {
            "skill_name": "hunting-saas-sso-token-abuse",
            "mitre_id": "T1567.002",
            "mitre_tactic": "Exfiltration",
            "remediation": "Restrict anonymous sharing.",
            "nist_csf": None,
            "tags": [],
        },
    },
}


@pytest.fixture()
def registry(tmp_path: Path) -> CheckRegistry:
    index_file = tmp_path / "skills_index.json"
    index_file.write_text(json.dumps(SEED_INDEX), encoding="utf-8")
    return CheckRegistry(index_path=index_file)


def test_get_known_check(registry: CheckRegistry):
    entry = registry.get("M365-CA-001")
    assert entry is not None
    assert isinstance(entry, CheckEntry)
    assert entry.check_id == "M365-CA-001"
    assert entry.mitre_id == "T1078.004"
    assert entry.mitre_tactic == "Initial Access"
    assert "legacy auth" in entry.remediation.lower()


def test_get_unknown_check_returns_none(registry: CheckRegistry):
    assert registry.get("NONEXISTENT-999") is None


def test_registry_len(registry: CheckRegistry):
    assert len(registry) == 2


def test_tags_loaded(registry: CheckRegistry):
    entry = registry.get("M365-CA-001")
    assert "entra-id" in entry.tags


def test_empty_registry_when_file_missing(tmp_path: Path):
    reg = CheckRegistry(index_path=tmp_path / "nonexistent.json")
    assert len(reg) == 0
    assert reg.get("M365-CA-001") is None


def test_module_level_registry_imports():
    from auditor.knowledge import registry
    assert registry is not None
    # Must have loaded from committed skills_index.json (27 checks)
    assert len(registry) > 0
