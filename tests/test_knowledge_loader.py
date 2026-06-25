"""Tests for knowledge layer loader."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from auditor.knowledge.loader import build_index


FAKE_SKILL_MD = """\
---
name: fake-skill
description: A fake skill for testing.
domain: cybersecurity
subdomain: cloud-security
tags: test, fake
version: 1.0
author: test
license: Apache-2.0
nist_csf: DE.CM-01
mitre_attack: T1566.001
---

## Overview
Fake skill overview.

## Workflow
Step 1: Do the thing.
Step 2: Verify the thing.
This is the remediation guidance derived from the workflow section.

## Validation Criteria
Must not explode.
"""

FAKE_CHECK_MAP = """\
TEST-001:
  skill: fake-skill
  mitre_id: T1566.001
  remediation_override: null

TEST-002:
  skill: null
  mitre_id: T1078.004
  remediation_override: "Hardcoded remediation text."

TEST-003:
  skill: fake-skill
  mitre_id: null
  remediation_override: null
"""


@pytest.fixture()
def fake_skills_dir(tmp_path: Path) -> Path:
    skill_dir = tmp_path / "skills" / "fake-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(FAKE_SKILL_MD, encoding="utf-8")
    return tmp_path / "skills"


@pytest.fixture()
def check_map_path(tmp_path: Path) -> Path:
    p = tmp_path / "check_map.yaml"
    p.write_text(FAKE_CHECK_MAP, encoding="utf-8")
    return p


@pytest.fixture()
def index_path(tmp_path: Path) -> Path:
    return tmp_path / "skills_index.json"


def _fake_git_commit(skills_dir: Path) -> str:
    return "abc123def456"


def test_build_index_generates_file(fake_skills_dir, check_map_path, index_path):
    with patch("auditor.knowledge.loader._git_commit", return_value="abc123"):
        build_index(fake_skills_dir, check_map_path, index_path)

    assert index_path.exists()
    data = json.loads(index_path.read_text())
    assert data["_meta"]["skills_commit"] == "abc123"
    assert "checks" in data
    assert "TEST-001" in data["checks"]
    assert "TEST-002" in data["checks"]


def test_skill_remediation_extracted(fake_skills_dir, check_map_path, index_path):
    with patch("auditor.knowledge.loader._git_commit", return_value="abc123"):
        build_index(fake_skills_dir, check_map_path, index_path)

    data = json.loads(index_path.read_text())
    entry = data["checks"]["TEST-001"]
    assert entry["mitre_id"] == "T1566.001"
    assert entry["mitre_tactic"] == "Initial Access"
    assert "Step 1" in entry["remediation"]  # from ## Workflow section


def test_remediation_override_takes_precedence(fake_skills_dir, check_map_path, index_path):
    with patch("auditor.knowledge.loader._git_commit", return_value="abc123"):
        build_index(fake_skills_dir, check_map_path, index_path)

    data = json.loads(index_path.read_text())
    entry = data["checks"]["TEST-002"]
    assert entry["remediation"] == "Hardcoded remediation text."


def test_mitre_id_from_skill_when_not_in_check_map(fake_skills_dir, check_map_path, index_path):
    with patch("auditor.knowledge.loader._git_commit", return_value="abc123"):
        build_index(fake_skills_dir, check_map_path, index_path)

    data = json.loads(index_path.read_text())
    # TEST-003 has mitre_id: null in check_map, so should fall back to skill frontmatter
    entry = data["checks"]["TEST-003"]
    assert entry["mitre_id"] == "T1566.001"


def test_idempotent_when_commit_unchanged(fake_skills_dir, check_map_path, index_path):
    with patch("auditor.knowledge.loader._git_commit", return_value="abc123"):
        build_index(fake_skills_dir, check_map_path, index_path)
        mtime_1 = index_path.stat().st_mtime

        # Second call with same commit — should not rewrite
        build_index(fake_skills_dir, check_map_path, index_path)
        mtime_2 = index_path.stat().st_mtime

    assert mtime_1 == mtime_2


def test_fallback_when_skills_dir_absent(check_map_path, index_path, tmp_path):
    absent_dir = tmp_path / "nonexistent_skills"
    build_index(absent_dir, check_map_path, index_path)

    assert index_path.exists()
    data = json.loads(index_path.read_text())
    assert data["_meta"]["skills_commit"] is None
    # Checks still generated (from check_map only)
    assert "TEST-002" in data["checks"]
    assert data["checks"]["TEST-002"]["remediation"] == "Hardcoded remediation text."
