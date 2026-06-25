"""Build and update skills_index.json from check_map.yaml + skills submodule."""
from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_HERE = Path(__file__).parent
_REPO_ROOT = _HERE.parent.parent

DEFAULT_MAP_PATH = _HERE / "check_map.yaml"
DEFAULT_SKILLS_DIR = _REPO_ROOT / "skills" / "skills"
DEFAULT_INDEX_PATH = _HERE / "skills_index.json"

# MITRE ATT&CK technique → tactic name (covers all techniques used in check_map.yaml)
_TACTIC_MAP: dict[str, str] = {
    "T1078":     "Initial Access",
    "T1078.004": "Initial Access",
    "T1087":     "Discovery",
    "T1087.004": "Discovery",
    "T1098":     "Persistence",
    "T1098.001": "Persistence",
    "T1114":     "Collection",
    "T1114.003": "Collection",
    "T1528":     "Credential Access",
    "T1550":     "Defense Evasion",
    "T1550.001": "Defense Evasion",
    "T1556":     "Credential Access",
    "T1556.007": "Credential Access",
    "T1557":     "Collection",
    "T1557.002": "Collection",
    "T1566":     "Initial Access",
    "T1566.001": "Initial Access",
    "T1566.003": "Initial Access",
    "T1567":     "Exfiltration",
    "T1567.002": "Exfiltration",
    "T1606":     "Credential Access",
    "T1606.002": "Credential Access",
}


def _git_commit(skills_dir: Path) -> str | None:
    """Return HEAD commit hash of the skills submodule, or None if unavailable."""
    try:
        result = subprocess.run(
            ["git", "-C", str(skills_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def _parse_skill_md(skill_md: Path) -> dict[str, Any]:
    """Parse a SKILL.md file and return frontmatter + remediation text."""
    if not skill_md.exists():
        return {}

    text = skill_md.read_text(encoding="utf-8", errors="replace")

    # Extract YAML frontmatter between first two --- markers
    frontmatter: dict[str, Any] = {}
    fm_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if fm_match:
        try:
            frontmatter = yaml.safe_load(fm_match.group(1)) or {}
        except yaml.YAMLError:
            pass

    # Extract remediation from preferred sections (first 600 chars of body)
    body = text[fm_match.end():] if fm_match else text
    remediation = ""
    for section_name in (
        "## Workflow",
        "## Detection and OPSEC Notes",
        "## Validation Criteria",
        "## Steps",
    ):
        idx = body.find(section_name)
        if idx == -1:
            continue
        section_start = idx + len(section_name)
        # Find next ## heading or end of file
        next_heading = re.search(r"\n## ", body[section_start:])
        section_body = (
            body[section_start: section_start + next_heading.start()]
            if next_heading
            else body[section_start:]
        )
        remediation = section_body.strip()[:600]
        break

    return {
        "mitre_attack": frontmatter.get("mitre_attack", ""),
        "nist_csf": frontmatter.get("nist_csf", ""),
        "tags": [t.strip() for t in str(frontmatter.get("tags", "")).split(",") if t.strip()],
        "remediation": remediation,
    }


def build_index(
    skills_dir: Path = DEFAULT_SKILLS_DIR,
    map_path: Path = DEFAULT_MAP_PATH,
    index_path: Path = DEFAULT_INDEX_PATH,
) -> None:
    """
    Generate skills_index.json from check_map.yaml, enriched with SKILL.md data.

    Idempotent: if the skills submodule commit hasn't changed and index exists, skip.
    Falls back gracefully when skills_dir is absent.
    """
    # Load check map
    check_map: dict[str, Any] = yaml.safe_load(map_path.read_text(encoding="utf-8")) or {}

    # Check current skills commit
    skills_commit = _git_commit(skills_dir) if skills_dir.exists() else None

    # Idempotency: skip if commit unchanged
    if index_path.exists() and skills_commit:
        try:
            existing = json.loads(index_path.read_text(encoding="utf-8"))
            if existing.get("_meta", {}).get("skills_commit") == skills_commit:
                return
        except Exception:
            pass

    checks: dict[str, Any] = {}

    for check_id, cfg in check_map.items():
        if not isinstance(cfg, dict):
            continue

        skill_name: str | None = cfg.get("skill") or None
        canonical_mitre: str | None = cfg.get("mitre_id") or None
        remediation_override: str | None = cfg.get("remediation_override") or None

        skill_data: dict[str, Any] = {}
        if skill_name and skills_dir.exists():
            skill_md = skills_dir / skill_name / "SKILL.md"
            skill_data = _parse_skill_md(skill_md)

        # MITRE ID: check_map overrides skill; skill as fallback
        mitre_id = canonical_mitre
        if not mitre_id and skill_data.get("mitre_attack"):
            raw = str(skill_data["mitre_attack"])
            mitre_id = raw.split(",")[0].strip() or None

        mitre_tactic = _TACTIC_MAP.get(mitre_id or "") if mitre_id else None

        # Remediation: override → skill body → empty string
        remediation: str = (
            remediation_override
            if remediation_override
            else skill_data.get("remediation", "")
        )

        checks[check_id] = {
            "skill_name": skill_name,
            "mitre_id": mitre_id,
            "mitre_tactic": mitre_tactic,
            "remediation": remediation,
            "nist_csf": skill_data.get("nist_csf") or None,
            "tags": skill_data.get("tags", []),
        }

    index: dict[str, Any] = {
        "_meta": {
            "skills_commit": skills_commit,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "skills_repo": "https://github.com/mukul975/Anthropic-Cybersecurity-Skills",
        },
        "checks": checks,
    }

    index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False), encoding="utf-8")


if __name__ == "__main__":
    build_index()
    print(f"Index written to {DEFAULT_INDEX_PATH}")
