"""Knowledge layer — maps check IDs to MITRE metadata and remediation from skill sources."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_INDEX_PATH = Path(__file__).parent / "skills_index.json"


@dataclass
class CheckEntry:
    check_id: str
    skill_name: str | None
    mitre_id: str | None
    mitre_tactic: str | None
    remediation: str
    nist_csf: str | None = field(default=None)
    tags: list[str] = field(default_factory=list)


class CheckRegistry:
    def __init__(self, index_path: Path = _INDEX_PATH) -> None:
        self._entries: dict[str, CheckEntry] = {}
        self._load(index_path)

    def _load(self, path: Path) -> None:
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for check_id, entry in data.get("checks", {}).items():
                self._entries[check_id] = CheckEntry(
                    check_id=check_id,
                    skill_name=entry.get("skill_name"),
                    mitre_id=entry.get("mitre_id"),
                    mitre_tactic=entry.get("mitre_tactic"),
                    remediation=entry.get("remediation", ""),
                    nist_csf=entry.get("nist_csf"),
                    tags=entry.get("tags", []),
                )
        except Exception:
            pass

    def get(self, check_id: str) -> CheckEntry | None:
        return self._entries.get(check_id)

    def __len__(self) -> int:
        return len(self._entries)


registry = CheckRegistry()
