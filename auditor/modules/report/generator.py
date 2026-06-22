"""Audit report generator — Markdown / JSON output."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from auditor.models import AuditSession, Finding, Priority


_PRIORITY_ORDER = {Priority.HIGH: 0, Priority.MEDIUM: 1, Priority.LOW: 2}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _PRIORITY_ORDER.get(f.priority, 99))


def generate_markdown(session: AuditSession) -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    findings = _sort_findings(session.findings)

    lines: list[str] = [
        f"# Informe de Auditoría de Seguridad",
        f"",
        f"**Target:** `{session.target.domain}`",
        f"**Fecha:** {now}",
        f"**Session ID:** `{session.id}`",
        f"",
        f"---",
        f"",
        f"## Resumen Ejecutivo",
        f"",
        f"| Prioridad | Cantidad |",
        f"|-----------|---------|",
        f"| Alta      | {session.high_count} |",
        f"| Media     | {session.medium_count} |",
        f"| Baja      | {session.low_count} |",
        f"| **Total** | **{len(findings)}** |",
        f"",
        f"---",
        f"",
        f"## Matriz de Hallazgos",
        f"",
        f"| ID | Componente | Vector | MITRE | Prioridad | Acción |",
        f"|----|-----------|--------|-------|-----------|--------|",
    ]

    for f in findings:
        lines.append(
            f"| {f.id} | {f.component} | {f.vector} | "
            f"`{f.mitre_id or '—'}` | **{f.priority.value.upper()}** | {f.remediation[:60]}... |"
        )

    lines += ["", "---", "", "## Hallazgos Detallados", ""]

    for f in findings:
        lines += [
            f"### [{f.priority.value.upper()}] {f.id} — {f.title}",
            f"",
            f"- **Componente:** {f.component}",
            f"- **Vector:** {f.vector}",
            f"- **MITRE ATT&CK:** `{f.mitre_id or 'N/A'}`",
            f"- **Severidad:** {f.severity.value}",
            f"",
            f"**Descripción:**",
            f"{f.description}",
            f"",
        ]
        if f.evidence:
            lines += [f"**Evidencia:**", f"```", f.evidence, f"```", ""]
        lines += [
            f"**Remediación:**",
            f"{f.remediation}",
            f"",
            f"---",
            f"",
        ]

    return "\n".join(lines)


def generate_json(session: AuditSession) -> str:
    return json.dumps(session.model_dump(mode="json"), indent=2, ensure_ascii=False)


def save_report(session: AuditSession, output_dir: Path, fmt: str = "markdown") -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    domain_slug = session.target.domain.replace(".", "_")

    if fmt == "json":
        path = output_dir / f"audit_{domain_slug}_{ts}.json"
        path.write_text(generate_json(session), encoding="utf-8")
    else:
        path = output_dir / f"audit_{domain_slug}_{ts}.md"
        path.write_text(generate_markdown(session), encoding="utf-8")

    return path
