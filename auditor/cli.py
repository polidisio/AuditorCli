"""AuditorCli — entry point."""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.prompt import Confirm

from auditor.config import get_settings
from auditor.knowledge import registry as _kr
from auditor.models import AuditSession, AuditTarget
from auditor.utils.console import console, print_banner, print_findings_table, print_step, print_ok, print_err, print_warn
from auditor.utils.validators import validate_domain


app = typer.Typer(
    name="auditor",
    help="Security audit CLI — Web · Network · M365/Entra ID",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

web_app = typer.Typer(help="Web application and network reconnaissance")
m365_app = typer.Typer(help="M365 / Entra ID tenant audit")
report_app = typer.Typer(help="Report generation")
knowledge_app = typer.Typer(help="Knowledge base management")

app.add_typer(web_app, name="web")
app.add_typer(m365_app, name="m365")
app.add_typer(report_app, name="report")
app.add_typer(knowledge_app, name="knowledge")


# ─── Web commands ─────────────────────────────────────────────────────────────

@web_app.command("recon")
def web_recon(
    target: Annotated[str, typer.Option("--target", "-t", help="Target domain")],
    authorized: Annotated[bool, typer.Option("--authorized", help="Confirm you are authorized to perform active scans")] = False,
    passive_only: Annotated[bool, typer.Option("--passive-only", help="Skip active scanning (nmap, nuclei)")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="Report format: markdown | json | xlsx")] = "markdown",
) -> None:
    """Web application and network reconnaissance."""
    print_banner()
    settings = get_settings()
    out_dir = output or settings.output_dir

    try:
        domain = validate_domain(target)
    except ValueError as e:
        print_err(str(e))
        raise typer.Exit(1)

    if not passive_only and not authorized:
        print_warn("Active scanning (nmap, nuclei) requires explicit authorization.")
        print_warn("Re-run with [bold]--authorized[/] flag after confirming written authorization.")
        passive_only = True

    session = AuditSession(
        id=str(uuid.uuid4())[:8],
        target=AuditTarget(domain=domain, authorized=authorized),
    )

    asyncio.run(_web_recon_async(domain, session, passive_only, out_dir, fmt))


def _sev_from_tag(tag: str) -> tuple["Severity", "Priority"]:
    from auditor.models import Severity, Priority
    _map = {
        "CRITICAL": (Severity.CRITICAL, Priority.HIGH),
        "HIGH":     (Severity.HIGH,     Priority.HIGH),
        "MEDIUM":   (Severity.MEDIUM,   Priority.MEDIUM),
        "LOW":      (Severity.LOW,      Priority.LOW),
        "INFO":     (Severity.INFO,     Priority.LOW),
    }
    return _map.get(tag.upper(), (Severity.MEDIUM, Priority.MEDIUM))


def _parse_issue(issue: str) -> tuple[str, "Severity", "Priority"]:
    """Extract '[TAG] message' → (message, Severity, Priority)."""
    from auditor.models import Severity, Priority
    if issue.startswith("[") and "]" in issue:
        tag, _, msg = issue[1:].partition("] ")
        sev, pri = _sev_from_tag(tag)
        return msg.strip(), sev, pri
    return issue, Severity.MEDIUM, Priority.MEDIUM


async def _web_recon_async(
    domain: str,
    session: AuditSession,
    passive_only: bool,
    out_dir: Path,
    fmt: str,
) -> None:
    from auditor.modules.web.passive import run_passive_recon, http_probe, check_dns_records, analyze_dmarc
    from auditor.modules.web.active import run_active_recon
    from auditor.modules.web.headers import run_headers_audit
    from auditor.modules.report.generator import save_report
    from auditor.models import Finding, Severity, Priority

    # Passive recon
    recon_result = await run_passive_recon(domain)

    # HTTP probe
    print_step("Probing live HTTP services...")
    live = await http_probe(recon_result.subdomains)
    live_urls = [r.url for r in live]
    print_ok(f"Live hosts: {len(live)}")

    for r in live[:20]:
        console.print(f"  [dim]{r.status_code}[/] {r.url} {f'[dim]— {r.title}[/]' if r.title else ''}")

    # DNS records analysis
    print_step("Checking email security DNS records (SPF/DMARC/DKIM)...")
    dns_records = check_dns_records(domain)
    dns_issues = analyze_dmarc(dns_records)

    _dns_c = _kr.get("WEB-DNS-GENERIC")
    for issue in dns_issues:
        print_warn(issue)
        finding = Finding(
            id=f"WEB-DNS-{len(session.findings)+1:03d}",
            title=issue,
            component="DNS / Email Security",
            vector="Email spoofing / phishing — missing or weak email authentication",
            mitre_id=(_dns_c.mitre_id if _dns_c else None) or "T1566.001",
            mitre_tactic=_dns_c.mitre_tactic if _dns_c else None,
            severity=Severity.HIGH,
            priority=Priority.MEDIUM,
            description=issue,
            remediation=(_dns_c.remediation if _dns_c else None) or "Configure SPF -all, DKIM selector1/selector2, DMARC p=reject.",
        )
        session.add_finding(finding)

    # Security headers + HSTS + TLS/cipher + cookies
    print_step("Auditing security headers, HSTS, TLS and cipher suites...")
    header_results = await run_headers_audit(live_urls)

    _HEADER_REMEDIATIONS: dict[str, str] = {
        "Content-Security-Policy": "Define a strict CSP policy; start with 'default-src self' and restrict script/style sources.",
        "Strict-Transport-Security": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "X-Frame-Options": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors 'none')",
        "X-Content-Type-Options": "Add: X-Content-Type-Options: nosniff",
        "Referrer-Policy": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "Permissions-Policy": "Add Permissions-Policy restricting unneeded browser features.",
        "HSTS": "Configure HSTS with max-age ≥31536000, includeSubDomains, preload.",
        "TLS": "Disable TLS ≤1.1, SSLv3, weak ciphers; enable TLS 1.3; use ECDHE cipher suites.",
        "Cookie": "Set Secure, HttpOnly, and SameSite=Strict (or Lax) on all session cookies.",
        "redirect": "Configure HTTP (port 80) to return 301 redirect to https://.",
    }

    def _hdr_remediation(msg: str) -> str:
        for key, rem in _HEADER_REMEDIATIONS.items():
            if key.lower() in msg.lower():
                return rem
        return "Review and apply recommended security header configuration."

    _hdr_c = _kr.get("WEB-HDR-MISSING")
    _tls_c = _kr.get("WEB-TLS-GENERIC")
    _redir_c = _kr.get("WEB-REDIRECT-GENERIC")

    for hr in header_results:
        all_header_issues = hr.missing_headers + hr.hsts_issues + hr.cookie_issues
        for raw_issue in all_header_issues:
            msg, sev, pri = _parse_issue(raw_issue)
            if sev == Severity.INFO:
                console.print(f"  [dim][INFO][/] {hr.url}: {msg}")
                continue
            print_warn(f"{hr.url}: {msg}")
            idx = len(session.findings) + 1
            session.add_finding(Finding(
                id=f"WEB-HDR-{idx:03d}",
                title=msg,
                component=f"Web Headers — {hr.url}",
                vector="HTTP response headers — missing or misconfigured security controls",
                mitre_id=_hdr_c.mitre_id if _hdr_c else None,
                mitre_tactic=_hdr_c.mitre_tactic if _hdr_c else None,
                severity=sev,
                priority=pri,
                description=msg,
                remediation=_hdr_remediation(msg),
            ))

        for raw_issue in hr.tls_issues:
            msg, sev, pri = _parse_issue(raw_issue)
            if sev == Severity.INFO:
                console.print(f"  [dim][INFO][/] {hr.url}: {msg}")
                continue
            print_warn(f"{hr.url}: {msg}")
            idx = len(session.findings) + 1
            session.add_finding(Finding(
                id=f"WEB-TLS-{idx:03d}",
                title=msg,
                component=f"TLS/Certificate — {hr.url}",
                vector="TLS configuration — weak protocols, ciphers, or certificate issues",
                mitre_id=(_tls_c.mitre_id if _tls_c else None) or "T1557.002",
                mitre_tactic=_tls_c.mitre_tactic if _tls_c else None,
                severity=sev,
                priority=pri,
                description=msg,
                remediation=(_tls_c.remediation if _tls_c else None) or _HEADER_REMEDIATIONS["TLS"],
            ))

        if hr.redirect_issue:
            msg, sev, pri = _parse_issue(hr.redirect_issue)
            print_warn(f"{hr.url}: {msg}")
            idx = len(session.findings) + 1
            session.add_finding(Finding(
                id=f"WEB-HDR-{idx:03d}",
                title=msg,
                component=f"HTTP Redirect — {hr.url}",
                vector="Plaintext HTTP access allowed — no forced redirect to HTTPS",
                mitre_id=(_redir_c.mitre_id if _redir_c else None) or "T1557",
                mitre_tactic=_redir_c.mitre_tactic if _redir_c else None,
                severity=sev,
                priority=pri,
                description=msg,
                remediation=(_redir_c.remediation if _redir_c else None) or _HEADER_REMEDIATIONS["redirect"],
            ))

    # Active recon
    if not passive_only and live_urls:
        print_step("Running active recon (nmap + nuclei)...")
        nmap_results, nuclei_results = await run_active_recon(domain, live_urls, out_dir / "web")

        for n in nuclei_results:
            for raw in n.findings:
                sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
                sev_str = raw.get("info", {}).get("severity", "medium").lower()
                sev = sev_map.get(sev_str, Severity.MEDIUM)
                pri = Priority.HIGH if sev in (Severity.CRITICAL, Severity.HIGH) else Priority.MEDIUM
                session.add_finding(Finding(
                    id=f"WEB-NUCL-{len(session.findings)+1:03d}",
                    title=raw.get("info", {}).get("name", "Unknown"),
                    component=f"Web — {n.target}",
                    vector=raw.get("info", {}).get("description", ""),
                    mitre_id=None,
                    severity=sev,
                    priority=pri,
                    description=raw.get("info", {}).get("description", ""),
                    evidence=raw.get("matched-at", ""),
                    remediation=raw.get("info", {}).get("remediation", "Review and patch"),
                ))

    # Save report
    if session.findings:
        print_findings_table(session.findings)
        from auditor.modules.report.generator import save_report
        path = save_report(session, out_dir, fmt)
        print_ok(f"Report saved: {path}")
    else:
        print_ok("No findings — passive recon complete. Run with --authorized for active scanning.")


# ─── M365 commands ────────────────────────────────────────────────────────────

@m365_app.command("recon")
def m365_recon(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Target domain (e.g. company.com)")],
) -> None:
    """Pre-auth tenant reconnaissance — no credentials required."""
    print_banner()
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        print_err(str(e))
        raise typer.Exit(1)

    asyncio.run(_m365_recon_async(domain))


async def _m365_recon_async(domain: str) -> None:
    from auditor.modules.m365.recon import get_tenant_info

    info = await get_tenant_info(domain)

    console.print(f"\n[bold cyan]Tenant Info: {domain}[/]")
    console.print(f"  Tenant ID    : [bold]{info.tenant_id or 'Not found'}[/]")
    console.print(f"  Auth type    : [bold]{info.auth_type or 'Unknown'}[/]")
    console.print(f"  M365 tenant  : [bold]{'Yes' if info.is_m365 else 'No'}[/]")
    if info.federation_brand:
        console.print(f"  Federation   : [yellow]{info.federation_brand}[/]")
    if info.tenant_region:
        console.print(f"  Region       : {info.tenant_region}")
    if info.errors:
        for e in info.errors:
            print_warn(f"Error: {e}")


@m365_app.command("audit")
def m365_audit(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Target domain")],
    authorized: Annotated[bool, typer.Option("--authorized", help="Confirm written authorization")] = False,
    auth_flow: Annotated[str, typer.Option("--auth", help="Auth flow: device-code | client-credentials")] = "device-code",
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="Report format: markdown | json | xlsx")] = "markdown",
) -> None:
    """Full authenticated M365 tenant audit (Entra ID + Exchange + SharePoint + Teams)."""
    print_banner()

    if not authorized:
        print_err("--authorized flag required. Confirm written authorization before running authenticated audit.")
        raise typer.Exit(1)

    try:
        domain = validate_domain(domain)
    except ValueError as e:
        print_err(str(e))
        raise typer.Exit(1)

    settings = get_settings()
    out_dir = output or settings.output_dir

    asyncio.run(_m365_audit_async(domain, auth_flow, settings, out_dir, fmt))


async def _m365_audit_async(
    domain: str,
    auth_flow: str,
    settings,
    out_dir: Path,
    fmt: str,
) -> None:
    from auditor.modules.m365.auth import get_token_device_code, get_token_client_credentials
    from auditor.modules.m365.entra import run_entra_audit
    from auditor.modules.m365.exchange import audit_exchange
    from auditor.modules.m365.sharepoint import audit_sharepoint
    from auditor.modules.m365.teams import audit_teams
    from auditor.modules.report.generator import save_report

    # Acquire token
    if auth_flow == "client-credentials":
        token = get_token_client_credentials(settings)
    else:
        token = get_token_device_code(settings)

    if not token:
        print_err("Authentication failed — cannot proceed")
        return

    session = AuditSession(
        id=str(uuid.uuid4())[:8],
        target=AuditTarget(domain=domain, authorized=True),
    )

    # Entra ID audit
    entra_findings = await run_entra_audit(token)
    for f in entra_findings:
        session.add_finding(f)

    # Exchange audit
    exo_findings = await audit_exchange(token)
    for f in exo_findings:
        session.add_finding(f)

    # SharePoint / OneDrive audit
    spo_findings = await audit_sharepoint(token)
    for f in spo_findings:
        session.add_finding(f)

    # Teams audit
    teams_findings = await audit_teams(token)
    for f in teams_findings:
        session.add_finding(f)

    if session.findings:
        print_findings_table(session.findings)
        path = save_report(session, out_dir, fmt)
        print_ok(f"Report saved: {path}")
    else:
        print_ok("No findings detected in this audit run.")


# ─── Report commands ───────────────────────────────────────────────────────────

@report_app.command("view")
def report_view(
    path: Annotated[Path, typer.Argument(help="Path to JSON session file")],
) -> None:
    """View a saved audit session in the terminal."""
    import json
    from auditor.models import AuditSession

    if not path.exists():
        print_err(f"File not found: {path}")
        raise typer.Exit(1)

    data = json.loads(path.read_text())
    session = AuditSession.model_validate(data)
    print_findings_table(session.findings)


@report_app.command("export")
def report_export(
    path: Annotated[Path, typer.Argument(help="Path to JSON session file")],
    fmt: Annotated[str, typer.Option("--format", "-f", help="Export format: markdown | json | xlsx")] = "xlsx",
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
) -> None:
    """Export a saved JSON session to xlsx, markdown, or json."""
    import json
    from auditor.models import AuditSession
    from auditor.modules.report.generator import save_report
    from auditor.config import get_settings

    if not path.exists():
        print_err(f"File not found: {path}")
        raise typer.Exit(1)

    data = json.loads(path.read_text())
    session = AuditSession.model_validate(data)

    settings = get_settings()
    out_dir = output or path.parent

    out_path = save_report(session, out_dir, fmt)
    print_ok(f"Exported [{fmt}]: {out_path}")


# ─── Knowledge commands ────────────────────────────────────────────────────────

@knowledge_app.command("update")
def knowledge_update() -> None:
    """Rebuild skills_index.json from the skills/ git submodule."""
    from auditor.knowledge.loader import build_index, DEFAULT_SKILLS_DIR, DEFAULT_MAP_PATH, DEFAULT_INDEX_PATH
    print_step("Rebuilding knowledge index from skills submodule...")
    build_index(DEFAULT_SKILLS_DIR, DEFAULT_MAP_PATH, DEFAULT_INDEX_PATH)
    import json
    data = json.loads(DEFAULT_INDEX_PATH.read_text())
    count = len(data.get("checks", {}))
    commit = data.get("_meta", {}).get("skills_commit") or "no submodule"
    print_ok(f"Knowledge index updated: {count} checks, skills commit: {commit[:12] if commit != 'no submodule' else commit}")


@knowledge_app.command("status")
def knowledge_status() -> None:
    """Show knowledge index status."""
    from auditor.knowledge.loader import DEFAULT_INDEX_PATH
    import json
    if not DEFAULT_INDEX_PATH.exists():
        print_err("skills_index.json not found — run: auditor knowledge update")
        raise typer.Exit(1)
    data = json.loads(DEFAULT_INDEX_PATH.read_text())
    meta = data.get("_meta", {})
    count = len(data.get("checks", {}))
    console.print(f"  Checks      : [bold]{count}[/]")
    console.print(f"  Skills repo : {meta.get('skills_repo', '?')}")
    console.print(f"  Commit      : {meta.get('skills_commit') or 'not initialized'}")
    console.print(f"  Generated   : {meta.get('generated_at', '?')}")
    console.print(f"  Registry    : [bold]{len(_kr)}[/] entries loaded")


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[bool, typer.Option("--version", "-v")] = False,
) -> None:
    if version:
        from auditor import __version__
        console.print(f"AuditorCli {__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())
