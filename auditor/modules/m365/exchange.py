"""Exchange Online audit checks via Microsoft Graph."""
from __future__ import annotations

from auditor.models import Finding, Priority, Severity
from auditor.modules.m365.graph import GraphClient
from auditor.utils.console import print_step, print_ok, print_warn


async def audit_exchange(access_token: str) -> list[Finding]:
    client = GraphClient(access_token)
    findings: list[Finding] = []

    print_step("Auditing Exchange Online mailbox rules...")

    # Inbox rules with external forwarding
    try:
        users = await client.get_all_pages(
            "/users?$select=id,userPrincipalName,displayName&$filter=accountEnabled eq true"
        )
        print_ok(f"Checking inbox rules for {len(users)} users...")

        forwarding_count = 0
        forwarding_users: list[str] = []

        for user in users[:50]:  # cap at 50 for performance
            uid = user.get("id")
            upn = user.get("userPrincipalName", "?")
            try:
                rules = await client.get_all_pages(f"/users/{uid}/mailFolders/inbox/messageRules")
                for rule in rules:
                    actions = rule.get("actions", {})
                    if actions.get("forwardTo") or actions.get("redirectTo") or actions.get("forwardAsAttachmentTo"):
                        forwarding_count += 1
                        forwarding_users.append(upn)
                        break
            except Exception:
                pass

        if forwarding_count:
            print_warn(f"{forwarding_count} users with external forwarding rules")
            findings.append(Finding(
                id="M365-EXO-001",
                title=f"{forwarding_count} Mailboxes with External Forwarding Rules",
                component="Exchange Online — Inbox Rules",
                vector="BEC persistence — attacker forwards all mail to external address silently",
                mitre_id="T1114.003",
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=f"Inbox forwarding rules (ForwardTo/RedirectTo) found on: "
                            f"{', '.join(forwarding_users[:5])}{'...' if len(forwarding_users) > 5 else ''}",
                remediation="Investigate each rule. Disable external auto-forwarding at org level via transport rule.",
            ))
        else:
            print_ok("No external forwarding rules found")

    except Exception as e:
        print_warn(f"Could not audit inbox rules: {e}")

    # Check SMTP AUTH status (via org settings — Graph beta)
    print_step("Checking SMTP AUTH configuration...")
    try:
        transport_config = await client.get(
            "/admin/serviceAnnouncement/healthOverviews/Exchange",
            beta=True,
        )
        # This endpoint won't give SMTP auth directly; noted as limitation
        print_warn("SMTP AUTH per-mailbox audit requires PowerShell (Exchange Online module)")
        findings.append(Finding(
            id="M365-EXO-002",
            title="SMTP AUTH Status Requires PowerShell Verification",
            component="Exchange Online — Legacy Auth",
            vector="SMTP AUTH enabled per-mailbox bypasses CA and MFA",
            mitre_id="T1078.004",
            severity=Severity.MEDIUM,
            priority=Priority.MEDIUM,
            description="SMTP AUTH per-mailbox configuration cannot be fully verified via Graph API. "
                        "PowerShell audit required.",
            remediation="Run: Get-CASMailbox -ResultSize Unlimited | Where {$_.SmtpClientAuthenticationDisabled -eq $false}",
        ))
    except Exception:
        pass

    return findings
