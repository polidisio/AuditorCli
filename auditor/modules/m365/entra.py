"""Entra ID / Azure AD audit checks via Microsoft Graph."""
from __future__ import annotations

from auditor.knowledge import registry as _kr
from auditor.models import Finding, Priority, Severity
from auditor.modules.m365.graph import GraphClient
from auditor.utils.console import print_step, print_ok, print_warn


async def audit_conditional_access(client: GraphClient) -> list[Finding]:
    findings: list[Finding] = []
    print_step("Auditing Conditional Access policies...")

    policies = await client.get_all_pages("/identity/conditionalAccess/policies")
    print_ok(f"Found {len(policies)} CA policies")

    # Check for legacy auth block policy
    legacy_blocked = any(
        p.get("state") == "enabled"
        and any(
            c.get("clientAppTypes") and set(c.get("clientAppTypes", [])) & {
                "exchangeActiveSync", "other"
            }
            for c in [p.get("conditions", {})]
        )
        for p in policies
    )

    if not legacy_blocked:
        _c = _kr.get("M365-CA-001")
        findings.append(Finding(
            id="M365-CA-001",
            title="Legacy Authentication Not Blocked by CA Policy",
            component="Entra ID — Conditional Access",
            vector="Legacy auth protocols (SMTP AUTH, POP3, IMAP) bypass MFA",
            mitre_id=(_c.mitre_id if _c else None) or "T1078.004",
            mitre_tactic=_c.mitre_tactic if _c else None,
            severity=Severity.CRITICAL,
            priority=Priority.HIGH,
            description="No Conditional Access policy found blocking legacy authentication protocols. "
                        "Legacy auth bypasses MFA entirely, enabling password spray and credential stuffing attacks.",
            remediation=(_c.remediation if _c else None) or "Create CA policy: Conditions → Client apps → Exchange ActiveSync + Other clients → Block",
        ))

    # Check if any policy is in report-only mode (not enforcing)
    report_only = [p for p in policies if p.get("state") == "enabledForReportingButNotEnforcing"]
    if report_only:
        _c = _kr.get("M365-CA-002")
        findings.append(Finding(
            id="M365-CA-002",
            title=f"{len(report_only)} CA Policies in Report-Only Mode",
            component="Entra ID — Conditional Access",
            vector="Policies not enforced — controls appear configured but don't block access",
            mitre_id=(_c.mitre_id if _c else None) or "T1078.004",
            mitre_tactic=_c.mitre_tactic if _c else None,
            severity=Severity.MEDIUM,
            priority=Priority.MEDIUM,
            description=f"Policies: {', '.join(p.get('displayName','?') for p in report_only)}",
            remediation=(_c.remediation if _c else None) or "Switch report-only policies to Enabled after impact review",
        ))

    return findings


async def audit_users(client: GraphClient) -> list[Finding]:
    findings: list[Finding] = []
    print_step("Auditing users and MFA registration...")

    # Users without MFA methods registered
    try:
        users_without_mfa = await client.get_all_pages(
            "/reports/authenticationMethods/userRegistrationDetails"
            "?$filter=isMfaRegistered eq false and accountEnabled eq true"
        )
        if users_without_mfa:
            count = len(users_without_mfa)
            print_warn(f"{count} users without MFA registered")
            _c = _kr.get("M365-USR-001")
            findings.append(Finding(
                id="M365-USR-001",
                title=f"{count} Enabled Users Without MFA Registration",
                component="Entra ID — Users",
                vector="Accounts accessible with password only — no second factor",
                mitre_id=(_c.mitre_id if _c else None) or "T1078.004",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=f"{count} enabled users have not registered any MFA method.",
                evidence=f"Sample UPNs: {', '.join(u.get('userPrincipalName','?') for u in users_without_mfa[:5])}",
                remediation=(_c.remediation if _c else None) or "Enforce MFA registration via CA policy + Identity Protection",
            ))
    except Exception as e:
        print_warn(f"Could not fetch MFA registration data: {e}")

    # Guest users
    guests = await client.get_all_pages("/users?$filter=userType eq 'Guest'&$select=displayName,userPrincipalName,createdDateTime")
    if guests:
        print_warn(f"{len(guests)} guest users in tenant")
        _c = _kr.get("M365-USR-002")
        findings.append(Finding(
            id="M365-USR-002",
            title=f"{len(guests)} Guest Users in Tenant",
            component="Entra ID — External Access",
            vector="Guest users can enumerate directory and access shared resources",
            mitre_id=(_c.mitre_id if _c else None) or "T1087.004",
            mitre_tactic=_c.mitre_tactic if _c else None,
            severity=Severity.MEDIUM,
            priority=Priority.MEDIUM,
            description=f"Tenant has {len(guests)} guest users. Verify each is authorized and has minimal permissions.",
            evidence=f"Sample: {', '.join(u.get('userPrincipalName','?') for u in guests[:5])}",
            remediation=(_c.remediation if _c else None) or "Review guest access. Set GuestUserRoleId = Restricted Guest User in External Identities settings.",
        ))

    return findings


async def audit_service_principals(client: GraphClient) -> list[Finding]:
    findings: list[Finding] = []
    print_step("Auditing Service Principals and OAuth consent...")

    HIGH_RISK_PERMISSIONS = {
        "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
        "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
        "62a82d76-70ea-41e2-9197-370581804d09",  # Group.ReadWrite.All
        "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
        "741f803b-c850-494e-b5df-cde7c675a1ca",  # User.ReadWrite.All
        "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
    }

    sps = await client.get_all_pages(
        "/servicePrincipals?$select=displayName,appId,appRoles,oauth2PermissionScopes,publisherName"
    )
    print_ok(f"Found {len(sps)} service principals")

    # Check for app-only grants with high-risk permissions
    try:
        grants = await client.get_all_pages("/oauth2PermissionGrants")
        app_grants = [g for g in grants if g.get("consentType") == "AllPrincipals"]
        if app_grants:
            _c = _kr.get("M365-SP-001")
            findings.append(Finding(
                id="M365-SP-001",
                title=f"{len(app_grants)} OAuth Apps with Tenant-Wide Consent",
                component="Entra ID — Service Principals",
                vector="Illicit consent grant — apps can access all users' data",
                mitre_id=(_c.mitre_id if _c else None) or "T1550.001",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=f"{len(app_grants)} apps have tenant-wide (AllPrincipals) OAuth consent grants.",
                remediation=(_c.remediation if _c else None) or "Review each grant at Entra ID → Enterprise Apps → Permissions. Revoke unauthorized grants.",
            ))
    except Exception as e:
        print_warn(f"Could not fetch OAuth grants: {e}")

    return findings


async def audit_privileged_roles(client: GraphClient) -> list[Finding]:
    findings: list[Finding] = []
    print_step("Auditing privileged role assignments...")

    HIGH_PRIV_ROLES = {
        "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
        "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
        "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
        "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
        "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    }

    try:
        role_assignments = await client.get_all_pages(
            "/roleManagement/directory/roleAssignments?$expand=principal"
        )
    except Exception as e:
        print_warn(f"Could not fetch role assignments: {e}")
        return findings

    permanent_admins: list[dict] = []
    for assignment in role_assignments:
        role_def_id = assignment.get("roleDefinitionId", "")
        if role_def_id in HIGH_PRIV_ROLES:
            principal = assignment.get("principal", {})
            permanent_admins.append({
                "role": HIGH_PRIV_ROLES[role_def_id],
                "principal": principal.get("userPrincipalName") or principal.get("displayName", "?"),
                "type": principal.get("@odata.type", ""),
            })

    if permanent_admins:
        print_warn(f"{len(permanent_admins)} permanent privileged role assignments found")
        _c = _kr.get("M365-ROLE-001")
        findings.append(Finding(
            id="M365-ROLE-001",
            title=f"{len(permanent_admins)} Permanent Privileged Role Assignments (No PIM)",
            component="Entra ID — Privileged Roles",
            vector="Permanent admin assignments — compromised account = persistent Global Admin",
            mitre_id=(_c.mitre_id if _c else None) or "T1078.004",
            mitre_tactic=_c.mitre_tactic if _c else None,
            severity=Severity.HIGH,
            priority=Priority.HIGH,
            description=f"Roles assigned permanently (not via PIM JIT): "
                        + ", ".join(f"{a['principal']} ({a['role']})" for a in permanent_admins[:5]),
            remediation=(_c.remediation if _c else None) or "Migrate all privileged roles to PIM Just-in-Time activation with approval workflow and MFA.",
        ))

    return findings


async def run_entra_audit(access_token: str) -> list[Finding]:
    client = GraphClient(access_token)
    findings: list[Finding] = []

    findings += await audit_conditional_access(client)
    findings += await audit_users(client)
    findings += await audit_service_principals(client)
    findings += await audit_privileged_roles(client)

    return findings
