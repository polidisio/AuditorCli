"""SharePoint Online / OneDrive for Business audit via Microsoft Graph."""
from __future__ import annotations

from auditor.knowledge import registry as _kr
from auditor.models import Finding, Priority, Severity
from auditor.modules.m365.graph import GraphClient
from auditor.utils.console import print_step, print_ok, print_warn


# Sharing capability values from Graph API
_SHARING_LEVEL = {
    "disabled": "Sharing disabled",
    "externalUserSharingOnly": "Authenticated external users only",
    "externalUserAndGuestSharing": "Anyone with the link (anonymous)",
    "existingExternalUserSharingOnly": "Existing external users only",
}

_LINK_TYPE = {
    "anyone": "Anonymous (Anyone with link)",
    "organization": "Organization-wide",
    "specificPeople": "Specific people only",
}


async def audit_sharepoint(access_token: str) -> list[Finding]:
    client = GraphClient(access_token)
    findings: list[Finding] = []

    # ── Tenant-level sharing policy ────────────────────────────────────────
    print_step("Auditing SharePoint tenant sharing settings...")
    try:
        settings = await client.get(
            "/admin/sharepoint/settings",
            beta=True,
        )

        sharing_cap = settings.get("sharingCapability", "")
        default_link = settings.get("defaultSharingLinkType", "")
        anon_link_expiry = settings.get("requireAnonymousLinksExpireInDays", 0)
        external_user_expiry = settings.get("emailAttestationRequired", False)
        legacy_auth = settings.get("isLegacyAuthProtocolsEnabled", None)

        sharing_label = _SHARING_LEVEL.get(sharing_cap, sharing_cap)
        print_ok(f"Tenant sharing level: {sharing_label}")

        # Anonymous sharing enabled
        if sharing_cap == "externalUserAndGuestSharing":
            _c = _kr.get("SPO-001")
            findings.append(Finding(
                id="SPO-001",
                title="SharePoint Anonymous Link Sharing Enabled (Anyone)",
                component="SharePoint Online — Tenant Sharing",
                vector="Anyone with a link can access files without authentication",
                mitre_id=(_c.mitre_id if _c else None) or "T1567.002",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=(
                    "Tenant sharing capability is set to 'Anyone with the link'. "
                    "Unauthenticated users can access files and folders if someone shares a link. "
                    "This allows data exfiltration without any audit trail tied to a user identity."
                ),
                remediation=(_c.remediation if _c else None) or (
                    "Restrict to 'ExternalUserSharingOnly' or 'ExistingExternalUserSharingOnly'. "
                    "Admin center: SharePoint → Policies → Sharing → set to 'New and existing guests'."
                ),
            ))

        # Default link type is Anyone
        if default_link == "anyone":
            _c = _kr.get("SPO-002")
            findings.append(Finding(
                id="SPO-002",
                title="Default Sharing Link Type is 'Anyone' (Anonymous)",
                component="SharePoint Online — Default Link",
                vector="Users share anonymous links by default without consciously choosing to",
                mitre_id=(_c.mitre_id if _c else None) or "T1567.002",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description=(
                    "The default link type when sharing is 'Anyone with the link'. "
                    "Users creating sharing links default to anonymous access unless they manually change it."
                ),
                remediation=(_c.remediation if _c else None) or (
                    "Change default to 'Specific people' or 'Only people in your organization'. "
                    "Admin center: SharePoint → Policies → Sharing → Default link type."
                ),
            ))

        # Anonymous links with no expiry
        if sharing_cap == "externalUserAndGuestSharing" and anon_link_expiry == 0:
            _c = _kr.get("SPO-003")
            findings.append(Finding(
                id="SPO-003",
                title="Anonymous Links Have No Expiration Date",
                component="SharePoint Online — Anonymous Links",
                vector="Leaked anonymous links remain valid indefinitely",
                mitre_id=(_c.mitre_id if _c else None) or "T1567.002",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description="Anonymous sharing links never expire. A leaked link provides permanent unauthenticated access.",
                remediation=(_c.remediation if _c else None) or "Set expiration on anonymous links: SharePoint Admin Center → Sharing → set 'These links must expire within this many days'.",
            ))

        # Legacy authentication
        if legacy_auth is True:
            _c = _kr.get("SPO-004")
            findings.append(Finding(
                id="SPO-004",
                title="Legacy Authentication Protocols Enabled for SharePoint",
                component="SharePoint Online — Legacy Auth",
                vector="Legacy auth bypasses MFA and Conditional Access for SharePoint",
                mitre_id=(_c.mitre_id if _c else None) or "T1078.004",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=(
                    "Legacy authentication protocols (Basic Auth, Forms-based) are enabled for SharePoint Online. "
                    "These protocols bypass Azure AD MFA and Conditional Access policies."
                ),
                remediation=(_c.remediation if _c else None) or "Disable legacy auth: SharePoint Admin Center → Settings → Legacy authentication → Off.",
            ))
        elif legacy_auth is False:
            print_ok("SharePoint legacy auth: disabled")

    except Exception as e:
        print_warn(f"SharePoint tenant settings require SharePoint Admin role: {e}")
        _c = _kr.get("SPO-INFO-001")
        findings.append(Finding(
            id="SPO-INFO-001",
            title="SharePoint Tenant Settings Require Manual Verification",
            component="SharePoint Online — Tenant Config",
            vector="Insufficient permissions to read SharePoint admin settings via Graph",
            mitre_id=(_c.mitre_id if _c else None),
            mitre_tactic=_c.mitre_tactic if _c else None,
            severity=Severity.INFO,
            priority=Priority.LOW,
            description=(
                "SharePoint admin settings could not be read. "
                "Verify manually in SharePoint Admin Center or with a SharePoint Admin account."
            ),
            remediation=(_c.remediation if _c else None) or (
                "Check manually:\n"
                "• SharePoint Admin Center → Policies → Sharing\n"
                "• PowerShell: Get-SPOTenant | Select SharingCapability,DefaultSharingLinkType,RequireAnonymousLinksExpireInDays"
            ),
        ))

    # ── Site collections with broad external sharing ───────────────────────
    print_step("Enumerating SharePoint site collections...")
    try:
        sites = await client.get_all_pages(
            "/sites?$select=id,displayName,webUrl,sharingCapability&search=*"
        )
        print_ok(f"Found {len(sites)} sites")

        anon_sites = [
            s for s in sites
            if s.get("sharingCapability") == "externalUserAndGuestSharing"
        ]
        if anon_sites:
            _c = _kr.get("SPO-005")
            findings.append(Finding(
                id="SPO-005",
                title=f"{len(anon_sites)} Site Collections Allow Anonymous Sharing",
                component="SharePoint Online — Site Collections",
                vector="Per-site sharing overrides may expose sensitive data to unauthenticated users",
                mitre_id=(_c.mitre_id if _c else None) or "T1567.002",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.HIGH,
                priority=Priority.HIGH,
                description=(
                    f"{len(anon_sites)} site collections have 'Anyone with the link' sharing enabled:\n"
                    + "\n".join(f"  • {s.get('webUrl', '?')}" for s in anon_sites[:10])
                ),
                remediation=(_c.remediation if _c else None) or "Review each site in SharePoint Admin Center. Restrict sharing to authenticated users minimum.",
            ))

    except Exception as e:
        print_warn(f"Could not enumerate site collections: {e}")

    # ── OneDrive default sharing ───────────────────────────────────────────
    print_step("Checking OneDrive for Business sharing policy...")
    try:
        od_settings = await client.get(
            "/admin/sharepoint/settings",
            beta=True,
        )
        od_link_type = od_settings.get("oneDriveSharingCapability", "")
        if od_link_type == "externalUserAndGuestSharing":
            _c = _kr.get("SPO-006")
            findings.append(Finding(
                id="SPO-006",
                title="OneDrive for Business Allows Anonymous Link Sharing",
                component="OneDrive for Business — Sharing",
                vector="Employees can share personal OneDrive files anonymously",
                mitre_id=(_c.mitre_id if _c else None) or "T1567.002",
                mitre_tactic=_c.mitre_tactic if _c else None,
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description="OneDrive for Business sharing is set to 'Anyone with the link', allowing anonymous file access.",
                remediation=(_c.remediation if _c else None) or "Restrict OneDrive sharing to authenticated external users or org-only.",
            ))
    except Exception:
        pass

    return findings


async def audit_sharepoint_permissions(access_token: str, site_id: str) -> list[Finding]:
    """Deep permission audit for a specific site collection."""
    client = GraphClient(access_token)
    findings: list[Finding] = []

    print_step(f"Auditing permissions for site: {site_id}")
    try:
        permissions = await client.get_all_pages(f"/sites/{site_id}/permissions")
        for perm in permissions:
            roles = perm.get("roles", [])
            granted_to = perm.get("grantedToIdentitiesV2", [])
            # Flag site-level write/owner grants to external identities
            for identity in granted_to:
                user = identity.get("user", {})
                if user.get("userType") == "external" and any(
                    r in roles for r in ["write", "owner", "fullControl"]
                ):
                    findings.append(Finding(
                        id=f"SPO-PERM-{len(findings)+1:03d}",
                        title="External User Has Write/Owner Permission on Site",
                        component=f"SharePoint — Site {site_id}",
                        vector="External user can modify or exfiltrate site content",
                        mitre_id="T1567.002",
                        severity=Severity.HIGH,
                        priority=Priority.HIGH,
                        description=f"External user '{user.get('displayName', '?')}' ({user.get('email', '?')}) has {roles} on site.",
                        remediation="Review and revoke external write/owner permissions for this site.",
                    ))
    except Exception as e:
        print_warn(f"Cannot read site permissions: {e}")

    return findings
