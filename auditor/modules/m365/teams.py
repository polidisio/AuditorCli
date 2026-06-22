"""Microsoft Teams audit via Microsoft Graph."""
from __future__ import annotations

from auditor.models import Finding, Priority, Severity
from auditor.modules.m365.graph import GraphClient
from auditor.utils.console import print_step, print_ok, print_warn


async def audit_teams(access_token: str) -> list[Finding]:
    client = GraphClient(access_token)
    findings: list[Finding] = []

    # ── Teams tenant-level settings ────────────────────────────────────────
    print_step("Auditing Teams tenant communication settings...")
    try:
        comms_policy = await client.get(
            "/teamwork/teamsAppSettings",
            beta=True,
        )

        # External access (federation) — can chat with any Teams org
        allow_external = comms_policy.get("isExternalAccessAllowed", None)
        if allow_external is True:
            findings.append(Finding(
                id="TEAMS-001",
                title="Teams External Access Open to All External Domains",
                component="Teams — External Access",
                vector="Users can communicate with any external Teams organization including unmanaged/consumer accounts",
                mitre_id="T1566.003",
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description=(
                    "Teams external access is configured to allow communication with all external "
                    "Teams organizations and Skype users. Attackers can use this to send phishing messages "
                    "or malicious files directly to internal users via Teams chat."
                ),
                remediation=(
                    "Restrict external access to a whitelist of known partner domains. "
                    "Teams Admin Center → Users → External access → Allow only specific external domains."
                ),
            ))

        # Guest access
        allow_guests = comms_policy.get("isGuestAccessAllowed", None)
        if allow_guests is True:
            findings.append(Finding(
                id="TEAMS-002",
                title="Teams Guest Access Enabled",
                component="Teams — Guest Access",
                vector="Guests invited to Teams can read channel content, files, and chat history",
                mitre_id="T1087.004",
                severity=Severity.LOW,
                priority=Priority.LOW,
                description=(
                    "Guest access is enabled in Teams. Guests (external B2B users) can be added to teams "
                    "and have access to channel conversations, files, and meetings. "
                    "Verify that guest permissions are scoped appropriately."
                ),
                remediation=(
                    "If guest access is required, ensure guests cannot create/delete channels, "
                    "add apps, or access sensitive teams. "
                    "Teams Admin Center → Guest access → review per-capability toggles."
                ),
            ))

        # Unmanaged external accounts (Skype/personal Teams accounts)
        allow_unmanaged = comms_policy.get("isUnmanagedCommunicationAllowed", None)
        if allow_unmanaged is True:
            findings.append(Finding(
                id="TEAMS-003",
                title="Communication with Unmanaged/Consumer Teams Accounts Allowed",
                component="Teams — External Access",
                vector="Phishing via unmanaged Teams or Skype consumer accounts — no tenant governance",
                mitre_id="T1566.003",
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description=(
                    "Internal users can receive messages from unmanaged Teams accounts (personal Microsoft accounts, "
                    "Skype users). These accounts have no corporate governance and are a common phishing vector."
                ),
                remediation=(
                    "Disable communication with unmanaged accounts unless required: "
                    "Teams Admin Center → Users → External access → toggle off 'Teams accounts not managed by an organization'."
                ),
            ))

    except Exception as e:
        print_warn(f"Teams app settings require Teams Admin role: {e}")

    # ── Teams + team/channel enumeration ──────────────────────────────────
    print_step("Enumerating Teams with guest members...")
    try:
        teams_list = await client.get_all_pages("/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName,visibility,createdDateTime")
        print_ok(f"Found {len(teams_list)} Teams")

        public_teams = [t for t in teams_list if t.get("visibility") == "Public"]
        if public_teams:
            findings.append(Finding(
                id="TEAMS-004",
                title=f"{len(public_teams)} Public Teams Visible to All Tenant Members",
                component="Teams — Team Visibility",
                vector="Any internal user can join public teams and read all channel content and files",
                mitre_id="T1087.004",
                severity=Severity.LOW,
                priority=Priority.LOW,
                description=(
                    f"{len(public_teams)} teams are set to Public visibility:\n"
                    + "\n".join(f"  • {t.get('displayName', '?')}" for t in public_teams[:10])
                ),
                remediation="Review public teams. Set sensitive teams to Private. Consider HiddenMembership for leadership teams.",
            ))

        # Teams with guest members
        guest_teams: list[str] = []
        for team in teams_list[:30]:  # cap for API rate limits
            tid = team.get("id")
            try:
                members = await client.get_all_pages(
                    f"/groups/{tid}/members?$select=userPrincipalName,userType"
                )
                has_guests = any(m.get("userType") == "Guest" for m in members)
                if has_guests:
                    guest_teams.append(team.get("displayName", tid))
            except Exception:
                pass

        if guest_teams:
            findings.append(Finding(
                id="TEAMS-005",
                title=f"{len(guest_teams)} Teams Have Guest Members",
                component="Teams — Guest Membership",
                vector="Guests can read all channel history, files, and tabs within the team",
                mitre_id="T1087.004",
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description=(
                    f"Teams with guest members: {', '.join(guest_teams[:10])}"
                    f"{'...' if len(guest_teams) > 10 else ''}\n"
                    "Verify each guest is authorized and the team does not contain sensitive data."
                ),
                remediation=(
                    "Audit guest membership per team. Remove unauthorized guests. "
                    "Apply sensitivity labels to restrict guest access to confidential teams."
                ),
            ))

    except Exception as e:
        print_warn(f"Could not enumerate Teams: {e}")

    # ── Meeting policies ───────────────────────────────────────────────────
    print_step("Checking Teams meeting policies...")
    try:
        meeting_policies = await client.get(
            "/teamwork/teamsAppSettings",
            beta=True,
        )

        # Check if anonymous join is allowed
        allow_anon_join = meeting_policies.get("isAnonymousJoinEnabled", None)
        if allow_anon_join is True:
            findings.append(Finding(
                id="TEAMS-006",
                title="Anonymous Users Can Join Teams Meetings",
                component="Teams — Meeting Policy",
                vector="Unauthenticated actors can join meetings, listen to discussions, access shared files",
                mitre_id="T1566.003",
                severity=Severity.MEDIUM,
                priority=Priority.MEDIUM,
                description=(
                    "Anonymous users (no account required) can join Teams meetings. "
                    "This enables eavesdropping on meetings where sensitive information is shared."
                ),
                remediation=(
                    "Disable anonymous join: Teams Admin Center → Meetings → Meeting policies → "
                    "Global policy → 'Allow anonymous users to join a meeting' → Off."
                ),
            ))

    except Exception as e:
        print_warn(f"Could not check meeting policies (may require Teams Admin): {e}")

    # ── Third-party app policies ───────────────────────────────────────────
    print_step("Checking Teams app permission policies (3rd-party apps)...")
    try:
        app_policies = await client.get(
            "/teamwork/teamsAppSettings",
            beta=True,
        )

        allow_third_party = app_policies.get("isThirdPartyAppsAllowed", None)
        allow_custom = app_policies.get("isCustomAppsAllowed", None)

        if allow_third_party is True:
            findings.append(Finding(
                id="TEAMS-007",
                title="Third-Party Teams Apps Allowed Tenant-Wide",
                component="Teams — App Policy",
                vector="3rd-party apps can request Graph API permissions and access team data",
                mitre_id="T1550.001",
                severity=Severity.LOW,
                priority=Priority.LOW,
                description=(
                    "Third-party Teams applications are allowed in the tenant. "
                    "Malicious or overly-permissive apps can exfiltrate channel messages, files, and user data via Graph API."
                ),
                remediation=(
                    "Restrict to approved apps only: Teams Admin Center → Teams apps → Permission policies → "
                    "Block all apps except approved list. Review existing app grants."
                ),
            ))

        if allow_custom is True:
            findings.append(Finding(
                id="TEAMS-008",
                title="Custom (Sideloaded) Teams Apps Allowed",
                component="Teams — App Policy",
                vector="Internal users can sideload apps with arbitrary permissions",
                mitre_id="T1550.001",
                severity=Severity.LOW,
                priority=Priority.LOW,
                description="Users or developers can sideload custom apps into Teams without IT approval.",
                remediation="Disable custom app upload for regular users. Allow only for specific developer accounts via app setup policies.",
            ))

    except Exception as e:
        print_warn(f"Could not check Teams app policies: {e}")

    return findings


async def get_teams_external_domains(access_token: str) -> list[str]:
    """Return list of allowed external domains for Teams federation."""
    client = GraphClient(access_token)
    try:
        policy = await client.get(
            "/policies/crossTenantAccessPolicy/default",
            beta=True,
        )
        b2b = policy.get("b2bCollaborationOutbound", {})
        allowed = b2b.get("tenants", {}).get("allowedValues", [])
        return [t.get("tenantId", "") for t in allowed]
    except Exception:
        return []
