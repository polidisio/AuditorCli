"""MSAL auth flows for M365 audit (delegated + device-code)."""
from __future__ import annotations

import msal

from auditor.config import Settings
from auditor.utils.console import console, print_step, print_ok, print_err


GRAPH_SCOPES = [
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.All",
    "https://graph.microsoft.com/SharePoint.ReadWrite.All",
    "https://graph.microsoft.com/Sites.Read.All",
    "https://graph.microsoft.com/TeamworkSettings.Read.All",
    "https://graph.microsoft.com/Group.Read.All",
]


def get_token_device_code(settings: Settings) -> str | None:
    """Acquire token via device-code flow (supports MFA)."""
    if not settings.client_id:
        print_err(
            "AUDITOR_CLIENT_ID not set.\n"
            "Register an Entra ID app (public client) with delegated Graph permissions,\n"
            "grant admin consent, then set AUDITOR_CLIENT_ID and AUDITOR_TENANT_ID."
        )
        return None
    tenant = settings.tenant_id or "organizations"
    client_id = settings.client_id

    app = msal.PublicClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant}",
    )

    flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
    if "user_code" not in flow:
        print_err(f"Device flow failed: {flow.get('error_description', 'unknown error')}")
        return None

    console.print(f"\n[bold yellow]Open:[/] {flow['verification_uri']}")
    console.print(f"[bold yellow]Code:[/] {flow['user_code']}\n")
    print_step("Waiting for authentication...")

    result = app.acquire_token_by_device_flow(flow)
    if "access_token" in result:
        print_ok(f"Authenticated as: {result.get('id_token_claims', {}).get('preferred_username', 'unknown')}")
        return result["access_token"]

    print_err(f"Auth failed: {result.get('error_description', result.get('error', 'unknown'))}")
    return None


def get_token_client_credentials(settings: Settings) -> str | None:
    """Acquire token via client credentials (app-only, no user interaction)."""
    if not all([settings.tenant_id, settings.client_id, settings.client_secret]):
        print_err("tenant_id, client_id, client_secret required for client credentials flow")
        return None

    app = msal.ConfidentialClientApplication(
        settings.client_id,
        authority=f"https://login.microsoftonline.com/{settings.tenant_id}",
        client_credential=settings.client_secret,
    )

    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )

    if "access_token" in result:
        print_ok("App-only token acquired")
        return result["access_token"]

    print_err(f"Auth failed: {result.get('error_description', result.get('error', 'unknown'))}")
    return None
