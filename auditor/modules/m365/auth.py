"""MSAL auth flows for M365 audit (delegated + device-code)."""
from __future__ import annotations

import msal

from auditor.config import Settings
from auditor.utils.console import console, print_step, print_ok, print_err, print_warn

# Module-level MSAL session — persisted after device-code auth so
# acquire_resource_token() can silently get tokens for other resources
# (e.g. SharePoint) using the cached refresh token.
_app: msal.PublicClientApplication | None = None
_account: dict | None = None


GRAPH_SCOPES = [
    "https://graph.microsoft.com/Policy.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/User.Read.All",
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/RoleManagement.Read.All",
    "https://graph.microsoft.com/Sites.Read.All",
    "https://graph.microsoft.com/Group.Read.All",
    "https://graph.microsoft.com/TeamworkAppSettings.Read.All",
    "https://graph.microsoft.com/AppCatalog.Read.All",
]


def get_token_device_code(settings: Settings) -> str | None:
    """Acquire token via device-code flow (supports MFA)."""
    global _app, _account

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
        _app = app
        _account = (app.get_accounts() or [None])[0]
        return result["access_token"]

    print_err(f"Auth failed: {result.get('error_description', result.get('error', 'unknown'))}")
    return None


def acquire_resource_token(resource_base_url: str) -> str | None:
    """Acquire a token for a non-Graph resource (e.g. SharePoint admin URL).

    Tries silent acquisition first (uses the refresh token cached from the
    initial device-code flow). If silent fails — typical when the resource
    requires fresh user interaction (AADSTS50199), which SharePoint admin
    APIs enforce even when the MFA claim is present in the cached token —
    falls back to a new device-code flow for this resource.
    """
    if not _app or not _account:
        return None
    scopes = [f"{resource_base_url}/.default"]

    result = _app.acquire_token_silent(scopes=scopes, account=_account)
    if result and "access_token" in result:
        return result["access_token"]

    silent_err = ""
    if result:
        silent_err = result.get("error_description") or result.get("error") or "unknown"
    print_warn(
        f"Silent token acquisition failed for {resource_base_url}: {silent_err}\n"
        "Resource requires fresh user interaction — starting device-code flow..."
    )

    flow = _app.initiate_device_flow(scopes=scopes)
    if "user_code" not in flow:
        print_warn(f"Device-code flow init failed: {flow.get('error_description', 'unknown')}")
        return None

    console.print(f"\n[bold yellow]Open:[/] {flow['verification_uri']}")
    console.print(f"[bold yellow]Code :[/] {flow['user_code']}\n")
    print_step(f"Waiting for {resource_base_url} authentication...")

    result = _app.acquire_token_by_device_flow(flow)
    if result and "access_token" in result:
        print_ok(f"Token acquired for {resource_base_url}")
        return result["access_token"]

    err = (result or {}).get("error_description") or (result or {}).get("error") or "unknown"
    print_warn(f"Device-code auth failed for {resource_base_url}: {err}")
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
