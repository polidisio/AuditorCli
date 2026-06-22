"""Pre-auth M365/Entra ID tenant reconnaissance — no credentials required."""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

from auditor.utils.console import print_step, print_ok, print_warn
from auditor.utils.validators import validate_domain


OPENID_CONFIG_URL = "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
TENANT_INFO_URL = "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
GETUSEREALM_URL = "https://login.microsoftonline.com/getuserrealm.srf?login={user}&json=1"
AUTODISCOVER_URL = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"


@dataclass
class TenantInfo:
    domain: str
    tenant_id: str | None = None
    tenant_region: str | None = None
    auth_type: str | None = None           # "Managed" | "Federated"
    federation_brand: str | None = None    # e.g. "ADFS", "Okta"
    mfa_required: bool | None = None
    is_m365: bool = False
    verified_domains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def get_tenant_info(domain: str) -> TenantInfo:
    """Pull tenant metadata without credentials."""
    domain = validate_domain(domain)
    info = TenantInfo(domain=domain)

    async with httpx.AsyncClient(timeout=15) as client:
        # OpenID config — leaks tenant_id
        print_step(f"Fetching OpenID config for {domain}")
        try:
            r = await client.get(TENANT_INFO_URL.format(domain=domain))
            if r.status_code == 200:
                data = r.json()
                issuer = data.get("issuer", "")
                # issuer format: https://login.microsoftonline.com/{tenant_id}/v2.0
                parts = issuer.rstrip("/").split("/")
                if len(parts) >= 5:
                    info.tenant_id = parts[-2]
                    info.is_m365 = True
                    print_ok(f"Tenant ID: {info.tenant_id}")
        except Exception as e:
            info.errors.append(f"openid-config: {e}")

        # GetUserRealm — reveals auth type (Managed vs Federated) and IdP
        print_step(f"GetUserRealm for admin@{domain}")
        try:
            r = await client.get(GETUSEREALM_URL.format(user=f"admin@{domain}"))
            if r.status_code == 200:
                data = r.json()
                namespace_type = data.get("NameSpaceType", "")
                info.auth_type = "Federated" if namespace_type == "Federated" else "Managed"
                if namespace_type == "Federated":
                    info.federation_brand = data.get("AuthURL", "").split("/")[2] if data.get("AuthURL") else None
                info.tenant_region = data.get("cloud_instance_name")
                print_ok(f"Auth type: {info.auth_type}")
                if info.federation_brand:
                    print_warn(f"Federated IdP: {info.federation_brand}")
        except Exception as e:
            info.errors.append(f"getuserrealm: {e}")

        # Check Autodiscover (confirms M365 Exchange Online presence)
        print_step("Checking Autodiscover endpoint")
        try:
            r = await client.get(f"https://autodiscover.{domain}/autodiscover/autodiscover.json/v1.0/test@{domain}?Protocol=Autodiscoverv1")
            if r.status_code in (200, 302, 401):
                info.is_m365 = True
                print_ok("Autodiscover: Exchange Online confirmed")
        except Exception:
            pass

    return info


async def enumerate_tenant_domains(tenant_id: str) -> list[str]:
    """Enumerate verified domains in the tenant via public Graph endpoint."""
    domains: list[str] = []
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(
                f"https://graph.microsoft.com/v1.0/tenantRelationships/findTenantInformationByTenantId(tenantId='{tenant_id}')"
            )
            if r.status_code == 200:
                data = r.json()
                domains = data.get("verifiedDomains", [])
    except Exception:
        pass
    return domains
