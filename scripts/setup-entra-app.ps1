#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Registers AuditorCli in Entra ID and grants admin consent for Graph API permissions.

.DESCRIPTION
    Creates a public-client app registration with the delegated Graph permissions
    required by "auditor m365 audit". Prints the env vars to set afterwards.

    Requires: Az.Accounts module + a Global Admin or Application Admin + Cloud Application Admin
    (for the admin consent grant step).

.PARAMETER AppName
    Display name for the app registration (default: AuditorCli).

.PARAMETER TenantId
    Tenant ID or domain. If omitted, uses the tenant from Connect-AzAccount.

.EXAMPLE
    .\setup-entra-app.ps1

.EXAMPLE
    .\setup-entra-app.ps1 -AppName "AuditorCli-Prod" -TenantId "contoso.onmicrosoft.com"
#>
[CmdletBinding()]
param(
    [string]$AppName  = "AuditorCli",
    [string]$TenantId = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. Connect ────────────────────────────────────────────────────────────────
Write-Host "`n[1/5] Connecting to Azure..." -ForegroundColor Cyan
if ($TenantId) {
    Connect-AzAccount -TenantId $TenantId | Out-Null
} else {
    Connect-AzAccount | Out-Null
}

$context  = Get-AzContext
$tenantId = $context.Tenant.Id
Write-Host "     Tenant : $tenantId" -ForegroundColor Gray
Write-Host "     Account: $($context.Account.Id)" -ForegroundColor Gray

# ── 2. Graph token ────────────────────────────────────────────────────────────
Write-Host "`n[2/5] Acquiring Graph API token..." -ForegroundColor Cyan
$graphToken = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
$h = @{
    Authorization  = "Bearer $graphToken"
    "Content-Type" = "application/json"
}

# ── 3. Resolve Graph permission scope IDs (dynamic — no hardcoded GUIDs) ─────
Write-Host "`n[3/5] Resolving Graph permission scope IDs..." -ForegroundColor Cyan

$graphSp = (Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,oauth2PermissionScopes" `
    -Headers $h).value[0]

$scopeNames = @(
    "Policy.Read.All",
    "Directory.Read.All",
    "AuditLog.Read.All",
    "User.Read.All",
    "Application.Read.All",
    "RoleManagement.Read.All",
    "SharePoint.ReadWrite.All",
    "Sites.Read.All",
    "TeamworkSettings.Read.All",
    "Group.Read.All"
)

$resolvedScopes = $graphSp.oauth2PermissionScopes | Where-Object { $_.value -in $scopeNames }
$missingScopes  = $scopeNames | Where-Object { $_ -notin $resolvedScopes.value }

if ($missingScopes) {
    Write-Warning "Could not resolve scope IDs for: $($missingScopes -join ', ')"
    Write-Warning "These will be skipped — add them manually in the portal."
}

$resourceAccess = $resolvedScopes | ForEach-Object {
    Write-Host "     $($_.value) -> $($_.id)" -ForegroundColor Gray
    @{ id = $_.id; type = "Scope" }
}

# ── 4. Create app registration ────────────────────────────────────────────────
Write-Host "`n[4/5] Creating app registration '$AppName'..." -ForegroundColor Cyan

$appPayload = @{
    displayName            = $AppName
    signInAudience         = "AzureADMyOrg"
    isFallbackPublicClient = $true
    publicClient           = @{
        redirectUris = @("https://login.microsoftonline.com/common/oauth2/nativeclient")
    }
    requiredResourceAccess = @(
        @{
            resourceAppId  = "00000003-0000-0000-c000-000000000000"
            resourceAccess = @($resourceAccess)
        }
    )
} | ConvertTo-Json -Depth 10

$app = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/applications" `
    -Method POST -Headers $h -Body $appPayload

Write-Host "     App ID (client): $($app.appId)" -ForegroundColor Gray
Write-Host "     Object ID      : $($app.id)"    -ForegroundColor Gray

# Create service principal (required for admin consent)
$spPayload = @{ appId = $app.appId } | ConvertTo-Json
$sp = Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals" `
    -Method POST -Headers $h -Body $spPayload

Write-Host "     Service principal created: $($sp.id)" -ForegroundColor Gray

# ── 5. Grant admin consent (AllPrincipals delegated grant) ───────────────────
Write-Host "`n[5/5] Granting admin consent for all resolved scopes..." -ForegroundColor Cyan

$consentPayload = @{
    clientId    = $sp.id
    consentType = "AllPrincipals"
    resourceId  = $graphSp.id
    scope       = ($resolvedScopes.value -join " ")
    startTime   = (Get-Date).ToUniversalTime().ToString("o")
    expiryTime  = (Get-Date).AddYears(10).ToUniversalTime().ToString("o")
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
    -Method POST -Headers $h -Body $consentPayload | Out-Null

Write-Host "     Admin consent granted for: $($resolvedScopes.value -join ', ')" -ForegroundColor Gray

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host " AuditorCli App Registration Complete" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Set these env vars before running 'auditor m365 audit':" -ForegroundColor Yellow
Write-Host ""
Write-Host "  # PowerShell" -ForegroundColor DarkGray
Write-Host "  `$env:AUDITOR_CLIENT_ID = '$($app.appId)'"
Write-Host "  `$env:AUDITOR_TENANT_ID = '$tenantId'"
Write-Host ""
Write-Host "  # Bash / zsh" -ForegroundColor DarkGray
Write-Host "  export AUDITOR_CLIENT_ID='$($app.appId)'"
Write-Host "  export AUDITOR_TENANT_ID='$tenantId'"
Write-Host ""
