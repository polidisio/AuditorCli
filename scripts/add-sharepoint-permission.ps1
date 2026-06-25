#Requires -Modules Az.Accounts
<#
.SYNOPSIS
    Adds SharePoint Online AllSites.Read delegated permission to an existing AuditorCli
    app registration and grants admin consent.

.DESCRIPTION
    Run this if "auditor m365 audit" shows SPO-INFO-001 (SharePoint settings not auditable).

    The script:
      1. Resolves your existing app registration by client ID
      2. Adds SharePoint Online AllSites.Read as a delegated permission (PATCH only,
         existing Graph permissions are preserved)
      3. Grants admin consent for the new scope
      4. Prints instructions to re-authenticate

    After running this script, the authenticated user must also have the
    SharePoint Administrator role in Entra ID for GetSPOTenant to succeed.

.PARAMETER ClientId
    Application (client) ID of the existing AuditorCli app registration.
    Defaults to $env:AUDITOR_CLIENT_ID.

.PARAMETER TenantId
    Tenant ID or domain. Defaults to $env:AUDITOR_TENANT_ID, then to Connect-AzAccount tenant.

.EXAMPLE
    .\add-sharepoint-permission.ps1

.EXAMPLE
    .\add-sharepoint-permission.ps1 -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#>
[CmdletBinding()]
param(
    [string]$ClientId = $env:AUDITOR_CLIENT_ID,
    [string]$TenantId = $env:AUDITOR_TENANT_ID
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $ClientId) {
    Write-Error "ClientId is required. Set AUDITOR_CLIENT_ID or pass -ClientId parameter."
}

# --- 1. Connect ---
Write-Host ""
Write-Host "[1/4] Connecting to Azure..." -ForegroundColor Cyan
if ($TenantId) {
    Connect-AzAccount -TenantId $TenantId | Out-Null
} else {
    Connect-AzAccount | Out-Null
}

$context  = Get-AzContext
$tenantId = $context.Tenant.Id
Write-Host "     Tenant : $tenantId" -ForegroundColor Gray
Write-Host "     Account: $($context.Account.Id)" -ForegroundColor Gray

# --- 2. Graph token (delegated, con scopes explícitos) ---
Write-Host ""
Write-Host "[2/4] Acquiring Graph API token..." -ForegroundColor Cyan

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    Write-Host "     Installing Microsoft.Graph.Authentication module..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
}

$graphScopes = @(
    "Application.Read.All",
    "Application.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All"
)

if ($TenantId) {
    Connect-MgGraph -TenantId $TenantId -Scopes $graphScopes -NoWelcome | Out-Null
} else {
    Connect-MgGraph -Scopes $graphScopes -NoWelcome | Out-Null
}

$graphToken = (Get-MgContext).AccessToken
$h = @{
    Authorization  = "Bearer $graphToken"
    "Content-Type" = "application/json"
}

# --- 3. Resolve existing app + SharePoint scope ---
Write-Host ""
Write-Host "[3/4] Resolving app registration and SharePoint scope..." -ForegroundColor Cyan

# Existing app
$app = (Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$ClientId'&`$select=id,appId,displayName,requiredResourceAccess" `
    -Headers $h).value[0]

if (-not $app) {
    Write-Error "No app registration found with clientId '$ClientId'."
}
Write-Host "     App: $($app.displayName) ($($app.appId))" -ForegroundColor Gray

# Service principal for the app (needed for consent)
$appSp = (Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$ClientId'&`$select=id" `
    -Headers $h).value[0]

if (-not $appSp) {
    Write-Error "No service principal found for clientId '$ClientId'."
}

# SharePoint Online service principal + AllSites.Read scope
$sharePointSp = (Invoke-RestMethod `
    -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0ff1-ce00-000000000000'&`$select=id,oauth2PermissionScopes" `
    -Headers $h).value[0]

if (-not $sharePointSp) {
    Write-Error "SharePoint Online service principal not found in this tenant."
}

$allSitesRead = $sharePointSp.oauth2PermissionScopes | Where-Object { $_.value -eq "AllSites.Read" }
if (-not $allSitesRead) {
    Write-Error "AllSites.Read scope not found on SharePoint Online service principal."
}
Write-Host "     AllSites.Read scope ID: $($allSitesRead.id)" -ForegroundColor Gray

# Check if SharePoint permission already present (initialize to $false for strict mode)
$spResourceId    = "00000003-0000-0ff1-ce00-000000000000"
$alreadyHasScope = $false
$alreadyHasIt    = $app.requiredResourceAccess | Where-Object { $_.resourceAppId -eq $spResourceId }

if ($alreadyHasIt) {
    $scopeMatch = $alreadyHasIt.resourceAccess | Where-Object { $_.id -eq $allSitesRead.id }
    if ($scopeMatch) {
        $alreadyHasScope = $true
        Write-Host "     AllSites.Read already present on app registration." -ForegroundColor Yellow
        Write-Host "     Skipping PATCH -- checking consent grant only." -ForegroundColor Yellow
    }
}

# --- 4. PATCH app + grant consent ---
Write-Host ""
Write-Host "[4/4] Adding SharePoint permission and granting admin consent..." -ForegroundColor Cyan

if (-not $alreadyHasScope) {
    # Build updated requiredResourceAccess: existing entries + SharePoint block
    $newSpBlock = @{
        resourceAppId  = $spResourceId
        resourceAccess = @( @{ id = $allSitesRead.id; type = "Scope" } )
    }

    # Keep existing resource access entries, append SharePoint block
    $existingResources = @($app.requiredResourceAccess | Where-Object { $_.resourceAppId -ne $spResourceId })
    $updatedAccess     = $existingResources + $newSpBlock

    $patchBody = @{ requiredResourceAccess = $updatedAccess } | ConvertTo-Json -Depth 10
    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/applications/$($app.id)" `
        -Method PATCH -Headers $h -Body $patchBody | Out-Null

    Write-Host "     PATCH: AllSites.Read added to app registration." -ForegroundColor Gray
}

# Grant admin consent
$consentPayload = @{
    clientId    = $appSp.id
    consentType = "AllPrincipals"
    resourceId  = $sharePointSp.id
    scope       = "AllSites.Read"
    startTime   = (Get-Date).ToUniversalTime().ToString("o")
    expiryTime  = (Get-Date).AddYears(10).ToUniversalTime().ToString("o")
} | ConvertTo-Json

try {
    Invoke-RestMethod `
        -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants" `
        -Method POST -Headers $h -Body $consentPayload | Out-Null
    Write-Host "     Admin consent granted for AllSites.Read." -ForegroundColor Gray
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 409) {
        Write-Host "     Admin consent already exists -- skipping." -ForegroundColor Yellow
    } else {
        throw
    }
}

# --- Done ---
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " SharePoint Permission Added" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Re-authenticate (new device-code flow picks up SharePoint consent):"
Write-Host "     auditor m365 audit --domain YOUR-DOMAIN.COM --authorized"
Write-Host ""
Write-Host "  2. The authenticated user must have SharePoint Administrator role in Entra ID"
Write-Host "     for GetSPOTenant to return tenant sharing settings."
Write-Host ""
