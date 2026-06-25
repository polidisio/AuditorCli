# AuditorCli

Security audit CLI for web applications, network services, and Microsoft 365 / Entra ID tenants.

Designed for penetration testers and security engineers who need structured, reproducible audits with MITRE ATT&CK–mapped findings and export-ready reports.

---

## Features

| Module | What it does |
|--------|-------------|
| **Web Recon** | Subdomain enumeration, HTTP probing, DNS email security (SPF/DMARC/DKIM), security headers, HSTS, TLS/cipher audit, cookie flags, HTTP→HTTPS redirect |
| **M365 Audit** | Entra ID (CA policies, MFA, service principals, PIM roles), Exchange Online (forwarding rules, SMTP AUTH), SharePoint/OneDrive (sharing levels, anonymous links), Teams (external access, guest, meetings, apps) |
| **Knowledge Layer** | Enriches every finding with authoritative MITRE ATT&CK tactics/techniques and remediation text sourced from [`Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) |
| **Reports** | Markdown, JSON, and Excel (.xlsx) with executive summary, full findings table, and risk matrix by component |

---

## Requirements

- Python 3.11+
- Optional (active scanning): `nmap`, `subfinder`, `nuclei`, `httpx`
- M365 audit: App Registration in Entra ID with delegated Graph API permissions

---

## Installation

```bash
# Clone with skills submodule
git clone --recurse-submodules https://github.com/polidisio/AuditorCli.git
cd AuditorCli

python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Build knowledge index (enriches MITRE IDs + remediation from skills)
auditor knowledge update

auditor --version
```

> If you cloned without `--recurse-submodules`:
> ```bash
> git submodule update --init --recursive
> auditor knowledge update
> ```

---

## M365 Setup — App Registration

Before running `auditor m365 audit` you need an Entra ID App Registration. Use the included PowerShell script (requires `Az.Accounts` module + Global Admin):

```powershell
.\scripts\setup-entra-app.ps1
# or with an explicit tenant:
.\scripts\setup-entra-app.ps1 -TenantId contoso.onmicrosoft.com
```

The script:
1. Connects via `Connect-AzAccount`
2. Resolves Graph permission scope IDs dynamically
3. Creates a public-client app registration with device-code flow enabled
4. Adds the 10 required delegated Graph permissions
5. Grants tenant-wide admin consent
6. Prints the env vars ready to copy

Then set:
```bash
export AUDITOR_CLIENT_ID="<Application ID>"
export AUDITOR_TENANT_ID="<Tenant ID>"
```

Or put them in `~/.auditor/.env`.

**Required Graph API permissions (delegated):**

| Permission | Purpose |
|---|---|
| `Policy.Read.All` | Conditional Access policies |
| `Directory.Read.All` | Users, groups, service principals |
| `AuditLog.Read.All` | Sign-in and audit logs |
| `User.Read.All` | MFA registration details |
| `Application.Read.All` | OAuth app grants |
| `RoleManagement.Read.All` | Privileged role assignments |
| `SharePoint.ReadWrite.All` | SharePoint tenant admin settings (sharing config, legacy auth, OneDrive) |
| `Sites.Read.All` | Site collections enumeration + external user permissions |
| `TeamworkSettings.Read.All` | Teams policies (external access, guest, meetings, apps) |
| `Group.Read.All` | Teams list + guest member enumeration |

---

## Usage

### Web Reconnaissance

```bash
# Passive — no direct contact with target (OSINT only)
auditor web recon --target empresa.com --passive-only

# Full — passive + active (nmap, nuclei). Requires written authorization.
auditor web recon --target empresa.com --authorized

# JSON output to specific directory
auditor web recon --target empresa.com --passive-only --format json --output ./reports
```

### M365 Pre-auth Recon (no credentials)

```bash
auditor m365 recon --domain empresa.com
```

Identifies tenant ID, authentication type (Managed/Federated), identity provider, Exchange presence, and region — without any credentials.

### M365 Authenticated Audit

```bash
# Device-code flow (supports MFA — recommended)
auditor m365 audit --domain empresa.com --authorized

# App-only / client credentials
auditor m365 audit --domain empresa.com --authorized --auth client-credentials

# Excel report
auditor m365 audit --domain empresa.com --authorized --format xlsx
```

### Knowledge Base

```bash
auditor knowledge status    # show index metadata and loaded entries
auditor knowledge update    # rebuild index from skills submodule
```

### Reports

```bash
# View a saved session in the terminal
auditor report view ~/.auditor/output/audit_empresa_20260625.json

# Re-export to a different format
auditor report export audit.json --format xlsx --output ./deliverables
auditor report export audit.json --format markdown
```

---

## Findings

All findings follow a consistent schema:

| Field | Description |
|---|---|
| `id` | Unique check ID (e.g. `M365-CA-001`, `WEB-TLS-003`) |
| `title` | Short human-readable title |
| `component` | System area (e.g. `Entra ID — Conditional Access`) |
| `vector` | Attack vector / threat scenario |
| `mitre_id` | MITRE ATT&CK technique (e.g. `T1078.004`) |
| `mitre_tactic` | MITRE ATT&CK tactic (e.g. `Initial Access`) |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `priority` | `alta` / `media` / `baja` |
| `description` | Detailed explanation with evidence |
| `remediation` | Step-by-step fix (enriched from skill repo when available) |

### M365 Check Coverage

| Check ID | Finding | MITRE |
|---|---|---|
| M365-CA-001 | Legacy auth not blocked by CA policy | T1078.004 |
| M365-CA-002 | CA policies in report-only mode | T1078.004 |
| M365-USR-001 | Enabled users without MFA | T1078.004 |
| M365-USR-002 | Guest users in tenant | T1087.004 |
| M365-SP-001 | OAuth apps with tenant-wide consent | T1550.001 |
| M365-ROLE-001 | Permanent privileged roles (no PIM) | T1078.004 |
| M365-EXO-001 | Mailboxes with external forwarding rules | T1114.003 |
| M365-EXO-002 | SMTP AUTH per-mailbox (manual verification) | T1078.004 |
| SPO-001 | SharePoint anonymous link sharing enabled | T1567.002 |
| SPO-002 | Default link type is anonymous | T1567.002 |
| SPO-003 | Anonymous links have no expiry | T1567.002 |
| SPO-004 | Legacy auth enabled in SharePoint | T1078.004 |
| SPO-005 | Site collections with anonymous sharing | T1567.002 |
| SPO-006 | OneDrive allows anonymous links | T1567.002 |
| TEAMS-001 | External access open to all domains | T1566.003 |
| TEAMS-002 | Guest access enabled | T1087.004 |
| TEAMS-003 | Communication with unmanaged accounts | T1566.003 |
| TEAMS-004 | Public Teams visible tenant-wide | T1087.004 |
| TEAMS-005 | Teams with guest members | T1087.004 |
| TEAMS-006 | Anonymous users can join meetings | T1566.003 |
| TEAMS-007 | Third-party apps allowed tenant-wide | T1550.001 |
| TEAMS-008 | Custom app sideloading allowed | T1550.001 |

### Web Check Coverage

| Check ID | Finding | MITRE |
|---|---|---|
| WEB-DNS-* | SPF / DMARC / DKIM misconfiguration | T1566.001 |
| WEB-HDR-* | Missing security headers, HSTS issues, cookie flags | — |
| WEB-TLS-* | Weak TLS version, broken ciphers, certificate issues | T1557.002 |
| WEB-NUCL-* | Active CVE/misconfiguration findings (nuclei) | varies |

---

## Knowledge Layer

Findings are enriched with data from [`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (817 skills, added as a git submodule).

```
auditor/knowledge/
├── check_map.yaml      ← curated mapping: check_id → skill name + canonical MITRE ID
├── loader.py           ← parses SKILL.md frontmatter + Workflow sections → skills_index.json
├── __init__.py         ← CheckRegistry singleton loaded at import
└── skills_index.json   ← committed seed (works without submodule init)
```

Each `SKILL.md` provides:
- **MITRE ATT&CK** technique from frontmatter (`mitre_attack` field)
- **Remediation text** from `## Workflow` or `## Detection and OPSEC Notes` sections

The loader is idempotent: rebuilds only when the submodule commit changes.

To update after pulling new skills:
```bash
git submodule update --remote skills
auditor knowledge update
```

---

## Excel Report

The `.xlsx` export contains 3 sheets:

| Sheet | Contents |
|---|---|
| **Resumen Ejecutivo** | Target metadata, finding counts by priority, color legend |
| **Hallazgos** | Full findings table: ID, Component, Title, MITRE ATT&CK, Tactic, Severity, Priority, Vector, Description, Evidence, Remediation |
| **Matriz por Componente** | Risk aggregation per component (High/Medium/Low counts) |

Colors: Red `#C0392B` → High · Orange `#E67E22` → Medium · Blue `#2980B9` → Low

---

## Configuration

`~/.auditor/.env`:

```env
AUDITOR_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AUDITOR_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AUDITOR_CLIENT_SECRET=your-secret-here     # only for client-credentials flow
AUDITOR_REQUEST_TIMEOUT=30
AUDITOR_MAX_CONCURRENT=10
AUDITOR_DEBUG=false
```

Credentials are never logged or included in reports — secrets are redacted as `[REDACTED]`.

---

## Recommended Audit Workflow

```
1. Passive recon (no auth, always safe)
   auditor m365 recon --domain target.com
   auditor web recon --target target.com --passive-only

2. Active recon (requires written authorization)
   auditor web recon --target target.com --authorized

3. Authenticated M365 audit
   auditor m365 audit --domain target.com --authorized

4. Export report
   auditor report export ~/.auditor/output/<session>.json --format xlsx
```

---

## Development

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=auditor --cov-report=term-missing

# Linting
ruff check auditor/
```

---

## Security

- `--authorized` flag required for all active scanning — confirms written authorization
- Credentials only in `~/.auditor/.env` (permissions 600) or environment variables
- No hardcoded secrets anywhere in the codebase
- All actions logged with timestamps to `~/.auditor/logs/auditor.log`
- Use only against infrastructure you own or have explicit written permission to test

---

## License

Apache 2.0

**Owner:** Jose Audisio ([@polidisio](https://github.com/polidisio))
