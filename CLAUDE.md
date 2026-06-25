# AuditorCli

## Qué es este proyecto
CLI tool para auditorías de seguridad: reconocimiento, enumeración y análisis de vulnerabilidades en aplicaciones web, servicios de red y tenants M365/Entra ID.

## Tipo
CLI Tool — Python

## Tech Stack
- **Lenguaje:** Python 3.11+
- **Framework:** Typer + Rich
- **Dependencies clave:** msal, httpx, pydantic, pyyaml, openpyxl, dnspython
- **Platform:** macOS / Linux

## Repository
`github.com/polidisio/AuditorCli`

---

## Quick Start

```bash
# Setup (incluye submodule de skills)
git clone --recurse-submodules https://github.com/polidisio/AuditorCli.git
cd AuditorCli
python3.11 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Generar knowledge index desde submodule
auditor knowledge update

# Run — Web recon
auditor web recon --target dominio.com --passive-only

# Run — M365 audit (requiere app registration propia en Entra ID)
export AUDITOR_CLIENT_ID="<Application ID de tu app registration>"
export AUDITOR_TENANT_ID="<Directory/Tenant ID>"
auditor m365 audit --domain contoso.com --authorized

# Test
pytest tests/
```

---

## File Structure

```
AuditorCli/
├── auditor/
│   ├── knowledge/            ← capa de conocimiento (MITRE, remediación)
│   │   ├── __init__.py       ← CheckEntry, CheckRegistry, registry singleton
│   │   ├── loader.py         ← genera skills_index.json desde submodule
│   │   ├── check_map.yaml    ← mapeo check_id → skill + MITRE ID canónico
│   │   └── skills_index.json ← índice generado (seed commiteado)
│   ├── modules/
│   │   ├── web/              ← reconocimiento web / network
│   │   ├── m365/             ← enumeración Entra ID / M365
│   │   └── report/           ← generación de reportes
│   ├── cli.py                ← entry point (Typer)
│   └── config.py             ← configuración global
├── scripts/
│   └── setup-entra-app.ps1   ← crea app registration en Entra ID (PowerShell)
├── skills/                   ← git submodule: mukul975/Anthropic-Cybersecurity-Skills
├── tests/
└── CLAUDE.md                 ← Este archivo
```

---

## Architecture

### Pattern
CLI modules → Runner → Output (JSON/Markdown/HTML)

### Módulos principales
1. **Web Recon** — subdomain enum, port scan, endpoint fuzzing, vuln scan
2. **M365 Audit** — Entra ID, Exchange, SharePoint, Teams (Graph API)
3. **Report** — generación de reporte estructurado con matriz de priorización
4. **Knowledge** — capa de enriquecimiento MITRE/remediación desde skill repo

### Web módulos (`auditor/modules/web/`)
| Archivo | Responsabilidad |
|---------|----------------|
| `passive.py` | Subdomain enum (subfinder + DNS brute-force), HTTP probe, DNS email records (SPF/DMARC/DKIM) |
| `active.py` | nmap port scan, nuclei CVE/misconfiguration scan (requiere `--authorized`) |
| `headers.py` | Security headers audit, HSTS validation, TLS/cipher check, cookie flags, HTTP→HTTPS redirect |

### M365 módulos (`auditor/modules/m365/`)
| Archivo | Responsabilidad |
|---------|----------------|
| `recon.py` | Pre-auth tenant recon (OpenID config, GetUserRealm) |
| `auth.py` | MSAL device-code + client-credentials. Requiere `AUDITOR_CLIENT_ID` propio (no acepta Azure CLI app ID — AADSTS65002) |
| `graph.py` | Graph API client con paginación |
| `entra.py` | CA policies, MFA, service principals, privileged roles |
| `exchange.py` | Inbox forwarding rules, SMTP AUTH |
| `sharepoint.py` | Sharing level, anonymous links, site collections, OneDrive |
| `teams.py` | External access, guest access, meetings, 3rd-party apps |

### Knowledge Layer (`auditor/knowledge/`)
Git submodule `skills/` apunta a `mukul975/Anthropic-Cybersecurity-Skills` (817 skills).

| Archivo | Responsabilidad |
|---------|----------------|
| `check_map.yaml` | Mapeo curado: check_id → skill + MITRE ID canónico + remediation_override |
| `loader.py` | Parsea frontmatter YAML + secciones `## Workflow` de cada SKILL.md → genera `skills_index.json`. Idempotente por commit hash |
| `__init__.py` | `CheckEntry` dataclass + `CheckRegistry` + singleton `registry` cargado al importar |
| `skills_index.json` | Índice generado (seed commiteado — funciona sin `git submodule init`) |

**Skills activas:**
- `auditing-entra-id-with-aadinternals` → CA-001/002, USR-001/002, ROLE-001, EXO-002
- `detecting-suspicious-oauth-application-consent` → SP-001, TEAMS-007/008
- `detecting-email-forwarding-rules-attack` → EXO-001
- `hunting-saas-sso-token-abuse` → SPO-001..006, TEAMS-001..006
- `attacking-entra-id-with-roadtools` *(pendiente Phase 5)*
- `analyzing-office365-audit-logs-for-compromise` *(pendiente Phase 5)*

**Actualizar índice tras pull del submodule:**
```bash
git submodule update --remote skills
auditor knowledge update
```

---

## Conventions

### Naming
- Módulos: `snake_case`
- Clases: `PascalCase`
- CLI commands: `kebab-case` (ej: `auditor m365-recon`)

### Code Style
- Indent: 4 spaces (Python) / tabs (Go)
- Sin semicolons innecesarios
- Async cuando sea posible para operaciones de red

### Git Conventions
- `feat: add m365 recon module`
- `fix: legacy auth detection false positive`
- `docs: update recon workflow`
- Branches: `feat/web-recon`, `fix/entra-id-enum`

---

## Important Rules

### Always Do
- Sanitizar targets antes de ejecutar comandos externos (no command injection)
- Requerir flag `--authorized` o archivo de autorización antes de scans activos
- Loguear todas las acciones con timestamp para audit trail

### Never Do
- Hardcodear credenciales o tokens en código
- Ejecutar scans activos sin confirmación explícita de autorización
- Guardar tokens/secrets en logs o output files sin redactar

### Security
- Credenciales: variables de entorno o `~/.auditor/config.toml` (permisos 600)
- Targets: validar formato antes de pasar a herramientas externas
- Output: redactar secrets en reportes con `[REDACTED]`
- M365 auth: no usar app IDs de Microsoft (Azure CLI, etc.) — registrar app propia en Entra ID con permisos delegados de Graph y admin consent

### M365 App Registration (prerequisito)
Usar el script automatizado (requiere `Az.Accounts` PowerShell module + Global Admin):

```powershell
.\scripts\setup-entra-app.ps1                          # tenant del Connect-AzAccount
.\scripts\setup-entra-app.ps1 -TenantId contoso.com   # tenant explícito
```

El script crea la app, habilita device-code (public client), añade los 6 permisos delegados de Graph y otorga admin consent. Al terminar imprime los `export` listos para copiar.

Pasos manuales equivalentes:
1. Entra ID → App registrations → New registration
2. Authentication → "Allow public client flows" → Yes
3. API permissions → Microsoft Graph → Delegated: `Policy.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `User.Read.All`, `Application.Read.All`, `RoleManagement.Read.All`
4. Grant admin consent
5. `export AUDITOR_CLIENT_ID=<app-id>` + `export AUDITOR_TENANT_ID=<tenant-id>`

---

## Development Workflow

### Plan First (>3 pasos)
Si la tarea tiene más de 3 pasos, escribir plan primero y confirmar antes de implementar.

### Verify Before Active Scans
Cualquier módulo de scan activo requiere flag `--authorized` explícito.

---

## Debugging

### Logs
`~/.auditor/logs/auditor.log` — rotación diaria

### Debug Commands
```bash
auditor --debug recon --target dominio.com
auditor m365-audit --verbose --dry-run
```

---

## Status

### Current Phase
- [x] Phase 1: Estructura del proyecto + CLI skeleton
- [x] Phase 2: Módulo Web Recon (passive + active)
- [x] Phase 3: Módulo M365 Audit (Entra ID + Exchange + SharePoint + Teams)
- [x] Phase 4: Report generator (Markdown + JSON + Excel)
- [x] Phase 4b: Web security headers + HSTS + TLS/cipher + cookie audit (`headers.py`)
- [x] Phase 4c: Bugfixes — f-string SyntaxError (`entra.py`), Azure CLI app ID fallback removido (`auth.py`)
- [x] Phase 4d: Knowledge layer — `auditor/knowledge/` + git submodule skills + `mitre_tactic` en `Finding` + `auditor knowledge update/status`
- [ ] Phase 5: Output HTML + ROADtools/AADInternals integration

---

## Contact
**Owner:** Jose Maudisio (@polidisio)
**Last updated:** 2026-06-25 (knowledge layer)
