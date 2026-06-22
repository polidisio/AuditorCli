# AuditorCli

## Qué es este proyecto
CLI tool para auditorías de seguridad: reconocimiento, enumeración y análisis de vulnerabilidades en aplicaciones web, servicios de red y tenants M365/Entra ID.

## Tipo
CLI Tool — Python/Shell (TBD según stack elegido)

## Tech Stack
- **Lenguaje:** TBD (Python / Go / Shell)
- **Framework:** TBD
- **Dependencies clave:** Por definir al inicializar
- **Platform:** macOS / Linux

## Repository
`github.com/polidisio/AuditorCli`

---

## Quick Start

```bash
# Setup
pip install -r requirements.txt   # o: go mod download

# Run
./auditor recon --target dominio.com

# Test
pytest tests/
```

---

## File Structure

```
AuditorCli/
├── auditor/
│   ├── modules/
│   │   ├── web/          ← reconocimiento web / network
│   │   ├── m365/         ← enumeración Entra ID / M365
│   │   └── report/       ← generación de reportes
│   ├── cli.py            ← entry point (Click/Typer)
│   └── config.py         ← configuración global
├── tests/
├── docs/
└── CLAUDE.md             ← Este archivo
```

---

## Architecture

### Pattern
CLI modules → Runner → Output (JSON/Markdown/HTML)

### Módulos principales
1. **Web Recon** — subdomain enum, port scan, endpoint fuzzing, vuln scan
2. **M365 Audit** — Entra ID, Exchange, SharePoint, Teams (Graph API)
3. **Report** — generación de reporte estructurado con matriz de priorización

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
| `auth.py` | MSAL device-code + client-credentials |
| `graph.py` | Graph API client con paginación |
| `entra.py` | CA policies, MFA, service principals, privileged roles |
| `exchange.py` | Inbox forwarding rules, SMTP AUTH |
| `sharepoint.py` | Sharing level, anonymous links, site collections, OneDrive |
| `teams.py` | External access, guest access, meetings, 3rd-party apps |

### Reference Skills (mukul975/Anthropic-Cybersecurity-Skills)
- `skills/auditing-entra-id-with-aadinternals`
- `skills/attacking-entra-id-with-roadtools`
- `skills/detecting-suspicious-oauth-application-consent`
- `skills/detecting-email-forwarding-rules-attack`
- `skills/analyzing-office365-audit-logs-for-compromise`
- `skills/hunting-saas-sso-token-abuse`

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
- [ ] Phase 5: Output HTML + ROADtools/AADInternals integration

---

## Contact
**Owner:** Jose Maudisio (@polidisio)
**Last updated:** 2026-06-22
