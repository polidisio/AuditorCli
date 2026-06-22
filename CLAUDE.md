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
2. **M365 Audit** — Entra ID recon (AADInternals/ROADtools), Exchange audit, CA policy review
3. **Report** — generación de reporte estructurado con matriz de priorización

### Reference Skills (mukul975/Anthropic-Cybersecurity-Skills)
- `skills/auditing-entra-id-with-aadinternals`
- `skills/attacking-entra-id-with-roadtools`
- `skills/detecting-suspicious-oauth-application-consent`
- `skills/detecting-email-forwarding-rules-attack`
- `skills/analyzing-office365-audit-logs-for-compromise`

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
- [ ] Phase 1: Estructura del proyecto + CLI skeleton
- [ ] Phase 2: Módulo Web Recon (passive + active)
- [ ] Phase 3: Módulo M365 Audit (Entra ID + Exchange)
- [ ] Phase 4: Report generator

---

## Contact
**Owner:** Jose Maudisio (@polidisio)
**Last updated:** 2026-06-22
