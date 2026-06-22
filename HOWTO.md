# AuditorCli — Guía de Uso

CLI de auditoría de seguridad para aplicaciones web, servicios de red y tenants M365/Entra ID.

---

## Instalación

**Requisitos:** Python 3.11+, pip

```bash
git clone https://github.com/polidisio/AuditorCli.git
cd AuditorCli

# Crear entorno virtual
python3.11 -m venv .venv
source .venv/bin/activate   # macOS/Linux
# .venv\Scripts\activate    # Windows

# Instalar
pip install -e ".[dev]"

# Verificar
auditor --version
```

**Herramientas externas opcionales** (aumentan cobertura de escaneo activo):

```bash
# macOS con Homebrew
brew install nmap

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

---

## Configuración

Credenciales y settings en `~/.auditor/.env` (se crea automáticamente):

```env
# M365 / Entra ID (opcionales — solo para auditoría autenticada)
AUDITOR_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AUDITOR_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AUDITOR_CLIENT_SECRET=your-secret-here

# Ajustes de red
AUDITOR_REQUEST_TIMEOUT=30
AUDITOR_MAX_CONCURRENT=10
AUDITOR_DEBUG=false
```

El archivo se crea con permisos `700` en `~/.auditor/`. Nunca hardcodear credenciales en el código.

---

## Comandos

### `auditor web recon` — Reconocimiento Web y Red

```bash
# Reconocimiento pasivo (OSINT — no contacta el target directamente)
auditor web recon --target empresa.com --passive-only

# Reconocimiento completo (pasivo + activo: nmap, nuclei)
# REQUIERE autorización escrita del cliente/target
auditor web recon --target empresa.com --authorized

# Guardar reporte en directorio específico
auditor web recon --target empresa.com --passive-only --output ./reportes

# Formato JSON en lugar de Markdown
auditor web recon --target empresa.com --passive-only --format json
```

**Qué hace:**
- Enumera subdominios (subfinder + DNS brute-force de prefijos comunes)
- Prueba servicios HTTP/HTTPS activos en todos los subdominios encontrados
- Analiza registros DNS de email (SPF, DMARC, DKIM) — identifica misconfiguraciones de spoofing
- Con `--authorized`: lanza nmap (port scan) y nuclei (CVEs, exposures, misconfigurations)

---

### `auditor m365 recon` — Reconocimiento de Tenant M365 (sin credenciales)

```bash
auditor m365 recon --domain empresa.com
```

**Qué obtiene sin credenciales:**
- Tenant ID
- Tipo de autenticación (Managed vs. Federated)
- Proveedor de identidad federado (ADFS, Okta, PingFederate, etc.)
- Confirmación de presencia de Exchange Online
- Región del tenant

---

### `auditor m365 audit` — Auditoría Autenticada M365

```bash
# Device-code flow (compatible con MFA — recomendado)
# REQUIERE --authorized flag
auditor m365 audit --domain empresa.com --authorized

# App-only (requiere AUDITOR_CLIENT_ID + AUDITOR_CLIENT_SECRET en ~/.auditor/.env)
auditor m365 audit --domain empresa.com --authorized --auth client-credentials

# Guardar reporte en JSON
auditor m365 audit --domain empresa.com --authorized --format json --output ./reportes
```

**Permisos Graph API necesarios:**
- `Policy.Read.All`
- `Directory.Read.All`
- `AuditLog.Read.All`
- `User.Read.All`
- `Application.Read.All`
- `RoleManagement.Read.All`

**Qué audita:**
| Check | Finding ID | MITRE |
|-------|-----------|-------|
| Políticas CA sin bloqueo de Legacy Auth | M365-CA-001 | T1078.004 |
| Políticas CA en modo Report-Only | M365-CA-002 | T1078.004 |
| Usuarios habilitados sin MFA registrado | M365-USR-001 | T1078.004 |
| Usuarios Guest con acceso al directorio | M365-USR-002 | T1087.004 |
| Apps con consent tenant-wide (AllPrincipals) | M365-SP-001 | T1550.001 |
| Roles privilegiados permanentes sin PIM | M365-ROLE-001 | T1078.004 |
| Reglas de reenvío externo en buzones | M365-EXO-001 | T1114.003 |
| SMTP AUTH por buzón (verificación manual) | M365-EXO-002 | T1078.004 |

---

### `auditor report view` — Ver reporte guardado

```bash
auditor report view ~/.auditor/output/audit_empresa_com_20260622_120000.json
```

---

## Flujo de Auditoría Recomendado

```
1. Recon pasivo (siempre, sin auth)
   auditor m365 recon --domain target.com
   auditor web recon --target target.com --passive-only

2. Recon activo (con autorización firmada)
   auditor web recon --target target.com --authorized

3. Auditoría autenticada M365 (con credenciales de auditor)
   auditor m365 audit --domain target.com --authorized

4. Revisar reportes en ~/.auditor/output/
```

---

## Seguridad Operacional

- **`--authorized`** es obligatorio para cualquier escaneo activo. Confirma autorización escrita.
- Credenciales nunca en el código — solo en `~/.auditor/.env` (permisos 600).
- Tokens y secrets se redactan como `[REDACTED]` en todos los reportes de salida.
- Todas las acciones se registran con timestamp en `~/.auditor/logs/auditor.log`.

---

## Tests

```bash
# Ejecutar suite completa
pytest tests/ -v

# Con coverage
pip install pytest-cov
pytest tests/ --cov=auditor --cov-report=term-missing
```

---

## Roadmap

- [ ] Módulo SharePoint/OneDrive — audit de permisos de sharing externo
- [ ] Módulo Teams — federación y guest access
- [ ] Output HTML con gráficas de riesgo
- [ ] Integración con ROADtools/AADInternals (subprocess wrappers)
- [ ] PowerShell bridge para checks Exchange que requieren EXO module

---

## Aviso Legal

Usar únicamente contra infraestructura con autorización escrita explícita del propietario.
El uso no autorizado puede constituir un delito informático.

**Owner:** Jose Maudisio (@polidisio)
