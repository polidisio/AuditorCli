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

# Instalar en modo editable con dev deps
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

## Reinstalación

Cuando se actualiza el repositorio (`git pull`) o se añaden nuevos módulos, no es necesario reinstalar si ya estás en modo editable (`pip install -e`). Los cambios en `.py` toman efecto inmediatamente.

**Cuando SÍ hace falta reinstalar:**
- Se modificó `pyproject.toml` (nuevas dependencias, scripts, versión)
- El entrypoint `auditor` dejó de funcionar
- Se corrompió el entorno virtual
- Error de tipo `ModuleNotFoundError` tras un `git pull`

### Reinstalación rápida (mantiene el venv)

```bash
source .venv/bin/activate

# Actualizar código
git pull

# Reinstalar (resuelve nuevas deps y regenera entrypoints)
pip install -e ".[dev]"

# Verificar
auditor --version
```

### Reinstalación limpia (venv desde cero)

```bash
# Desactivar y eliminar entorno anterior
deactivate 2>/dev/null; rm -rf .venv

# Recrear
python3.11 -m venv .venv
source .venv/bin/activate

# Reinstalar
pip install -e ".[dev]"

# Verificar
auditor --version
```

### Actualizar solo dependencias (sin tocar el código)

```bash
pip install --upgrade -e ".[dev]"
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
- **Audita headers de seguridad HTTP** (ver tabla abajo)
- **Valida HSTS** (presencia, max-age, includeSubDomains, preload)
- **Audita TLS y cipher suites** (cert expiry, protocolos débiles, cifrados rotos, PFS)
- **Audita flags de cookies** (Secure, HttpOnly, SameSite)
- **Verifica redirect HTTP→HTTPS**
- Con `--authorized`: lanza nmap (port scan) y nuclei (CVEs, exposures, misconfigurations)

#### Headers auditados

| Header | Finding si ausente | Severidad |
|---|---|---|
| `Content-Security-Policy` | XSS / content injection risk | HIGH |
| `Strict-Transport-Security` | HTTPS no enforced, MITM posible | HIGH |
| `X-Frame-Options` | Clickjacking risk | MEDIUM |
| `X-Content-Type-Options` | MIME sniffing risk | MEDIUM |
| `Referrer-Policy` | Info leakage en referrer | LOW |
| `Permissions-Policy` | Feature exposure (cam, mic, geo) | LOW |
| `X-XSS-Protection` | Filtro XSS ausente (browsers legacy) | LOW |
| `X-Permitted-Cross-Domain-Policies` | Flash/PDF cross-domain no restringido | LOW |
| `Cross-Origin-Opener-Policy` | Side-channel isolation ausente (Spectre) | LOW |
| `Cross-Origin-Resource-Policy` | Cross-origin reads no restringidos | LOW |
| `Cross-Origin-Embedder-Policy` | SharedArrayBuffer isolation ausente | LOW |
| `Cache-Control: no-store` | Respuestas sensibles cacheadas | LOW |
| `Server` / `X-Powered-By` | Disclosure de versión/tecnología | LOW |

#### HSTS — checks ejecutados

| Check | Severidad |
|---|---|
| Header HSTS ausente | HIGH |
| `max-age=0` (HSTS desactivado) | HIGH |
| HSTS enviado sobre HTTP (ignorado por browsers) | HIGH |
| `max-age` < 31 536 000 s (1 año) | MEDIUM |
| Ausencia de `includeSubDomains` | MEDIUM |
| Ausencia de `preload` | LOW |

#### TLS / Certificate / Cipher — checks ejecutados

| Check | Severidad |
|---|---|
| Certificado expirado | CRITICAL |
| Cifrado NULL (sin cifrado) | CRITICAL |
| Cifrado anónimo (sin autenticación) | CRITICAL |
| TLS 1.0 aceptado | HIGH |
| TLS 1.1 aceptado | HIGH |
| Cifrado RC4 o ARCFOUR | HIGH |
| Cifrado 3DES / DES-CBC3 (SWEET32) | HIGH |
| Cifrado EXPORT-grade (FREAK/Logjam) | HIGH |
| Certificado self-signed | HIGH |
| SAN mismatch | HIGH |
| Certificado expira en ≤30 días | HIGH |
| Sin Perfect Forward Secrecy (no ECDHE/DHE) | MEDIUM |
| MD5 en cipher suite (MAC débil) | MEDIUM |
| Certificado expira en ≤90 días | MEDIUM |
| TLS 1.3 no soportado | LOW |

#### Cookie flags — checks ejecutados

| Check | Severidad |
|---|---|
| `SameSite=None` sin `Secure` | HIGH |
| Ausencia de flag `Secure` (en HTTPS) | MEDIUM |
| Ausencia de flag `HttpOnly` | MEDIUM |
| Ausencia de atributo `SameSite` | MEDIUM |
| `Max-Age` > 1 año | LOW |

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
- `Sites.Read.All` *(SharePoint audit)*
- `TeamSettings.Read.All` *(Teams audit)*
- `Group.Read.All` *(Teams enumeration)*

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
| **SharePoint** | | |
| Sharing anónimo ("Anyone") habilitado | SPO-001 | T1567.002 |
| Link por defecto es tipo anónimo | SPO-002 | T1567.002 |
| Links anónimos sin fecha de expiración | SPO-003 | T1567.002 |
| Legacy auth habilitada en SharePoint | SPO-004 | T1078.004 |
| Site collections con sharing anónimo | SPO-005 | T1567.002 |
| OneDrive permite links anónimos | SPO-006 | T1567.002 |
| **Teams** | | |
| Acceso externo abierto a todos los dominios | TEAMS-001 | T1566.003 |
| Guest access habilitado (verificar permisos) | TEAMS-002 | T1087.004 |
| Comunicación con cuentas no gestionadas (Skype) | TEAMS-003 | T1566.003 |
| Teams públicos visibles a todo el tenant | TEAMS-004 | T1087.004 |
| Teams con miembros guest | TEAMS-005 | T1087.004 |
| Usuarios anónimos pueden unirse a reuniones | TEAMS-006 | T1566.003 |
| Apps de terceros permitidas sin whitelist | TEAMS-007 | T1550.001 |
| Sideloading de apps custom permitido | TEAMS-008 | T1550.001 |

---

### SharePoint / OneDrive — Checks clave

El módulo `m365 audit` incluye SharePoint automáticamente. Checks ejecutados:

```
SPO-001  Tenant sharing level = "Anyone with the link" (anonymous)
SPO-002  Default link type = anonymous
SPO-003  Anonymous links sin expiración
SPO-004  Legacy auth habilitada en SPO
SPO-005  Site collections individuales con sharing anónimo
SPO-006  OneDrive for Business con sharing anónimo
```

Para auditar permisos de una site collection específica, usar el SDK directamente:

```python
from auditor.modules.m365.sharepoint import audit_sharepoint_permissions
# site_id obtenible de: https://graph.microsoft.com/v1.0/sites?search=*
await audit_sharepoint_permissions(token, "contoso.sharepoint.com,<site-id>,<web-id>")
```

**Verificación manual complementaria (PowerShell):**
```powershell
Connect-SPOService -Url https://contoso-admin.sharepoint.com
Get-SPOTenant | Select SharingCapability, DefaultSharingLinkType, RequireAnonymousLinksExpireInDays
Get-SPOSite -Limit All | Select Url, SharingCapability | Where {$_.SharingCapability -ne "Disabled"}
```

---

### Teams — Checks clave

```
TEAMS-001  External access abierto a todos los dominios externos
TEAMS-002  Guest access habilitado (revisar permisos granulares)
TEAMS-003  Comunicación con cuentas personales/Skype habilitada
TEAMS-004  Teams con visibilidad Public (cualquier interno puede unirse)
TEAMS-005  Teams con miembros guest — listar cuáles
TEAMS-006  Usuarios anónimos pueden unirse a reuniones sin cuenta
TEAMS-007  Apps de terceros permitidas sin lista blanca
TEAMS-008  Sideloading de apps custom habilitado
```

**Verificación manual complementaria (PowerShell):**
```powershell
# Requires MicrosoftTeams module
Connect-MicrosoftTeams
Get-CsExternalAccessPolicy -Identity Global
Get-CsTeamsGuestAccessConfiguration
Get-CsTeamsMeetingPolicy -Identity Global | Select AllowAnonymousUsersToJoinMeeting
Get-CsTeamsAppPermissionPolicy -Identity Global
```

---

### `auditor report view` — Ver reporte en terminal

```bash
auditor report view ~/.auditor/output/audit_empresa_com_20260622_120000.json
```

---

### `auditor report export` — Exportar a Excel / Markdown / JSON

Exporta una sesión JSON ya guardada a otro formato **sin necesidad de re-escanear**.

```bash
# Exportar a Excel (por defecto)
auditor report export ~/.auditor/output/audit_empresa_com_20260622_120000.json

# Especificar formato y directorio de salida
auditor report export audit.json --format xlsx --output ./entregas/
auditor report export audit.json --format markdown --output ./entregas/
auditor report export audit.json --format json --output ./entregas/
```

**El archivo Excel generado contiene 3 hojas:**

| Hoja | Contenido |
|------|-----------|
| **Resumen Ejecutivo** | Metadatos del target, conteo por prioridad (Alta/Media/Baja), leyenda de colores |
| **Hallazgos** | Tabla completa con todas las columnas: ID, Componente, Título, MITRE ATT&CK, Severidad, Prioridad, Vector, Descripción, Evidencia, Remediación. Header congelado, AutoFilter activo, ordenado por prioridad |
| **Matriz por Componente** | Agrupación de findings por componente: cuántos Alta/Media/Baja tiene cada área |

**Colores por prioridad en Excel:**
- Rojo oscuro `#C0392B` → Alta
- Naranja `#E67E22` → Media
- Azul `#2980B9` → Baja

**Generar Excel directamente durante el escaneo:**
```bash
# Web recon con output Excel
auditor web recon --target empresa.com --passive-only --format xlsx

# M365 audit con output Excel
auditor m365 audit --domain empresa.com --authorized --format xlsx
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

- [x] Módulo SharePoint/OneDrive — audit de permisos de sharing externo
- [x] Módulo Teams — federación, guest access, meeting policies, app policies
- [ ] Output HTML con gráficas de riesgo
- [ ] Integración con ROADtools/AADInternals (subprocess wrappers)
- [ ] PowerShell bridge para checks Exchange que requieren EXO module
- [ ] Sensitivity labels audit (SharePoint + Teams)
- [ ] Cross-tenant access policy (B2B) deep audit
- [ ] Defender for Cloud Apps (MCAS) alerts integration

---

## Aviso Legal

Usar únicamente contra infraestructura con autorización escrita explícita del propietario.
El uso no autorizado puede constituir un delito informático.

**Owner:** Jose Maudisio (@polidisio)
