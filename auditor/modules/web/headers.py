"""Security headers, HSTS, TLS/cipher, and cookie audit — passive, no active scanning."""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

from auditor.utils.console import print_ok, print_step, print_warn


@dataclass
class HeaderAuditResult:
    url: str
    missing_headers: list[str] = field(default_factory=list)  # "[SEVERITY] message"
    hsts_issues: list[str] = field(default_factory=list)
    tls_issues: list[str] = field(default_factory=list)
    cookie_issues: list[str] = field(default_factory=list)
    redirect_issue: str | None = None  # "[SEVERITY] message" or None


# (header_name, required_value_or_None, severity_tag, description)
_REQUIRED_HEADERS: list[tuple[str, str | None, str, str]] = [
    ("Content-Security-Policy", None, "HIGH", "XSS / content injection risk"),
    ("Strict-Transport-Security", None, "HIGH", "HTTPS not enforced — MITM / downgrade risk"),
    ("X-Frame-Options", None, "MEDIUM", "Clickjacking risk"),
    ("X-Content-Type-Options", "nosniff", "MEDIUM", "MIME-type sniffing risk"),
    ("Referrer-Policy", None, "LOW", "Referrer information leakage"),
    ("Permissions-Policy", None, "LOW", "Browser feature exposure (camera, mic, geolocation)"),
    ("X-XSS-Protection", None, "LOW", "Legacy XSS filter absent (legacy browsers)"),
    ("X-Permitted-Cross-Domain-Policies", None, "LOW", "Flash/PDF cross-domain not restricted"),
    ("Cross-Origin-Opener-Policy", None, "LOW", "Spectre-class side-channel isolation missing"),
    ("Cross-Origin-Resource-Policy", None, "LOW", "Cross-origin resource read not restricted"),
    ("Cross-Origin-Embedder-Policy", None, "LOW", "SharedArrayBuffer isolation not enforced"),
]

_DISCLOSURE_HEADERS: list[str] = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
]

_WEAK_CIPHER_PATTERNS: list[tuple[str, str, str]] = [
    ("NULL", "CRITICAL", "NULL cipher — no encryption"),
    ("ANON", "CRITICAL", "Anonymous cipher — no server authentication"),
    ("EXP", "HIGH", "Export-grade cipher — vulnerable to FREAK/Logjam"),
    ("RC4", "HIGH", "RC4 cipher — broken stream cipher"),
    ("ARCFOUR", "HIGH", "RC4 (ARCFOUR) cipher — broken"),
    ("DES-CBC3", "HIGH", "3DES (DES-CBC3) — vulnerable to SWEET32"),
    ("3DES", "HIGH", "3DES cipher — vulnerable to SWEET32"),
    ("DES", "HIGH", "DES cipher — trivially breakable"),
    ("MD5", "MEDIUM", "MD5 in cipher suite — weak MAC"),
]

_TLS_PROBES: list[tuple[str, str, str]] = [
    # (attr_name_on_ssl.TLSVersion, severity_tag, description)
    ("TLSv1", "HIGH", "TLS 1.0 accepted — deprecated (PCI DSS non-compliant)"),
    ("TLSv1_1", "HIGH", "TLS 1.1 accepted — deprecated"),
]

HSTS_MIN_MAX_AGE = 31_536_000  # 1 year in seconds


# ─── Synchronous check functions ──────────────────────────────────────────────

def check_security_headers(response: httpx.Response) -> list[str]:
    """Return list of '[SEVERITY] ...' finding strings for missing/weak headers."""
    issues: list[str] = []
    headers = response.headers

    for name, expected, sev, desc in _REQUIRED_HEADERS:
        value = headers.get(name)
        if value is None:
            # Special case: X-Frame-Options absence OK if CSP has frame-ancestors
            if name == "X-Frame-Options":
                csp = headers.get("Content-Security-Policy", "")
                if "frame-ancestors" in csp:
                    continue
            issues.append(f"[{sev}] Missing header: {name} — {desc}")
        elif expected and expected.lower() not in value.lower():
            issues.append(f"[{sev}] Header {name} has wrong value '{value}' (expected: {expected})")

    for disc in _DISCLOSURE_HEADERS:
        val = headers.get(disc)
        if val:
            issues.append(f"[LOW] Version disclosure: {disc}: {val}")

    # Cache-Control: flag if no-store absent on HTTPS
    cc = headers.get("Cache-Control", "")
    if response.url.scheme == "https" and "no-store" not in cc:
        issues.append("[LOW] Cache-Control: no-store missing — sensitive responses may be cached")

    return issues


def check_hsts(response: httpx.Response) -> list[str]:
    """Return HSTS-specific '[SEVERITY] ...' findings."""
    issues: list[str] = []
    hsts = response.headers.get("Strict-Transport-Security")
    is_https = str(response.url).startswith("https://")

    if not hsts:
        if is_https:
            issues.append("[HIGH] HSTS header missing — HTTPS not enforced, downgrade attacks possible")
        return issues

    if not is_https:
        issues.append("[HIGH] HSTS header sent over HTTP — ignored by browsers, no protection")

    # Parse max-age
    max_age: int | None = None
    for part in hsts.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age"):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except (IndexError, ValueError):
                issues.append("[MEDIUM] HSTS max-age could not be parsed")

    if max_age is not None:
        if max_age == 0:
            issues.append("[HIGH] HSTS disabled (max-age=0) — HTTPS no longer enforced")
        elif max_age < HSTS_MIN_MAX_AGE:
            issues.append(
                f"[MEDIUM] HSTS max-age too low ({max_age}s) — minimum recommended: {HSTS_MIN_MAX_AGE}s (1 year)"
            )

    if "includesubdomains" not in hsts.lower():
        issues.append("[MEDIUM] HSTS missing includeSubDomains — subdomains not protected")

    if "preload" not in hsts.lower():
        issues.append("[LOW] HSTS preload directive absent — not eligible for browser preload list")

    return issues


def check_cookies(response: httpx.Response) -> list[str]:
    """Return cookie security '[SEVERITY] ...' findings from Set-Cookie headers."""
    issues: list[str] = []
    is_https = str(response.url).startswith("https://")

    raw_cookies: list[str] = response.headers.get_list("set-cookie")
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue

        name = parts[0].split("=")[0].strip()
        flags = [p.lower() for p in parts[1:]]

        if is_https and "secure" not in flags:
            issues.append(f"[MEDIUM] Cookie '{name}' missing Secure flag — transmittable over HTTP")

        if "httponly" not in flags:
            issues.append(f"[MEDIUM] Cookie '{name}' missing HttpOnly flag — accessible via JavaScript (XSS risk)")

        samesite = next((f for f in flags if f.startswith("samesite")), None)
        if samesite is None:
            issues.append(f"[MEDIUM] Cookie '{name}' missing SameSite attribute — CSRF risk")
        elif samesite == "samesite=none" and "secure" not in flags:
            issues.append(f"[HIGH] Cookie '{name}' SameSite=None without Secure — sent cross-origin over HTTP")

        # Excessive lifetime: max-age > 1 year or expires far future
        max_age_part = next((f for f in flags if f.startswith("max-age=")), None)
        if max_age_part:
            try:
                age = int(max_age_part.split("=", 1)[1])
                if age > HSTS_MIN_MAX_AGE:
                    issues.append(f"[LOW] Cookie '{name}' has excessive Max-Age ({age}s > 1 year)")
            except (IndexError, ValueError):
                pass

    return issues


def check_tls_certificate(hostname: str, port: int = 443) -> list[str]:
    """Return TLS/cert/cipher '[SEVERITY] ...' findings. Blocking — call in executor."""
    issues: list[str] = []

    # --- Certificate + negotiated cipher ---
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()  # (name, protocol, bits)

        # Expiry
        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (not_after - now).days
            if days_left < 0:
                issues.append(f"[CRITICAL] TLS certificate expired on {not_after.date()}")
            elif days_left <= 30:
                issues.append(f"[HIGH] TLS certificate expiring soon — {days_left} day(s) remaining")
            elif days_left <= 90:
                issues.append(f"[MEDIUM] TLS certificate expiring in {days_left} days")

        # Self-signed
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        if subject == issuer:
            issues.append("[HIGH] Self-signed certificate — not trusted by browsers")

        # Wildcard info
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        wildcards = [s for s in sans if s.startswith("*.")]
        if wildcards:
            issues.append(f"[INFO] Wildcard certificate: {', '.join(wildcards)}")

        # Cipher analysis
        if cipher_info:
            cipher_name = cipher_info[0] or ""
            cipher_bits = cipher_info[2] or 0

            for pattern, sev, desc in _WEAK_CIPHER_PATTERNS:
                if pattern in cipher_name.upper():
                    issues.append(f"[{sev}] {desc} (negotiated: {cipher_name})")
                    break  # one match per cipher is enough

            if cipher_bits and cipher_bits < 128:
                issues.append(f"[HIGH] Weak cipher key length — {cipher_bits} bits (negotiated: {cipher_name})")

            # PFS: TLS 1.3 ciphers (TLS_AES_*, TLS_CHACHA20_*) always have PFS
            is_tls13_cipher = cipher_name.upper().startswith("TLS_")
            if not is_tls13_cipher and not any(kw in cipher_name.upper() for kw in ("ECDHE", "DHE", "EDH")):
                issues.append(f"[MEDIUM] No Perfect Forward Secrecy — cipher: {cipher_name}")

    except ssl.SSLCertVerificationError as e:
        issues.append(f"[HIGH] TLS certificate verification failed: {e.reason}")
    except ssl.SSLError as e:
        issues.append(f"[MEDIUM] TLS error connecting to {hostname}:{port} — {e}")
    except (socket.timeout, ConnectionRefusedError, OSError):
        return issues  # port closed or unreachable — skip further probes

    # --- Protocol version probing ---
    for attr, sev, desc in _TLS_PROBES:
        tls_version = getattr(ssl.TLSVersion, attr, None)
        if tls_version is None:
            continue  # current OpenSSL doesn't support this version at all
        try:
            probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe_ctx.check_hostname = False
            probe_ctx.verify_mode = ssl.CERT_NONE
            probe_ctx.minimum_version = tls_version
            probe_ctx.maximum_version = tls_version
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with probe_ctx.wrap_socket(sock, server_hostname=hostname):
                    issues.append(f"[{sev}] {desc}")
        except (ssl.SSLError, OSError, AttributeError):
            pass  # protocol refused — good

    # TLS 1.3 support probe
    try:
        probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        probe_ctx.check_hostname = False
        probe_ctx.verify_mode = ssl.CERT_NONE
        probe_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        probe_ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with probe_ctx.wrap_socket(sock, server_hostname=hostname):
                pass  # TLS 1.3 accepted — good
    except ssl.SSLError:
        issues.append("[LOW] TLS 1.3 not supported — upgrade recommended")
    except (OSError, AttributeError):
        pass

    return issues


def check_http_redirect(hostname: str) -> str | None:
    """Return '[SEVERITY] ...' finding if HTTP does not redirect to HTTPS. Blocking."""
    try:
        with httpx.Client(verify=False, timeout=5, follow_redirects=False) as client:
            r = client.head(f"http://{hostname}")
            if r.status_code in (301, 302, 307, 308):
                location = r.headers.get("location", "")
                if location.startswith("https://"):
                    return None  # correct redirect
                return f"[MEDIUM] HTTP redirects to non-HTTPS location: {location}"
            elif r.status_code < 400:
                return "[MEDIUM] HTTP does not redirect to HTTPS — plaintext access possible"
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        pass  # HTTP port closed — not necessarily a finding
    return None


# ─── Async orchestrator ───────────────────────────────────────────────────────

async def _audit_one_host(
    client: httpx.AsyncClient,
    hostname: str,
    loop: asyncio.AbstractEventLoop,
) -> HeaderAuditResult:
    url = f"https://{hostname}"
    result = HeaderAuditResult(url=url)

    # Fetch HTTPS response for header checks
    try:
        response = await client.get(url, follow_redirects=True, timeout=10)
        result.missing_headers = check_security_headers(response)
        result.hsts_issues = check_hsts(response)
        result.cookie_issues = check_cookies(response)
    except Exception:
        pass

    # TLS check (blocking stdlib ssl — run in executor)
    result.tls_issues = await loop.run_in_executor(None, check_tls_certificate, hostname)

    # HTTP→HTTPS redirect check (blocking httpx sync — run in executor)
    result.redirect_issue = await loop.run_in_executor(None, check_http_redirect, hostname)

    return result


async def run_headers_audit(live_urls: list[str]) -> list[HeaderAuditResult]:
    """Audit security headers, HSTS, TLS, ciphers, and cookies for all live hosts."""
    # Deduplicate by hostname, prefer HTTPS URLs
    seen: dict[str, str] = {}
    for url in live_urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        if not hostname:
            continue
        if hostname not in seen or parsed.scheme == "https":
            seen[hostname] = hostname

    if not seen:
        return []

    print_step(f"Headers/HSTS/TLS/cipher audit: {len(seen)} host(s)...")
    loop = asyncio.get_event_loop()

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        tasks = [_audit_one_host(client, hostname, loop) for hostname in seen]
        results: list[HeaderAuditResult] = await asyncio.gather(*tasks, return_exceptions=False)

    total = sum(
        len(r.missing_headers) + len(r.hsts_issues) + len(r.tls_issues) + len(r.cookie_issues)
        + (1 if r.redirect_issue else 0)
        for r in results
    )
    print_ok(f"Headers/TLS audit: {total} finding(s) across {len(results)} host(s)")
    return results
