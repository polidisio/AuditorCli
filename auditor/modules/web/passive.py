"""Passive web reconnaissance — no direct contact with target."""
from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass, field

import dns.resolver
import httpx

from auditor.utils.console import console, print_step, print_ok, print_warn
from auditor.utils.validators import validate_domain


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class HttpProbeResult:
    url: str
    status_code: int
    title: str
    technologies: list[str] = field(default_factory=list)
    redirect_url: str | None = None


async def probe_url(client: httpx.AsyncClient, url: str) -> HttpProbeResult | None:
    try:
        r = await client.get(url, follow_redirects=True, timeout=10)
        title = ""
        if b"<title" in r.content:
            import re
            m = re.search(rb"<title[^>]*>(.*?)</title>", r.content, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).decode("utf-8", errors="replace").strip()[:120]
        return HttpProbeResult(
            url=str(r.url),
            status_code=r.status_code,
            title=title,
        )
    except Exception:
        return None


async def http_probe(subdomains: list[str]) -> list[HttpProbeResult]:
    """Probe list of subdomains for live HTTP/HTTPS services."""
    results: list[HttpProbeResult] = []
    urls = []
    for sub in subdomains:
        urls.append(f"https://{sub}")
        urls.append(f"http://{sub}")

    async with httpx.AsyncClient(verify=False, timeout=10) as client:
        tasks = [probe_url(client, url) for url in urls]
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result and result.status_code < 500:
                results.append(result)

    return sorted(results, key=lambda r: r.url)


def enumerate_subdomains_dns(domain: str) -> list[str]:
    """Basic DNS brute-force using a small wordlist."""
    wordlist = [
        "www", "mail", "smtp", "pop", "imap", "ftp", "api", "dev", "staging",
        "test", "app", "admin", "portal", "vpn", "remote", "login", "auth",
        "sso", "id", "cdn", "static", "assets", "media", "owa", "autodiscover",
        "lyncdiscover", "enterpriseregistration", "enterpriseenrollment",
    ]
    found: list[str] = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    for word in wordlist:
        fqdn = f"{word}.{domain}"
        try:
            resolver.resolve(fqdn, "A")
            found.append(fqdn)
        except Exception:
            pass

    return found


def run_subfinder(domain: str) -> list[str]:
    """Run subfinder if available, return discovered subdomains."""
    try:
        result = subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-all"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except FileNotFoundError:
        print_warn("subfinder not found — skipping (install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)")
        return []
    except subprocess.TimeoutExpired:
        print_warn("subfinder timed out")
        return []


def check_dns_records(domain: str) -> dict[str, list[str]]:
    """Check SPF, DMARC, DKIM-selector1, MX records."""
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5

    checks = {
        "SPF": (domain, "TXT"),
        "DMARC": (f"_dmarc.{domain}", "TXT"),
        "DKIM_selector1": (f"selector1._domainkey.{domain}", "TXT"),
        "DKIM_selector2": (f"selector2._domainkey.{domain}", "TXT"),
        "MX": (domain, "MX"),
    }

    for key, (qname, rtype) in checks.items():
        try:
            answers = resolver.resolve(qname, rtype)
            records[key] = [str(r) for r in answers]
        except Exception:
            records[key] = []

    return records


def analyze_dmarc(records: dict[str, list[str]]) -> list[str]:
    """Return list of findings from DNS record analysis."""
    issues: list[str] = []

    spf = " ".join(records.get("SPF", []))
    if not spf or "v=spf1" not in spf:
        issues.append("SPF record missing")
    elif "~all" in spf:
        issues.append("SPF uses ~all (SoftFail) — should be -all (HardFail)")

    dmarc = " ".join(records.get("DMARC", []))
    if not dmarc or "v=DMARC1" not in dmarc:
        issues.append("DMARC record missing — spoofing unprotected")
    elif "p=none" in dmarc:
        issues.append("DMARC policy is p=none — no enforcement, only monitoring")
    elif "p=quarantine" in dmarc:
        issues.append("DMARC policy is p=quarantine — should be p=reject")

    if not records.get("DKIM_selector1") and not records.get("DKIM_selector2"):
        issues.append("DKIM records not found for selector1/selector2")

    return issues


async def run_passive_recon(domain: str) -> SubdomainResult:
    domain = validate_domain(domain)
    result = SubdomainResult(domain=domain)

    print_step(f"Passive recon: {domain}")

    # Subfinder
    print_step("Running subfinder...")
    subfinder_subs = run_subfinder(domain)
    result.subdomains.extend(subfinder_subs)
    if subfinder_subs:
        print_ok(f"subfinder: {len(subfinder_subs)} subdomains")

    # DNS brute-force with common prefixes
    print_step("DNS brute-force (common prefixes)...")
    dns_subs = enumerate_subdomains_dns(domain)
    for sub in dns_subs:
        if sub not in result.subdomains:
            result.subdomains.append(sub)
    print_ok(f"DNS: {len(dns_subs)} subdomains resolved")

    # Remove duplicates
    result.subdomains = sorted(set(result.subdomains))
    print_ok(f"Total unique subdomains: {len(result.subdomains)}")

    return result
