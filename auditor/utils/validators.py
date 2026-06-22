from __future__ import annotations

import re
import ipaddress

import validators as _v


_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def validate_domain(domain: str) -> str:
    """Return clean domain or raise ValueError."""
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain!r}")
    return domain


def validate_ip_or_cidr(value: str) -> str:
    """Return clean IP/CIDR or raise ValueError."""
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR: {value!r}")


def validate_url(url: str) -> str:
    if not _v.url(url):
        raise ValueError(f"Invalid URL: {url!r}")
    return url
