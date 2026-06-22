import pytest
from auditor.utils.validators import validate_domain, validate_ip_or_cidr


def test_valid_domains():
    assert validate_domain("example.com") == "example.com"
    assert validate_domain("sub.example.com") == "sub.example.com"
    assert validate_domain("https://example.com/path") == "example.com"
    assert validate_domain("  Example.COM  ") == "example.com"


def test_invalid_domains():
    with pytest.raises(ValueError):
        validate_domain("not a domain")
    with pytest.raises(ValueError):
        validate_domain("localhost")
    with pytest.raises(ValueError):
        validate_domain("")


def test_valid_ip():
    assert validate_ip_or_cidr("192.168.1.1") == "192.168.1.1"
    assert validate_ip_or_cidr("10.0.0.0/24") == "10.0.0.0/24"


def test_invalid_ip():
    with pytest.raises(ValueError):
        validate_ip_or_cidr("not-an-ip")
    with pytest.raises(ValueError):
        validate_ip_or_cidr("999.999.999.999")
