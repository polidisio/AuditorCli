from auditor.models import AuditSession, AuditTarget, Finding, Priority, Severity


def _make_finding(priority: Priority) -> Finding:
    return Finding(
        id="TEST-001",
        title="Test finding",
        component="Test",
        vector="Test vector",
        severity=Severity.HIGH,
        priority=priority,
        description="desc",
        remediation="fix it",
    )


def test_session_counts():
    target = AuditTarget(domain="example.com")
    session = AuditSession(id="abc", target=target)

    session.add_finding(_make_finding(Priority.HIGH))
    session.add_finding(_make_finding(Priority.HIGH))
    session.add_finding(_make_finding(Priority.MEDIUM))
    session.add_finding(_make_finding(Priority.LOW))

    assert session.high_count == 2
    assert session.medium_count == 1
    assert session.low_count == 1


def test_report_json_roundtrip():
    import json
    target = AuditTarget(domain="example.com")
    session = AuditSession(id="abc", target=target)
    session.add_finding(_make_finding(Priority.HIGH))

    data = json.loads(session.model_dump_json())
    restored = AuditSession.model_validate(data)
    assert len(restored.findings) == 1
