from asfops.fleet.schemas import SEVERITY_ORDER, AgentReport, Finding, Severity


def test_severity_order_is_critical_first() -> None:
    assert SEVERITY_ORDER[Severity.critical] < SEVERITY_ORDER[Severity.high]
    assert SEVERITY_ORDER[Severity.high] < SEVERITY_ORDER[Severity.informational]


def test_agent_report_round_trips() -> None:
    report = AgentReport(
        summary="ok",
        findings=[
            Finding(
                title="XSS",
                severity=Severity.high,
                description="reflected",
                recommendation="encode output",
            )
        ],
        confidence="high",
    )
    dumped = report.model_dump_json()
    restored = AgentReport.model_validate_json(dumped)
    assert restored == report


def test_finding_defaults() -> None:
    finding = Finding(title="t", severity=Severity.low, description="d", recommendation="r")
    assert finding.references == []
    assert finding.likelihood is None
