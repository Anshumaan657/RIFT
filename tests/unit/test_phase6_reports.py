import json

import pytest

from rift.domain.models import ReportFormat
from rift.reports.models import ReportVariant
from rift.reports.render import render_report


def snapshot(marker: str = "safe marker") -> dict[str, object]:
    return {
        "assessment": {
            "id": "assessment-1",
            "state": "completed_with_errors",
        },
        "target": {
            "scheme": "https",
            "hostname": "staging.example.test",
            "port": 443,
            "base_path": "/api",
        },
        "authorization": {
            "valid_from": "2026-01-01T00:00:00+00:00",
            "valid_until": "2026-01-02T00:00:00+00:00",
        },
        "checks": [
            {
                "check_identifier": "RIFT-AUTHN-001",
                "check_version": "1.0",
                "outcome": "finding",
                "summary": marker,
                "reason_code": "ANONYMOUS_MARKER_EXPOSED",
            },
            {
                "check_identifier": "RIFT-AUTHZ-001",
                "check_version": "1.0",
                "outcome": "error",
                "summary": "Controlled transport error",
                "reason_code": "SERVER_ERROR",
            },
        ],
        "coverage": {
            "tested": ["RIFT-AUTHN-001"],
            "skipped": [],
            "failed": ["RIFT-AUTHZ-001"],
        },
        "findings": [],
        "evidence": [],
        "limitations": "Skipped and failed checks are not clean results.",
    }


def test_html_escapes_target_controlled_content_and_marks_draft():
    content = render_report(
        snapshot('<script>alert("x")</script>'),
        format=ReportFormat.HTML,
        variant=ReportVariant.TECHNICAL_DETAIL,
        snapshot_digest="a" * 64,
    ).decode()
    assert "<script>" not in content
    assert "&lt;script&gt;" in content
    assert "DRAFT" in content


def test_reviewed_export_is_distinct_and_visibly_reviewed():
    content = render_report(
        snapshot(),
        format=ReportFormat.HTML,
        variant=ReportVariant.FOUNDER_SUMMARY,
        snapshot_digest="b" * 64,
        review_status="reviewed",
    ).decode()
    assert "REVIEWED — approved for delivery" in content
    assert "operator review required" not in content


def test_json_report_is_deterministic_and_contains_partial_results():
    first = render_report(
        snapshot(),
        format=ReportFormat.JSON,
        variant=ReportVariant.TECHNICAL_DETAIL,
        snapshot_digest="c" * 64,
    )
    second = render_report(
        snapshot(),
        format=ReportFormat.JSON,
        variant=ReportVariant.TECHNICAL_DETAIL,
        snapshot_digest="c" * 64,
    )
    assert first == second
    parsed = json.loads(first)
    assert parsed["review_status"] == "draft"
    assert parsed["checks"][1]["outcome"] == "error"


def test_pdf_renderer_outputs_a_pdf():
    try:
        content = render_report(
            snapshot(),
            format=ReportFormat.PDF,
            variant=ReportVariant.FOUNDER_SUMMARY,
            snapshot_digest="d" * 64,
        )
    except TypeError as exc:
        if "pydyf.PDF" in str(exc) or "positional argument" in str(exc):
            pytest.skip("local virtualenv has stale WeasyPrint/pydyf; lock pins WeasyPrint 69")
        raise
    assert content.startswith(b"%PDF-")
