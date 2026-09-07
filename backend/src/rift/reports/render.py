"""Escaped deterministic HTML, JSON, and PDF rendering."""

from jinja2 import BaseLoader, Environment, select_autoescape
from weasyprint import HTML

from rift.domain.models import ReportFormat
from rift.engine.persistence import canonical_json
from rift.reports.models import ReportVariant

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RIFT {{ variant }}</title>
<style>body{font:14px system-ui;margin:40px;color:#18212b}h1{font-size:24px}
.draft{color:#9a3412;font-weight:700}code,pre{white-space:pre-wrap;word-break:break-word}
section{margin:24px 0;border-top:1px solid #ccd3da;padding-top:12px}</style></head>
<body><p class="draft">{{ review_status|upper }}{% if review_status == 'draft' %} — operator review required before delivery{% else %} — approved for delivery{% endif %}</p>
<h1>RIFT {{ variant|replace('_', ' ')|title }}</h1>
<p>Assessment {{ report.assessment.id }}</p>
<p>Target: <code>{{ report.target.scheme }}://{{ report.target.hostname }}:{{ report.target.port }}{{ report.target.base_path }}</code></p>
<p>State: {{ report.assessment.state }}</p>
<p>Authorization window: {{ report.authorization.valid_from }} to {{ report.authorization.valid_until }}</p>
<section><h2>Results</h2>{% for item in report.checks %}
<h3>{{ item.check_identifier }} v{{ item.check_version }} — {{ item.outcome }}</h3>
<p>{{ item.summary }}</p><p>Reason: <code>{{ item.reason_code }}</code></p>
{% else %}<p>No check results were recorded.</p>{% endfor %}</section>
<section><h2>Coverage</h2>
<p>Tested: {{ report.coverage.tested|join(', ') or 'none' }}</p>
<p>Skipped: {{ report.coverage.skipped|join(', ') or 'none' }}</p>
<p>Failed or cancelled: {{ report.coverage.failed|join(', ') or 'none' }}</p></section>
<section><h2>Findings</h2>{% for finding in report.findings %}
<h3>{{ finding.title }}</h3><p>{{ finding.severity }} — {{ finding.severity_rationale }}</p>
<p>{{ finding.observed_behavior }}</p><p>Remediation: {{ finding.remediation_guidance }}</p>
<p>Minimal retest: {{ finding.reproduction_guidance }}</p>
{% else %}<p>No evidence-backed findings were recorded.</p>{% endfor %}</section>
{% if variant == 'technical_detail' %}<section><h2>Sanitized evidence</h2>
{% for item in report.evidence %}<pre>{{ item|tojson(indent=2) }}</pre>{% endfor %}</section>{% endif %}
<section><h2>Limitations</h2><p>{{ report.limitations }}</p>
<p>Snapshot digest: <code>{{ snapshot_digest }}</code></p></section></body></html>"""

ENV = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html", "xml"]))


def render_report(
    snapshot: dict[str, object],
    *,
    format: ReportFormat,
    variant: ReportVariant,
    snapshot_digest: str,
    review_status: str = "draft",
) -> bytes:
    if format == ReportFormat.JSON:
        return canonical_json(
            {
                "review_status": review_status,
                "variant": variant.value,
                "snapshot_digest": snapshot_digest,
                **snapshot,
            }
        ).encode()
    html = (
        ENV.from_string(TEMPLATE)
        .render(
            report=snapshot,
            variant=variant.value,
            snapshot_digest=snapshot_digest,
            review_status=review_status,
        )
        .encode()
    )
    if format == ReportFormat.HTML:
        return html
    return bytes(HTML(string=html.decode()).write_pdf())
