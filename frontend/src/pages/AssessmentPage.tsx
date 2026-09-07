import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";

import { api, type AssessmentState, type ReportArtifact } from "../api/client";
import { InlineError } from "../components/InlineError";
import { StateBadge } from "../components/StateBadge";

const TERMINAL: AssessmentState[] = [
  "completed",
  "completed_with_errors",
  "failed",
  "cancelled",
];

function formatDate(value: string | null) {
  return value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "medium",
      }).format(new Date(value))
    : "—";
}

export function AssessmentPage() {
  const { assessmentId = "" } = useParams();
  const client = useQueryClient();
  const [reportFormat, setReportFormat] =
    useState<ReportArtifact["format"]>("html");
  const [reportVariant, setReportVariant] =
    useState<ReportArtifact["variant"]>("technical_detail");

  const assessment = useQuery({
    queryKey: ["assessment", assessmentId],
    queryFn: ({ signal }) => api.assessment(assessmentId, signal),
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state && TERMINAL.includes(state) ? false : 2000;
    },
  });
  const isTerminal = assessment.data
    ? TERMINAL.includes(assessment.data.state)
    : false;
  const findings = useQuery({
    queryKey: ["findings", assessmentId],
    queryFn: ({ signal }) => api.findings(assessmentId, signal),
    enabled: isTerminal,
  });
  const evidence = useQuery({
    queryKey: ["evidence", assessmentId],
    queryFn: ({ signal }) => api.evidence(assessmentId, signal),
    enabled: isTerminal,
  });
  const reports = useQuery({
    queryKey: ["reports", assessmentId],
    queryFn: ({ signal }) => api.reports(assessmentId, signal),
    enabled: isTerminal,
  });

  const cancel = useMutation({
    mutationFn: () => api.cancelAssessment(assessmentId),
    onSuccess: async () =>
      client.invalidateQueries({ queryKey: ["assessment", assessmentId] }),
  });
  const reviewFinding = useMutation({
    mutationFn: (id: string) => api.reviewFinding(id),
    onSuccess: async () =>
      client.invalidateQueries({ queryKey: ["findings", assessmentId] }),
  });
  const generateReport = useMutation({
    mutationFn: () =>
      api.createReport(assessmentId, reportFormat, reportVariant),
    onSuccess: async () =>
      client.invalidateQueries({ queryKey: ["reports", assessmentId] }),
  });
  const reviewReport = useMutation({
    mutationFn: (id: string) => api.reviewReport(id),
    onSuccess: async () =>
      client.invalidateQueries({ queryKey: ["reports", assessmentId] }),
  });

  const error = [
    assessment.error,
    findings.error,
    evidence.error,
    reports.error,
    cancel.error,
    reviewFinding.error,
    generateReport.error,
    reviewReport.error,
  ].find((item): item is Error => item instanceof Error);
  const canCancel =
    assessment.data &&
    ["draft", "queued", "running"].includes(assessment.data.state);
  const allFindingsReviewed = Boolean(
    findings.data?.every((item) => item.operator_reviewed_at),
  );

  if (assessment.isPending)
    return <p className="loading-line">Loading assessment…</p>;

  return (
    <div className="page-stack assessment-detail">
      <header className="page-heading">
        <div>
          <Link className="back-link" to="/">
            Assessment register
          </Link>
          <p className="section-label">Run / {assessmentId.slice(0, 8)}</p>
          <h1>Assessment evidence</h1>
        </div>
        {assessment.data && <StateBadge state={assessment.data.state} />}
      </header>
      <InlineError message={error?.message ?? null} />

      {assessment.data && (
        <>
          <section
            className="run-strip"
            aria-label="Assessment timing and scope"
          >
            <div>
              <span>Started</span>
              <strong>{formatDate(assessment.data.started_at)}</strong>
            </div>
            <div>
              <span>Completed</span>
              <strong>{formatDate(assessment.data.completed_at)}</strong>
            </div>
            <div>
              <span>Request budget</span>
              <strong>{assessment.data.request_budget}</strong>
            </div>
            <div>
              <span>Selected checks</span>
              <strong>{assessment.data.selected_checks.length}</strong>
            </div>
          </section>

          {!isTerminal && (
            <section className="progress-panel" aria-live="polite">
              <div className="progress-rule">
                <span />
              </div>
              <div>
                <h2>
                  {assessment.data.state === "queued"
                    ? "Waiting for a worker"
                    : assessment.data.state === "cancelling"
                      ? "Stopping safely"
                      : "Checks are running"}
                </h2>
                <p>
                  RIFT checks cancellation before each request and preserves
                  every completed outcome.
                </p>
              </div>
              {canCancel && (
                <button
                  className="danger-button"
                  type="button"
                  disabled={cancel.isPending}
                  onClick={() => cancel.mutate()}
                >
                  {cancel.isPending ? "Cancelling…" : "Cancel assessment"}
                </button>
              )}
            </section>
          )}

          <section aria-labelledby="outcomes-title">
            <div className="section-heading">
              <h2 id="outcomes-title">Per-check outcomes</h2>
              <p>HTTP status alone never establishes unauthorized access.</p>
            </div>
            {assessment.data.checks.length === 0 ? (
              <div className="ruled-empty">
                {isTerminal
                  ? "No check results were recorded. This is not a clean result."
                  : "Outcomes will appear as checks finish."}
              </div>
            ) : (
              <div className="outcome-list">
                {assessment.data.checks.map((check) => (
                  <article key={check.check_identifier}>
                    <div>
                      <code>{check.check_identifier}</code>
                      <span>v{check.check_version}</span>
                    </div>
                    <strong className={"outcome outcome-" + check.outcome}>
                      {check.outcome}
                    </strong>
                    <p>{check.summary}</p>
                    <small>{check.reason_code}</small>
                  </article>
                ))}
              </div>
            )}
          </section>

          {isTerminal && (
            <>
              <section aria-labelledby="findings-title">
                <div className="section-heading">
                  <h2 id="findings-title">Findings review</h2>
                  <p>
                    Review every evidence-backed claim before approving a
                    report.
                  </p>
                </div>
                {findings.isPending && (
                  <p className="loading-line">Loading findings…</p>
                )}
                {findings.data?.length === 0 && (
                  <div className="ruled-empty">
                    No evidence-backed findings were produced.
                  </div>
                )}
                <div className="finding-list">
                  {findings.data?.map((finding) => (
                    <article className="finding" key={finding.id}>
                      <header>
                        <div>
                          <span
                            className={"severity severity-" + finding.severity}
                          >
                            {finding.severity}
                          </span>
                          <code>{finding.check_identifier}</code>
                        </div>
                        <span className="review-state">
                          {finding.operator_reviewed_at
                            ? "Reviewed"
                            : "Review required"}
                        </span>
                      </header>
                      <h3>{finding.title}</h3>
                      <p>{finding.observed_behavior}</p>
                      <details>
                        <summary>Evidence claim and guidance</summary>
                        <dl>
                          <div>
                            <dt>Expected</dt>
                            <dd>{finding.expected_behavior}</dd>
                          </div>
                          <div>
                            <dt>Impact</dt>
                            <dd>{finding.impact}</dd>
                          </div>
                          <div>
                            <dt>Remediation</dt>
                            <dd>{finding.remediation_guidance}</dd>
                          </div>
                          <div>
                            <dt>Minimal retest</dt>
                            <dd>{finding.reproduction_guidance}</dd>
                          </div>
                        </dl>
                      </details>
                      {!finding.operator_reviewed_at && (
                        <button
                          className="secondary-button"
                          type="button"
                          disabled={reviewFinding.isPending}
                          onClick={() => reviewFinding.mutate(finding.id)}
                        >
                          Mark finding reviewed
                        </button>
                      )}
                    </article>
                  ))}
                </div>
              </section>

              <section aria-labelledby="evidence-title">
                <div className="section-heading">
                  <h2 id="evidence-title">Sanitized evidence</h2>
                  <p>
                    Authorization, cookies, and tokens are replaced before
                    display.
                  </p>
                </div>
                {evidence.data?.length === 0 && (
                  <div className="ruled-empty">
                    No request evidence is available.
                  </div>
                )}
                <div className="evidence-list">
                  {evidence.data?.map((item) => (
                    <details key={item.id}>
                      <summary>
                        <code>
                          {item.request.method} {item.request.path}
                        </code>
                        <span>{item.response.status_code}</span>
                      </summary>
                      <div className="evidence-body">
                        <p>
                          <strong>Check</strong> {item.check_identifier} v
                          {item.check_version}
                        </p>
                        <p>
                          <strong>Body digest</strong>{" "}
                          <code>{item.body_digest}</code>
                        </p>
                        <pre>
                          {item.response.excerpt || "(empty response body)"}
                        </pre>
                      </div>
                    </details>
                  ))}
                </div>
              </section>

              <section
                className="report-workbench"
                aria-labelledby="reports-title"
              >
                <div className="section-heading">
                  <h2 id="reports-title">Report review and export</h2>
                  <p>
                    Generated exports remain DRAFT until all findings and the
                    report are reviewed.
                  </p>
                </div>
                <div className="report-controls">
                  <label>
                    Format
                    <select
                      value={reportFormat}
                      onChange={(event) =>
                        setReportFormat(
                          event.target.value as ReportArtifact["format"],
                        )
                      }
                    >
                      <option value="html">HTML</option>
                      <option value="json">JSON</option>
                      <option value="pdf">PDF</option>
                    </select>
                  </label>
                  <label>
                    Audience
                    <select
                      value={reportVariant}
                      onChange={(event) =>
                        setReportVariant(
                          event.target.value as ReportArtifact["variant"],
                        )
                      }
                    >
                      <option value="technical_detail">Technical detail</option>
                      <option value="founder_summary">Founder summary</option>
                    </select>
                  </label>
                  <button
                    className="primary-button"
                    type="button"
                    disabled={!allFindingsReviewed || generateReport.isPending}
                    title={
                      !allFindingsReviewed
                        ? "Review every finding first"
                        : undefined
                    }
                    onClick={() => generateReport.mutate()}
                  >
                    {generateReport.isPending
                      ? "Generating…"
                      : "Generate draft"}
                  </button>
                </div>
                <div className="report-list">
                  {reports.data?.map((report) => (
                    <article key={report.id}>
                      <div>
                        <strong>{report.variant.replace("_", " ")}</strong>
                        <span>
                          {report.format.toUpperCase()} ·{" "}
                          {report.review_status.toUpperCase()}
                        </span>
                      </div>
                      <code>{report.file_digest.slice(0, 16)}…</code>
                      {report.review_status === "draft" ? (
                        <button
                          className="secondary-button"
                          type="button"
                          disabled={
                            !allFindingsReviewed || reviewReport.isPending
                          }
                          title={
                            !allFindingsReviewed
                              ? "Review every finding first"
                              : undefined
                          }
                          onClick={() => reviewReport.mutate(report.id)}
                        >
                          Approve report
                        </button>
                      ) : (
                        <a
                          className="primary-button"
                          href={"/api/v1/reports/" + report.id + "/download"}
                        >
                          Download reviewed
                        </a>
                      )}
                    </article>
                  ))}
                </div>
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}
