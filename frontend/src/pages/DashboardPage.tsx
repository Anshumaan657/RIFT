import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";

import { api, getSavedApplicationId } from "../api/client";
import { InlineError } from "../components/InlineError";
import { StateBadge } from "../components/StateBadge";

export function DashboardPage() {
  const applicationId = getSavedApplicationId();
  const workspace = useQuery({
    queryKey: ["workspace", applicationId],
    queryFn: ({ signal }) => api.workspace(applicationId!, signal),
    enabled: Boolean(applicationId),
  });
  const history = useQuery({
    queryKey: ["assessments", applicationId],
    queryFn: ({ signal }) => api.assessments(applicationId!, signal),
    enabled: Boolean(applicationId),
  });

  if (!applicationId) {
    return (
      <section className="empty-workbench">
        <p className="section-label">Assessment register</p>
        <h1>No staging application is open.</h1>
        <p>
          Start assisted onboarding to record authorization, target scope, and
          synthetic fixtures.
        </p>
        <Link className="primary-button" to="/setup">
          Start onboarding
        </Link>
      </section>
    );
  }

  return (
    <div className="page-stack">
      <header className="page-heading">
        <div>
          <p className="section-label">Assessment register</p>
          <h1>{workspace.data?.display_name ?? "Loading application…"}</h1>
        </div>
        <Link className="primary-button" to="/setup">
          New assessment
        </Link>
      </header>
      <InlineError
        message={
          workspace.error instanceof Error ? workspace.error.message : null
        }
      />
      <section className="readiness-strip" aria-label="Configuration readiness">
        <div>
          <span>Authorization</span>
          <strong>{workspace.data?.authorization_records.length ?? "—"}</strong>
        </div>
        <div>
          <span>Verified targets</span>
          <strong>
            {workspace.data?.targets.filter(
              (item) => item.verification_state === "verified",
            ).length ?? "—"}
          </strong>
        </div>
        <div>
          <span>Test identities</span>
          <strong>{workspace.data?.test_identities.length ?? "—"}</strong>
        </div>
        <div>
          <span>Resources</span>
          <strong>{workspace.data?.resource_expectations.length ?? "—"}</strong>
        </div>
      </section>
      <section aria-labelledby="history-title">
        <div className="section-heading">
          <h2 id="history-title">Assessment history</h2>
          <p>
            Every terminal state stays visible; partial work is never shown as
            clean.
          </p>
        </div>
        {history.isPending && (
          <p className="loading-line">Loading assessment history…</p>
        )}
        <InlineError
          message={
            history.error instanceof Error ? history.error.message : null
          }
        />
        {history.data?.length === 0 && (
          <div className="ruled-empty">
            No assessments have run for this application.
          </div>
        )}
        {history.data && history.data.length > 0 && (
          <div className="data-list">
            {history.data.map((item) => (
              <Link
                className="assessment-row"
                to={"/assessments/" + item.id}
                key={item.id}
              >
                <span className="row-id">{item.id.slice(0, 8)}</span>
                <span>
                  {new Intl.DateTimeFormat(undefined, {
                    dateStyle: "medium",
                    timeStyle: "short",
                  }).format(new Date(item.created_at))}
                </span>
                <span>{item.selected_checks.length} checks</span>
                <StateBadge state={item.state} />
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}
