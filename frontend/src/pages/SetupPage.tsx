import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import {
  ApiError,
  api,
  getSavedApplicationId,
  saveApplicationId,
  type Workspace,
} from "../api/client";
import { InlineError } from "../components/InlineError";

const CHECKS = [
  ["RIFT-AUTHN-001", "Missing authentication"],
  ["RIFT-AUTHZ-001", "Cross-user access"],
  ["RIFT-CONFIG-001", "Transport and headers"],
] as const;

function formText(data: FormData, name: string) {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

function localDateTime(hoursFromNow: number) {
  const date = new Date(Date.now() + hoursFromNow * 60 * 60 * 1000);
  date.setMinutes(date.getMinutes() - date.getTimezoneOffset());
  return date.toISOString().slice(0, 16);
}

function SectionState({ done }: { done: boolean }) {
  return (
    <span className={"section-state " + (done ? "is-done" : "")}>
      {done ? "Recorded" : "Required"}
    </span>
  );
}

function IdentityRow({
  identity,
  refresh,
}: {
  identity: Workspace["test_identities"][number];
  refresh: () => Promise<void>;
}) {
  const [replacement, setReplacement] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function replace() {
    if (!replacement) return;
    setBusy(true);
    setError(null);
    try {
      await api.replaceIdentity(identity.id, { bearer_token: replacement });
      setReplacement("");
      await refresh();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Credential replacement failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    setError(null);
    try {
      await api.deleteIdentity(identity.id);
      await refresh();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Identity deletion failed.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="identity-row">
      <div>
        <strong>{identity.label}</strong>
        <span>Credential stored · value hidden</span>
      </div>
      <label className="compact-field">
        <span>Replacement token</span>
        <input
          aria-label={"Replacement token for " + identity.label}
          type="password"
          value={replacement}
          onChange={(event) => setReplacement(event.target.value)}
          autoComplete="off"
        />
      </label>
      <button
        className="secondary-button"
        type="button"
        disabled={busy || !replacement}
        onClick={() => void replace()}
      >
        Replace
      </button>
      <button
        className="danger-button"
        type="button"
        disabled={busy}
        onClick={() => void remove()}
      >
        Delete
      </button>
      <InlineError message={error} />
    </div>
  );
}

export function SetupPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [applicationId, setApplicationId] = useState(getSavedApplicationId());
  const [authorizationId, setAuthorizationId] = useState<string | null>(null);
  const [targetId, setTargetId] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<{
    token: string;
    path: string;
  } | null>(null);
  const [scope, setScope] = useState({
    scheme: "http",
    hostname: "127.0.0.1",
    port: 18081,
    base_path: "/api/",
  });
  const [resourceReady, setResourceReady] = useState(false);
  const [selectedChecks, setSelectedChecks] = useState<string[]>(
    CHECKS.map(([id]) => id),
  );
  const [reviewed, setReviewed] = useState(false);
  const [busyStep, setBusyStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const workspace = useQuery({
    queryKey: ["workspace", applicationId],
    queryFn: ({ signal }) => api.workspace(applicationId!, signal),
    enabled: Boolean(applicationId),
  });

  const activeAuthorizationId =
    authorizationId ?? workspace.data?.authorization_records[0]?.id ?? null;
  const activeTarget =
    workspace.data?.targets.find((item) => item.id === targetId) ??
    workspace.data?.targets[0];
  const activeTargetId = targetId ?? activeTarget?.id ?? null;
  const authorizationDone = Boolean(activeAuthorizationId);
  const targetDone = activeTarget?.verification_state === "verified";
  const identitiesDone = (workspace.data?.test_identities.length ?? 0) >= 2;
  const resourcesDone =
    resourceReady || (workspace.data?.resource_expectations.length ?? 0) > 0;
  const ready = Boolean(
    applicationId &&
    authorizationDone &&
    targetDone &&
    identitiesDone &&
    resourcesDone,
  );
  const ownerOptions = workspace.data?.test_identities ?? [];

  const reviewRows = useMemo(
    () => [
      ["Environment", "Staging"],
      [
        "Target",
        activeTarget
          ? activeTarget.scheme +
            "://" +
            activeTarget.hostname +
            ":" +
            activeTarget.port +
            activeTarget.base_path_prefix
          : "Not verified",
      ],
      [
        "Authorization",
        authorizationDone ? "Operator-reviewed record selected" : "Missing",
      ],
      [
        "Synthetic identities",
        String(workspace.data?.test_identities.length ?? 0),
      ],
      [
        "Declared resources",
        String(workspace.data?.resource_expectations.length ?? 0),
      ],
      ["Checks", selectedChecks.join(", ")],
    ],
    [activeTarget, authorizationDone, selectedChecks, workspace.data],
  );

  async function runAction(name: string, action: () => Promise<void>) {
    setBusyStep(name);
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError(
        reason instanceof ApiError
          ? reason.message
          : reason instanceof Error
            ? reason.message
            : "Action failed.",
      );
    } finally {
      setBusyStep(null);
    }
  }

  async function refresh() {
    await queryClient.invalidateQueries({
      queryKey: ["workspace", applicationId],
    });
  }

  async function createApplication(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    await runAction("application", async () => {
      const organization = await api.createOrganization(
        formText(data, "organization"),
      );
      const application = await api.createApplication(
        organization.id,
        formText(data, "application"),
      );
      saveApplicationId(application.id);
      setApplicationId(application.id);
    });
  }

  async function createAuthorization(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!applicationId) return;
    const data = new FormData(event.currentTarget);
    await runAction("authorization", async () => {
      const record = await api.createAuthorization({
        application_id: applicationId,
        approver_identity: formText(data, "approver"),
        authorization_statement: formText(data, "statement"),
        valid_from: new Date(formText(data, "valid_from")).toISOString(),
        valid_until: new Date(formText(data, "valid_until")).toISOString(),
        approved_scope: {
          targets: [
            {
              scheme: scope.scheme,
              hostname: scope.hostname,
              port: scope.port,
              base_path: scope.base_path,
            },
          ],
        },
        prohibited_actions: ["state-changing requests", "production testing"],
        operator_review: true,
      });
      setAuthorizationId(record.id);
      await refresh();
    });
  }

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!applicationId) return;
    await runAction("target", async () => {
      const target = await api.createTarget({
        application_id: applicationId,
        scheme: scope.scheme,
        hostname: scope.hostname,
        port: scope.port,
        base_path_prefix: scope.base_path,
      });
      setTargetId(target.id);
      setChallenge({
        token: target.challenge_token,
        path: target.challenge_path,
      });
      await refresh();
    });
  }

  async function verifyTarget() {
    if (!activeTargetId) return;
    await runAction("verification", async () => {
      await api.verifyTarget(activeTargetId);
      setChallenge(null);
      await refresh();
    });
  }

  async function createIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!applicationId) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    await runAction("identity", async () => {
      await api.createIdentity({
        application_id: applicationId,
        label: formText(data, "label"),
        bearer_token: formText(data, "token"),
        token_expiry: data.get("expiry")
          ? new Date(formText(data, "expiry")).toISOString()
          : null,
      });
      form.reset();
      await refresh();
    });
  }

  async function createResource(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!applicationId) return;
    const data = new FormData(event.currentTarget);
    await runAction("resource", async () => {
      await api.createResource({
        application_id: applicationId,
        endpoint_template: formText(data, "path"),
        synthetic_resource_id: formText(data, "resource_id"),
        owner_identity: formText(data, "owner"),
        is_public: false,
        expected_access: "deny",
        content_marker: formText(data, "marker"),
      });
      setResourceReady(true);
      await refresh();
    });
  }

  async function createAssessment() {
    if (
      !applicationId ||
      !activeTargetId ||
      !activeAuthorizationId ||
      !reviewed
    )
      return;
    await runAction("assessment", async () => {
      const assessment = await api.createAssessment({
        application_id: applicationId,
        target_id: activeTargetId,
        authorization_record_id: activeAuthorizationId,
        selected_checks: selectedChecks,
        request_budget: 100,
        idempotency_key: crypto.randomUUID(),
      });
      void navigate("/assessments/" + assessment.id);
    });
  }

  return (
    <div className="page-stack setup-page">
      <header className="page-heading">
        <div>
          <p className="section-label">Assisted onboarding</p>
          <h1>Define the boundary before the run.</h1>
        </div>
        <p className="heading-note">
          Staging and synthetic data only. Every network request remains inside
          the reviewed target scope.
        </p>
      </header>
      <InlineError message={error} />

      <section className="setup-section" aria-labelledby="step-1">
        <div className="step-number">01</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-1">Application</h2>
              <p>Create the partner and staging application record.</p>
            </div>
            <SectionState done={Boolean(applicationId)} />
          </header>
          {!applicationId ? (
            <form
              className="form-grid"
              onSubmit={(event) => void createApplication(event)}
            >
              <label>
                Organization name
                <input
                  name="organization"
                  required
                  placeholder="Partner organization"
                />
              </label>
              <label>
                Application name
                <input name="application" required placeholder="Staging API" />
              </label>
              <button
                className="primary-button"
                disabled={busyStep === "application"}
                type="submit"
              >
                Save application
              </button>
            </form>
          ) : (
            <p className="recorded-line">
              {workspace.data?.display_name ?? "Application recorded"} · staging
            </p>
          )}
        </div>
      </section>

      <section className="setup-section" aria-labelledby="step-2">
        <div className="step-number">02</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-2">Authorization and exact scope</h2>
              <p>Record the approved window and one exact target.</p>
            </div>
            <SectionState done={authorizationDone} />
          </header>
          <form
            className="form-grid"
            onSubmit={(event) => void createAuthorization(event)}
          >
            <label>
              Approver identity
              <input
                name="approver"
                required
                disabled={!applicationId || authorizationDone}
              />
            </label>
            <label className="span-two">
              Authorization statement
              <textarea
                name="statement"
                required
                disabled={!applicationId || authorizationDone}
                placeholder="Explicit authorization to validate this staging target using synthetic data."
              />
            </label>
            <label>
              Valid from
              <input
                name="valid_from"
                type="datetime-local"
                required
                defaultValue={localDateTime(-1)}
                disabled={!applicationId || authorizationDone}
              />
            </label>
            <label>
              Valid until
              <input
                name="valid_until"
                type="datetime-local"
                required
                defaultValue={localDateTime(24)}
                disabled={!applicationId || authorizationDone}
              />
            </label>
            <label>
              Scheme
              <select
                value={scope.scheme}
                disabled={!applicationId || authorizationDone}
                onChange={(event) =>
                  setScope({ ...scope, scheme: event.target.value })
                }
              >
                <option value="https">HTTPS</option>
                <option value="http">HTTP · local lab only</option>
              </select>
            </label>
            <label>
              Exact hostname
              <input
                value={scope.hostname}
                disabled={!applicationId || authorizationDone}
                onChange={(event) =>
                  setScope({ ...scope, hostname: event.target.value })
                }
              />
            </label>
            <label>
              Port
              <input
                type="number"
                min="1"
                max="65535"
                value={scope.port}
                disabled={!applicationId || authorizationDone}
                onChange={(event) =>
                  setScope({ ...scope, port: Number(event.target.value) })
                }
              />
            </label>
            <label>
              Base path
              <input
                value={scope.base_path}
                disabled={!applicationId || authorizationDone}
                onChange={(event) =>
                  setScope({ ...scope, base_path: event.target.value })
                }
              />
            </label>
            <label className="check-line span-two">
              <input
                type="checkbox"
                required
                disabled={!applicationId || authorizationDone}
              />
              I reviewed the written authorization and testing window.
            </label>
            {!authorizationDone && (
              <button
                className="primary-button"
                disabled={!applicationId || busyStep === "authorization"}
                type="submit"
              >
                Record authorization
              </button>
            )}
          </form>
        </div>
      </section>

      <section className="setup-section" aria-labelledby="step-3">
        <div className="step-number">03</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-3">Target verification</h2>
              <p>
                Prove control of the exact host. This does not replace written
                authorization.
              </p>
            </div>
            <SectionState done={targetDone} />
          </header>
          {!activeTargetId && (
            <form onSubmit={(event) => void createTarget(event)}>
              <button
                className="primary-button"
                disabled={!authorizationDone || busyStep === "target"}
                type="submit"
              >
                Create verification challenge
              </button>
            </form>
          )}
          {challenge && (
            <div className="challenge-box">
              <p>
                Publish this one-time challenge at <code>{challenge.path}</code>
              </p>
              <code className="challenge-token">{challenge.token}</code>
              <button
                className="secondary-button"
                disabled={busyStep === "verification"}
                type="button"
                onClick={() => void verifyTarget()}
              >
                Verify target
              </button>
            </div>
          )}
          {targetDone && (
            <p className="recorded-line">Target verified and enabled.</p>
          )}
          {activeTargetId && !targetDone && !challenge && (
            <button
              className="secondary-button"
              type="button"
              onClick={() => void verifyTarget()}
            >
              Retry verification
            </button>
          )}
        </div>
      </section>

      <section className="setup-section" aria-labelledby="step-4">
        <div className="step-number">04</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-4">Synthetic identities</h2>
              <p>
                Add two bearer-token identities. Token values are hidden
                immediately after submission.
              </p>
            </div>
            <SectionState done={identitiesDone} />
          </header>
          <form
            className="form-grid"
            onSubmit={(event) => void createIdentity(event)}
          >
            <label>
              Identity label
              <input
                name="label"
                required
                disabled={!targetDone}
                placeholder="Synthetic User A"
              />
            </label>
            <label>
              Bearer token
              <input
                name="token"
                type="password"
                autoComplete="off"
                required
                disabled={!targetDone}
              />
            </label>
            <label>
              Token expiry · optional
              <input
                name="expiry"
                type="datetime-local"
                disabled={!targetDone}
              />
            </label>
            <button
              className="primary-button"
              disabled={!targetDone || busyStep === "identity"}
              type="submit"
            >
              Store identity
            </button>
          </form>
          <div className="identity-list">
            {ownerOptions.map((identity) => (
              <IdentityRow
                identity={identity}
                refresh={refresh}
                key={identity.id}
              />
            ))}
          </div>
        </div>
      </section>

      <section className="setup-section" aria-labelledby="step-5">
        <div className="step-number">05</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-5">Declared resource</h2>
              <p>
                Use a supplied synthetic ID and unique marker. RIFT will not
                enumerate identifiers.
              </p>
            </div>
            <SectionState done={resourcesDone} />
          </header>
          <form
            className="form-grid"
            onSubmit={(event) => void createResource(event)}
          >
            <label className="span-two">
              Endpoint template
              <input
                name="path"
                required
                disabled={!identitiesDone || resourcesDone}
                defaultValue="/api/records/{resource_id}"
              />
            </label>
            <label>
              Synthetic resource ID
              <input
                name="resource_id"
                required
                disabled={!identitiesDone || resourcesDone}
                defaultValue="synthetic-record-b"
              />
            </label>
            <label>
              Owner identity
              <select
                name="owner"
                required
                disabled={!identitiesDone || resourcesDone}
              >
                <option value="">Select identity</option>
                {ownerOptions.map((item) => (
                  <option key={item.id} value={item.label}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="span-two">
              Unique content marker
              <input
                name="marker"
                required
                disabled={!identitiesDone || resourcesDone}
                placeholder="RIFT_SYNTHETIC_RECORD_B_..."
              />
            </label>
            {!resourcesDone && (
              <button
                className="primary-button"
                disabled={!identitiesDone || busyStep === "resource"}
                type="submit"
              >
                Save resource
              </button>
            )}
          </form>
        </div>
      </section>

      <section className="setup-section final-review" aria-labelledby="step-6">
        <div className="step-number">06</div>
        <div className="step-content">
          <header>
            <div>
              <h2 id="step-6">Final review</h2>
              <p>
                Confirm the immutable assessment snapshot before queueing work.
              </p>
            </div>
            <SectionState done={ready && reviewed} />
          </header>
          <div className="review-table">
            {reviewRows.map(([label, value]) => (
              <div key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>
          <fieldset className="check-fieldset">
            <legend>Approved V1 checks</legend>
            {CHECKS.map(([id, label]) => (
              <label className="check-line" key={id}>
                <input
                  type="checkbox"
                  checked={selectedChecks.includes(id)}
                  onChange={(event) =>
                    setSelectedChecks(
                      event.target.checked
                        ? [...selectedChecks, id]
                        : selectedChecks.filter((item) => item !== id),
                    )
                  }
                />
                {label}
                <code>{id}</code>
              </label>
            ))}
          </fieldset>
          <label className="check-line review-confirm">
            <input
              type="checkbox"
              checked={reviewed}
              onChange={(event) => setReviewed(event.target.checked)}
              disabled={!ready}
            />
            I confirm the target, authorization window, synthetic fixtures, and
            selected checks.
          </label>
          <button
            className="run-button"
            type="button"
            disabled={
              !ready ||
              !reviewed ||
              selectedChecks.length === 0 ||
              busyStep === "assessment"
            }
            onClick={() => void createAssessment()}
          >
            {busyStep === "assessment"
              ? "Queueing assessment…"
              : "Queue controlled assessment"}
          </button>
        </div>
      </section>
    </div>
  );
}
