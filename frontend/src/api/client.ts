export type AssessmentState =
  | "draft"
  | "queued"
  | "running"
  | "cancelling"
  | "completed"
  | "completed_with_errors"
  | "failed"
  | "cancelled";

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly code: string,
    public readonly details?: unknown,
  ) {
    super(message);
  }
}

export interface HealthResponse {
  status: "ok";
  version: string;
}

export interface Workspace {
  id: string;
  organization_id: string;
  display_name: string;
  environment_type: "staging" | "production";
  lifecycle_status: string;
  authorization_records: Array<{
    id: string;
    approver_identity: string;
    valid_from: string;
    valid_until: string;
    operator_review: boolean;
    status: string;
    approved_scope: { targets?: Array<Record<string, unknown>> };
  }>;
  targets: Array<{
    id: string;
    scheme: string;
    hostname: string;
    port: number;
    base_path_prefix: string;
    verification_state: string;
    enabled_state: string;
  }>;
  test_identities: Array<{
    id: string;
    label: string;
    token_expiry: string | null;
    credential_state: "stored";
  }>;
  resource_expectations: Array<{
    id: string;
    endpoint_template: string;
    synthetic_resource_id: string;
    owner_identity: string | null;
    is_public: boolean;
    expected_access: string;
    content_marker: string;
  }>;
}

export interface Assessment {
  id: string;
  application_id: string;
  target_id: string;
  state: AssessmentState;
  selected_checks: string[];
  request_budget: number;
  started_at: string | null;
  completed_at: string | null;
  terminal_reason: string | null;
  checks: Array<{
    check_identifier: string;
    check_version: string;
    outcome: string;
    reason_code: string;
    summary: string;
  }>;
}

export interface AssessmentSummary {
  id: string;
  target_id: string;
  state: AssessmentState;
  selected_checks: string[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  terminal_reason: string | null;
}

export interface Finding {
  id: string;
  assessment_id: string;
  check_identifier: string;
  check_version: string;
  title: string;
  validation_state: string;
  severity: string;
  severity_rationale: string;
  expected_behavior: string;
  observed_behavior: string;
  impact: string;
  reproduction_guidance: string;
  remediation_guidance: string;
  evidence_refs: string[];
  operator_reviewed_by: string | null;
  operator_reviewed_at: string | null;
}

export interface Evidence {
  id: string;
  check_identifier: string;
  check_version: string;
  request: { method: string; path: string; headers: Record<string, string> };
  response: {
    status_code: number;
    headers: Record<string, string>;
    excerpt: string;
  };
  body_digest: string;
  capture_time: string;
  redaction_version: number;
  schema_version: number;
}

export interface ReportArtifact {
  id: string;
  format: "html" | "json" | "pdf";
  variant: "founder_summary" | "technical_detail";
  review_status: "draft" | "reviewed";
  file_digest: string;
  snapshot_digest?: string;
  created_at?: string;
}

const CSRF_KEY = "rift.csrf";
const APP_KEY = "rift.application";

export const getCsrfToken = () => sessionStorage.getItem(CSRF_KEY);
export const setCsrfToken = (token: string) =>
  sessionStorage.setItem(CSRF_KEY, token);
export const getSavedApplicationId = () => sessionStorage.getItem(APP_KEY);
export const saveApplicationId = (id: string) =>
  sessionStorage.setItem(APP_KEY, id);
export function clearSession() {
  sessionStorage.removeItem(CSRF_KEY);
  sessionStorage.removeItem(APP_KEY);
}

async function request<T>(
  path: string,
  init: RequestInit = {},
  mutation = false,
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (mutation) {
    const token = getCsrfToken();
    if (token) headers.set("X-CSRF-Token", token);
  }
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });
  if (!response.ok) {
    let body: ApiErrorBody = {
      code: "HTTP_" + response.status,
      message: "Request failed with status " + response.status,
    };
    try {
      const parsed = (await response.json()) as Partial<ApiErrorBody> & {
        detail?: string;
      };
      body = {
        code: parsed.code ?? "HTTP_" + response.status,
        message: parsed.message ?? parsed.detail ?? body.message,
        details: parsed.details,
      };
    } catch {
      // Keep the safe status-only fallback for non-JSON failures.
    }
    if (response.status === 401) clearSession();
    throw new ApiError(body.message, response.status, body.code, body.details);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

const mutate = <T>(path: string, method: string, payload?: unknown) =>
  request<T>(
    path,
    {
      method,
      body: payload === undefined ? undefined : JSON.stringify(payload),
    },
    true,
  );

export const api = {
  health: (signal?: AbortSignal) =>
    request<HealthResponse>("/api/v1/health/live", { signal }),
  login: (username: string, password: string) =>
    request<{ csrf_token: string }>("/api/v1/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => mutate<void>("/api/v1/logout", "POST"),
  createOrganization: (name: string) =>
    mutate<{ id: string }>("/api/v1/organizations", "POST", { name }),
  createApplication: (organizationId: string, displayName: string) =>
    mutate<{ id: string }>("/api/v1/applications", "POST", {
      organization_id: organizationId,
      display_name: displayName,
      environment_type: "staging",
    }),
  workspace: (id: string, signal?: AbortSignal) =>
    request<Workspace>("/api/v1/applications/" + id, { signal }),
  assessments: (id: string, signal?: AbortSignal) =>
    request<AssessmentSummary[]>(
      "/api/v1/applications/" + id + "/assessments",
      { signal },
    ),
  createAuthorization: (payload: Record<string, unknown>) =>
    mutate<{ id: string }>("/api/v1/authorization-records", "POST", payload),
  createTarget: (payload: Record<string, unknown>) =>
    mutate<{ id: string; challenge_token: string; challenge_path: string }>(
      "/api/v1/targets",
      "POST",
      payload,
    ),
  verifyTarget: (id: string) =>
    mutate<{ id: string; verification_state: string }>(
      "/api/v1/targets/" + id + "/verify",
      "POST",
    ),
  createIdentity: (payload: Record<string, unknown>) =>
    mutate<{ id: string; label: string }>(
      "/api/v1/test-identities",
      "POST",
      payload,
    ),
  replaceIdentity: (id: string, payload: Record<string, unknown>) =>
    mutate<{ id: string; label: string }>(
      "/api/v1/test-identities/" + id,
      "PUT",
      payload,
    ),
  deleteIdentity: (id: string) =>
    mutate<void>("/api/v1/test-identities/" + id, "DELETE"),
  createResource: (payload: Record<string, unknown>) =>
    mutate<{ id: string }>("/api/v1/resource-expectations", "POST", payload),
  createAssessment: (payload: Record<string, unknown>) =>
    mutate<{ id: string; state: AssessmentState }>(
      "/api/v1/assessments",
      "POST",
      payload,
    ),
  assessment: (id: string, signal?: AbortSignal) =>
    request<Assessment>("/api/v1/assessments/" + id, { signal }),
  cancelAssessment: (id: string) =>
    mutate<{ id: string; state: AssessmentState }>(
      "/api/v1/assessments/" + id + "/cancel",
      "POST",
    ),
  findings: (id: string, signal?: AbortSignal) =>
    request<Finding[]>("/api/v1/assessments/" + id + "/findings", { signal }),
  reviewFinding: (id: string) =>
    mutate<Finding>("/api/v1/findings/" + id + "/review", "POST"),
  evidence: (id: string, signal?: AbortSignal) =>
    request<Evidence[]>("/api/v1/assessments/" + id + "/evidence", { signal }),
  reports: (id: string, signal?: AbortSignal) =>
    request<ReportArtifact[]>("/api/v1/assessments/" + id + "/reports", {
      signal,
    }),
  createReport: (
    assessmentId: string,
    format: ReportArtifact["format"],
    variant: ReportArtifact["variant"],
  ) =>
    mutate<ReportArtifact>(
      "/api/v1/assessments/" + assessmentId + "/reports",
      "POST",
      {
        format,
        variant,
        idempotency_key: crypto.randomUUID(),
      },
    ),
  reviewReport: (id: string) =>
    mutate<{ id: string; review_status: "reviewed" }>(
      "/api/v1/reports/" + id + "/review",
      "POST",
    ),
};

export const fetchHealth = (signal?: AbortSignal) => api.health(signal);
