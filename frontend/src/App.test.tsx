import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

const authorization = {
  id: "authorization-1",
  approver_identity: "security-owner@example.test",
  valid_from: "2026-09-01T00:00:00Z",
  valid_until: "2026-09-30T00:00:00Z",
  operator_review: true,
  status: "active",
  approved_scope: { targets: [] },
};

function workspace(overrides: Record<string, unknown> = {}) {
  return {
    id: "application-1",
    organization_id: "organization-1",
    display_name: "Synthetic staging API",
    environment_type: "staging",
    lifecycle_status: "active",
    authorization_records: [],
    targets: [],
    test_identities: [],
    resource_expectations: [],
    ...overrides,
  };
}

function response(body: unknown, status = 200) {
  return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function renderApp(
  path: string,
  fetcher: (path: string, init?: RequestInit) => Response | Promise<Response>,
) {
  sessionStorage.setItem("rift.csrf", "csrf-test");
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      return Promise.resolve(fetcher(path, init));
    }),
  );
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  sessionStorage.clear();
});

describe("Phase 7 operator workflow", () => {
  it("requires an authenticated operator session", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <MemoryRouter initialEntries={["/"]}>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(
      screen.getByRole("heading", { name: "Sign in" }),
    ).toBeInTheDocument();
  });

  it.each([
    "authorization window has expired",
    "target is outside the approved scope",
  ])("shows a safe setup error: %s", async (detail) => {
    sessionStorage.setItem("rift.application", "application-1");
    renderApp("/setup", (path, init) => {
      if (path.endsWith("/health/live"))
        return response({ status: "ok", version: "0.1.0" });
      if (path.endsWith("/applications/application-1"))
        return response(workspace());
      if (path.endsWith("/authorization-records") && init?.method === "POST") {
        return response({ detail }, 409);
      }
      throw new Error("Unexpected request: " + path);
    });

    await screen.findByText(/Synthetic staging API/);
    fireEvent.change(screen.getByLabelText("Approver identity"), {
      target: { value: "owner" },
    });
    fireEvent.change(screen.getByLabelText("Authorization statement"), {
      target: { value: "Approved staging validation" },
    });
    fireEvent.click(screen.getByText(/I reviewed the written authorization/));
    fireEvent.click(
      screen.getByRole("button", { name: "Record authorization" }),
    );
    expect(await screen.findByText(detail)).toBeInTheDocument();
  });

  it("surfaces failed target verification without changing readiness", async () => {
    sessionStorage.setItem("rift.application", "application-1");
    renderApp("/setup", (path, init) => {
      if (path.endsWith("/health/live"))
        return response({ status: "ok", version: "0.1.0" });
      if (path.endsWith("/applications/application-1")) {
        return response(
          workspace({
            authorization_records: [authorization],
            targets: [
              {
                id: "target-1",
                scheme: "https",
                hostname: "staging.example.test",
                port: 443,
                base_path_prefix: "/api/",
                verification_state: "pending",
                enabled_state: "disabled",
              },
            ],
          }),
        );
      }
      if (
        path.endsWith("/targets/target-1/verify") &&
        init?.method === "POST"
      ) {
        return response({ detail: "target challenge did not match" }, 409);
      }
      throw new Error("Unexpected request: " + path);
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Retry verification" }),
    );
    expect(
      await screen.findByText("target challenge did not match"),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText("Required", { selector: ".section-state" }).length,
    ).toBeGreaterThan(0);
  });

  it("shows cancelled and empty results as explicit states", async () => {
    renderApp("/assessments/assessment-empty", (path) => {
      if (path.endsWith("/health/live"))
        return response({ status: "ok", version: "0.1.0" });
      if (path.endsWith("/assessments/assessment-empty")) {
        return response({
          id: "assessment-empty",
          application_id: "application-1",
          target_id: "target-1",
          state: "cancelled",
          selected_checks: ["RIFT-AUTHN-001"],
          request_budget: 100,
          started_at: "2026-09-07T10:00:00Z",
          completed_at: "2026-09-07T10:01:00Z",
          terminal_reason: "operator_cancelled",
          checks: [],
        });
      }
      if (
        path.endsWith("/findings") ||
        path.endsWith("/evidence") ||
        path.endsWith("/reports")
      ) {
        return response([]);
      }
      throw new Error("Unexpected request: " + path);
    });

    expect(
      await screen.findByText("Cancelled", { selector: ".state-badge" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "No check results were recorded. This is not a clean result.",
      ),
    ).toBeInTheDocument();
    expect(
      await screen.findByText("No evidence-backed findings were produced."),
    ).toBeInTheDocument();
  });

  it("keeps partial outcomes visible and reports export failure", async () => {
    renderApp("/assessments/assessment-partial", (path, init) => {
      if (path.endsWith("/health/live"))
        return response({ status: "ok", version: "0.1.0" });
      if (
        path.endsWith("/assessments/assessment-partial") &&
        !path.endsWith("/reports")
      ) {
        return response({
          id: "assessment-partial",
          application_id: "application-1",
          target_id: "target-1",
          state: "completed_with_errors",
          selected_checks: ["RIFT-AUTHN-001", "RIFT-AUTHZ-001"],
          request_budget: 100,
          started_at: "2026-09-07T10:00:00Z",
          completed_at: "2026-09-07T10:02:00Z",
          terminal_reason: "check_errors",
          checks: [
            {
              check_identifier: "RIFT-AUTHN-001",
              check_version: "1.0",
              outcome: "not_vulnerable",
              reason_code: "AUTH_REQUIRED",
              summary: "Authentication was enforced.",
            },
            {
              check_identifier: "RIFT-AUTHZ-001",
              check_version: "1.0",
              outcome: "error",
              reason_code: "CONTROLLED_TIMEOUT",
              summary: "The check did not finish.",
            },
          ],
        });
      }
      if (path.endsWith("/findings") || path.endsWith("/evidence"))
        return response([]);
      if (path.endsWith("/reports") && init?.method === "POST") {
        return response({ detail: "report renderer unavailable" }, 503);
      }
      if (path.endsWith("/reports")) return response([]);
      throw new Error("Unexpected request: " + path);
    });

    expect(
      await screen.findByText("Completed with errors", {
        selector: ".state-badge",
      }),
    ).toBeInTheDocument();
    expect(screen.getByText("The check did not finish.")).toBeInTheDocument();
    fireEvent.click(
      await screen.findByRole("button", { name: "Generate draft" }),
    );
    await waitFor(() =>
      expect(
        screen.getByText("report renderer unavailable"),
      ).toBeInTheDocument(),
    );
  });
});
