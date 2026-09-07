import { expect, test, type Route } from "@playwright/test";

const json = (route: Route, body: unknown, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });

test("operator configures a lab run, reviews evidence, and downloads an approved report", async ({
  page,
}) => {
  const state = {
    authorization: false,
    target: false,
    verified: false,
    identities: [] as Array<{ id: string; label: string }>,
    resource: false,
    findingReviewed: false,
    draft: false,
    reviewed: false,
  };

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    if (path.endsWith("/health/live"))
      return json(route, { status: "ok", version: "0.1.0" });
    if (path.endsWith("/login")) return json(route, { csrf_token: "csrf-e2e" });
    if (path.endsWith("/organizations") && method === "POST") {
      return json(route, { id: "organization-1" }, 201);
    }
    if (path.endsWith("/applications") && method === "POST") {
      return json(route, { id: "application-1" }, 201);
    }
    if (path.endsWith("/applications/application-1") && method === "GET") {
      return json(route, {
        id: "application-1",
        organization_id: "organization-1",
        display_name: "RIFT synthetic lab",
        environment_type: "staging",
        lifecycle_status: "active",
        authorization_records: state.authorization
          ? [
              {
                id: "authorization-1",
                approver_identity: "owner",
                valid_from: "2026-09-01T00:00:00Z",
                valid_until: "2026-09-30T00:00:00Z",
                operator_review: true,
                status: "active",
                approved_scope: { targets: [] },
              },
            ]
          : [],
        targets: state.target
          ? [
              {
                id: "target-1",
                scheme: "http",
                hostname: "127.0.0.1",
                port: 18081,
                base_path_prefix: "/api/",
                verification_state: state.verified ? "verified" : "pending",
                enabled_state: state.verified ? "enabled" : "disabled",
              },
            ]
          : [],
        test_identities: state.identities.map((identity) => ({
          ...identity,
          token_expiry: null,
          credential_state: "stored",
        })),
        resource_expectations: state.resource
          ? [
              {
                id: "resource-1",
                endpoint_template: "/api/records/{resource_id}",
                synthetic_resource_id: "synthetic-record-b",
                owner_identity: "Synthetic User B",
                is_public: false,
                expected_access: "deny",
                content_marker: "RIFT_SYNTHETIC_RECORD_B",
              },
            ]
          : [],
      });
    }
    if (path.endsWith("/authorization-records") && method === "POST") {
      state.authorization = true;
      return json(route, { id: "authorization-1" }, 201);
    }
    if (path.endsWith("/targets") && method === "POST") {
      state.target = true;
      return json(
        route,
        {
          id: "target-1",
          challenge_token: "rift-challenge-token",
          challenge_path: "/.well-known/rift-verification",
        },
        201,
      );
    }
    if (path.endsWith("/targets/target-1/verify")) {
      state.verified = true;
      return json(route, { id: "target-1", verification_state: "verified" });
    }
    if (path.endsWith("/test-identities") && method === "POST") {
      const payload = request.postDataJSON() as { label: string };
      const identity = {
        id: "identity-" + (state.identities.length + 1),
        label: payload.label,
      };
      state.identities.push(identity);
      return json(route, identity, 201);
    }
    if (path.endsWith("/resource-expectations") && method === "POST") {
      state.resource = true;
      return json(route, { id: "resource-1" }, 201);
    }
    if (path.endsWith("/assessments") && method === "POST") {
      return json(route, { id: "assessment-1", state: "queued" }, 201);
    }
    if (path.endsWith("/assessments/assessment-1") && method === "GET") {
      return json(route, {
        id: "assessment-1",
        application_id: "application-1",
        target_id: "target-1",
        state: "completed",
        selected_checks: [
          "RIFT-AUTHN-001",
          "RIFT-AUTHZ-001",
          "RIFT-CONFIG-001",
        ],
        request_budget: 100,
        started_at: "2026-09-07T10:00:00Z",
        completed_at: "2026-09-07T10:02:00Z",
        terminal_reason: null,
        checks: [
          {
            check_identifier: "RIFT-AUTHZ-001",
            check_version: "1.0",
            outcome: "finding",
            reason_code: "CROSS_USER_MARKER_EXPOSED",
            summary: "A synthetic cross-user marker was returned.",
          },
        ],
      });
    }
    if (path.endsWith("/assessments/assessment-1/findings")) {
      return json(route, [
        {
          id: "finding-1",
          assessment_id: "assessment-1",
          check_identifier: "RIFT-AUTHZ-001",
          check_version: "1.0",
          title: "Synthetic cross-user resource was readable",
          validation_state: "validated",
          severity: "high",
          severity_rationale: "Cross-user data exposure.",
          expected_behavior: "Access denied.",
          observed_behavior: "The unique marker was returned.",
          impact: "A user could read another user's resource.",
          reproduction_guidance: "Repeat with the declared synthetic IDs.",
          remediation_guidance: "Enforce ownership on the resource lookup.",
          evidence_refs: ["evidence-1"],
          operator_reviewed_by: state.findingReviewed ? "operator" : null,
          operator_reviewed_at: state.findingReviewed
            ? "2026-09-07T10:03:00Z"
            : null,
        },
      ]);
    }
    if (path.endsWith("/findings/finding-1/review")) {
      state.findingReviewed = true;
      return json(route, {
        id: "finding-1",
        operator_reviewed_at: "2026-09-07T10:03:00Z",
      });
    }
    if (path.endsWith("/assessments/assessment-1/evidence")) {
      return json(route, [
        {
          id: "evidence-1",
          check_identifier: "RIFT-AUTHZ-001",
          check_version: "1.0",
          request: {
            method: "GET",
            path: "/api/records/synthetic-record-b",
            headers: { authorization: "[REDACTED]" },
          },
          response: {
            status_code: 200,
            headers: {},
            excerpt: "RIFT_SYNTHETIC_RECORD_B",
          },
          body_digest: "abcdef0123456789",
          capture_time: "2026-09-07T10:01:00Z",
          redaction_version: 1,
          schema_version: 1,
        },
      ]);
    }
    if (
      path.endsWith("/assessments/assessment-1/reports") &&
      method === "POST"
    ) {
      state.draft = true;
      return json(
        route,
        {
          id: "report-draft",
          format: "html",
          variant: "technical_detail",
          review_status: "draft",
          file_digest: "a".repeat(64),
        },
        201,
      );
    }
    if (path.endsWith("/assessments/assessment-1/reports")) {
      const reports = [];
      if (state.draft)
        reports.push({
          id: "report-draft",
          format: "html",
          variant: "technical_detail",
          review_status: "draft",
          file_digest: "a".repeat(64),
        });
      if (state.reviewed)
        reports.unshift({
          id: "report-reviewed",
          format: "html",
          variant: "technical_detail",
          review_status: "reviewed",
          file_digest: "b".repeat(64),
        });
      return json(route, reports);
    }
    if (path.endsWith("/reports/report-draft/review")) {
      state.reviewed = true;
      return json(
        route,
        { id: "report-reviewed", review_status: "reviewed" },
        201,
      );
    }
    if (path.endsWith("/reports/report-reviewed/download")) {
      return route.fulfill({
        status: 200,
        contentType: "text/html",
        headers: {
          "Content-Disposition": 'attachment; filename="rift-report.html"',
        },
        body: "<h1>Reviewed RIFT report</h1>",
      });
    }
    return json(
      route,
      { detail: "unhandled test route: " + method + " " + path },
      500,
    );
  });

  await page.goto("/login");
  await page.getByLabel("Operator username").fill("operator");
  await page.getByLabel("Password").fill("password");
  await page.getByRole("button", { name: "Enter console" }).click();
  await page.getByRole("link", { name: "Start onboarding" }).click();

  await page.getByLabel("Organization name").fill("RIFT partner");
  await page.getByLabel("Application name").fill("RIFT synthetic lab");
  await page.getByRole("button", { name: "Save application" }).click();
  await expect(page.getByText("RIFT synthetic lab")).toBeVisible();

  await page.getByLabel("Approver identity").fill("security owner");
  await page
    .getByLabel("Authorization statement")
    .fill("Approved synthetic staging validation");
  await page.getByText("I reviewed the written authorization").click();
  await page.getByRole("button", { name: "Record authorization" }).click();
  await page
    .getByRole("button", { name: "Create verification challenge" })
    .click();
  await expect(page.getByText("rift-challenge-token")).toBeVisible();
  await page.getByRole("button", { name: "Verify target" }).click();

  for (const [index, label] of [
    "Synthetic User A",
    "Synthetic User B",
  ].entries()) {
    await page.getByLabel("Identity label").fill(label);
    await page.getByLabel("Bearer token").fill("test-token-" + label.at(-1));
    await page.getByRole("button", { name: "Store identity" }).click();
    await expect(
      page.getByText("Credential stored · value hidden"),
    ).toHaveCount(index + 1);
  }

  await page
    .getByLabel("Owner identity")
    .selectOption({ label: "Synthetic User B" });
  await page
    .getByLabel("Unique content marker")
    .fill("RIFT_SYNTHETIC_RECORD_B");
  await page.getByRole("button", { name: "Save resource" }).click();
  for (const width of [320, 375, 414, 768]) {
    await page.setViewportSize({ width, height: 900 });
    const hasOverflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    );
    expect(hasOverflow).toBe(false);
  }
  await page.getByText("I confirm the target").click();
  await page
    .getByRole("button", { name: "Queue controlled assessment" })
    .click();

  await expect(
    page.locator(".state-badge", { hasText: "Completed" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Sanitized evidence" }),
  ).toBeVisible();
  await expect(page.locator("body")).not.toContainText("test-token");
  await page.getByRole("button", { name: "Mark finding reviewed" }).click();
  await expect(page.getByText("Reviewed", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Generate draft" }).click();
  await page.getByRole("button", { name: "Approve report" }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("link", { name: "Download reviewed" }).click();
  expect((await download).suggestedFilename()).toBe("rift-report.html");
});

for (const width of [320, 375, 414, 768]) {
  test(`login has no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 800 });
    await page.goto("/login");
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    );
    expect(overflow).toBe(false);
  });
}
