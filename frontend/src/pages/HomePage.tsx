import { useQuery } from "@tanstack/react-query";

import { fetchHealth } from "../api/client";

export function HomePage() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => fetchHealth(signal),
  });

  return (
    <main className="shell">
      <p className="eyebrow">Authorized staging assessments</p>
      <h1>RIFT operator console</h1>
      <p className="lede">
        The application foundation is ready. Assessment onboarding begins in
        Phase 4.
      </p>
      <section aria-labelledby="service-status" className="status-card">
        <h2 id="service-status">Service status</h2>
        {health.isPending && <p>Checking the API…</p>}
        {health.isError && <p role="alert">The API is unavailable.</p>}
        {health.data && (
          <p>
            <span className="status-dot" aria-hidden="true" />
            API {health.data.version} is available.
          </p>
        )}
      </section>
    </main>
  );
}
