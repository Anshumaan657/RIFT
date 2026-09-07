import { useQuery } from "@tanstack/react-query";
import { NavLink, Outlet, useNavigate } from "react-router-dom";

import { api, clearSession } from "../api/client";

export function AppShell() {
  const navigate = useNavigate();
  const health = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => api.health(signal),
  });

  async function signOut() {
    try {
      await api.logout();
    } finally {
      clearSession();
      void navigate("/login");
    }
  }

  return (
    <div className="operator-layout">
      <header className="operator-rail">
        <NavLink className="wordmark" to="/" aria-label="RIFT dashboard">
          <span aria-hidden="true">R/</span>
          <strong>RIFT</strong>
        </NavLink>
        <p className="rail-context">Authorized staging validation</p>
        <nav aria-label="Operator navigation">
          <NavLink to="/" end>
            Assessments
          </NavLink>
          <NavLink to="/setup">New assessment</NavLink>
        </nav>
        <div className="rail-foot">
          <p className="service-line">
            <span
              className={"service-mark " + (health.data ? "is-live" : "")}
              aria-hidden="true"
            />
            {health.data ? "API " + health.data.version : "API unavailable"}
          </p>
          <button
            className="text-button"
            type="button"
            onClick={() => void signOut()}
          >
            Sign out
          </button>
        </div>
      </header>
      <main className="operator-main">
        <Outlet />
      </main>
    </div>
  );
}
