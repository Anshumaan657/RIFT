import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";

import { ApiError, api, setCsrfToken } from "../api/client";
import { InlineError } from "../components/InlineError";

function formText(data: FormData, name: string) {
  const value = data.get(name);
  return typeof value === "string" ? value : "";
}

export function LoginPage() {
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const session = await api.login(
        formText(data, "username"),
        formText(data, "password"),
      );
      setCsrfToken(session.csrf_token);
      void navigate("/");
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "Login failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-page">
      <section className="login-intro">
        <div className="register-mark" aria-hidden="true">
          <span />
          <span />
        </div>
        <p className="section-label">RIFT / operator access</p>
        <h1>Validate only what has been authorized.</h1>
        <p>
          This console runs controlled checks against reviewed staging targets
          and keeps every claim tied to sanitized evidence.
        </p>
      </section>
      <section className="login-panel" aria-labelledby="login-title">
        <p className="step-index">01</p>
        <h2 id="login-title">Sign in</h2>
        <form onSubmit={(event) => void submit(event)}>
          <label>
            Operator username
            <input name="username" autoComplete="username" required />
          </label>
          <label>
            Password
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </label>
          <InlineError message={error} />
          <button className="primary-button" disabled={busy} type="submit">
            {busy ? "Signing in…" : "Enter console"}
          </button>
        </form>
        <p className="form-note">
          Internal operator account only. Sessions expire automatically.
        </p>
      </section>
    </main>
  );
}
