import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <main className="shell">
      <h1>Page not found</h1>
      <Link to="/">Return to RIFT</Link>
    </main>
  );
}
