import type { ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";

import { getCsrfToken } from "../api/client";

export function AuthGate({ children }: { children: ReactNode }) {
  const location = useLocation();
  if (!getCsrfToken()) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  }
  return children;
}
