import { Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { AuthGate } from "./components/AuthGate";
import { AssessmentPage } from "./pages/AssessmentPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { SetupPage } from "./pages/SetupPage";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <AuthGate>
            <AppShell />
          </AuthGate>
        }
      >
        <Route path="/" element={<DashboardPage />} />
        <Route path="/setup" element={<SetupPage />} />
        <Route path="/assessments/:assessmentId" element={<AssessmentPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
