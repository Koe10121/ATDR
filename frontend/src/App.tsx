import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AlertsTriage } from "./pages/AlertsTriage";
import { DetectionTuning } from "./pages/DetectionTuning";
import { ExecutiveOverview } from "./pages/ExecutiveOverview";
import { LoginPage } from "./pages/LoginPage";
import { MLGovernance } from "./pages/MLGovernance";
import { ResponseCenter } from "./pages/ResponseCenter";

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<ExecutiveOverview />} />
          <Route path="/alerts" element={<AlertsTriage />} />
          <Route path="/tuning" element={<DetectionTuning />} />
          <Route path="/ml" element={<MLGovernance />} />
          <Route path="/response" element={<ResponseCenter />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
