import { lazy, Suspense } from "react";
import type { ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AdminRoute } from "./components/AdminRoute";
import { AppShell } from "./components/AppShell";
import { LoadingPanel } from "./components/LoadingPanel";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { LoginPage } from "./pages/LoginPage";

const AlertsTriage = lazy(() => import("./pages/AlertsTriage").then((module) => ({ default: module.AlertsTriage })));
const AssistantPage = lazy(() => import("./pages/AssistantPage").then((module) => ({ default: module.AssistantPage })));
const AuditLogPage = lazy(() => import("./pages/AuditLogPage").then((module) => ({ default: module.AuditLogPage })));
const DemoControls = lazy(() => import("./pages/DemoControls").then((module) => ({ default: module.DemoControls })));
const DetectionTuning = lazy(() => import("./pages/DetectionTuning").then((module) => ({ default: module.DetectionTuning })));
const EvidenceReviewPage = lazy(() => import("./pages/EvidenceReviewPage").then((module) => ({ default: module.EvidenceReviewPage })));
const ExecutiveOverview = lazy(() => import("./pages/ExecutiveOverview").then((module) => ({ default: module.ExecutiveOverview })));
const LogExplorer = lazy(() => import("./pages/LogExplorer").then((module) => ({ default: module.LogExplorer })));
const MLGovernance = lazy(() => import("./pages/MLGovernance").then((module) => ({ default: module.MLGovernance })));
const ResponseCenter = lazy(() => import("./pages/ResponseCenter").then((module) => ({ default: module.ResponseCenter })));
const ThreatControls = lazy(() => import("./pages/ThreatControls").then((module) => ({ default: module.ThreatControls })));
const UserAdmin = lazy(() => import("./pages/UserAdmin").then((module) => ({ default: module.UserAdmin })));

function PageSuspense({ children }: { children: ReactNode }) {
  return <Suspense fallback={<LoadingPanel label="Loading page" />}>{children}</Suspense>;
}

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route index element={<Navigate to="/overview" replace />} />
          <Route path="/overview" element={<PageSuspense><ExecutiveOverview /></PageSuspense>} />
          <Route path="/alerts" element={<PageSuspense><AlertsTriage /></PageSuspense>} />
          <Route path="/logs" element={<PageSuspense><LogExplorer /></PageSuspense>} />
          <Route path="/assistant" element={<PageSuspense><AssistantPage /></PageSuspense>} />
          <Route path="/response" element={<PageSuspense><ResponseCenter /></PageSuspense>} />
          <Route path="/controls" element={<PageSuspense><ThreatControls /></PageSuspense>} />
          <Route path="/audit" element={<PageSuspense><AuditLogPage /></PageSuspense>} />
          <Route path="/tuning" element={<PageSuspense><DetectionTuning /></PageSuspense>} />
          <Route path="/evidence-review" element={<PageSuspense><EvidenceReviewPage /></PageSuspense>} />
          <Route path="/ml" element={<PageSuspense><MLGovernance /></PageSuspense>} />
          <Route element={<AdminRoute />}>
            <Route path="/users" element={<PageSuspense><UserAdmin /></PageSuspense>} />
            <Route path="/demo" element={<PageSuspense><DemoControls /></PageSuspense>} />
          </Route>
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  );
}
