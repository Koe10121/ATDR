import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { LoadingPanel } from "./LoadingPanel";

export function ProtectedRoute() {
  const { isAuthenticated, isReady } = useAuth();
  const location = useLocation();
  if (!isReady) {
    return <LoadingPanel label="Checking secure session" />;
  }
  if (!isAuthenticated) {
    const returnTo = `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to="/login" replace state={{ from: returnTo }} />;
  }
  return <Outlet />;
}
