import { Outlet } from "react-router-dom";
import { useAuth } from "../hooks/useAuth";
import { AccessDenied } from "./AccessDenied";

export function AdminRoute() {
  const { isAdmin } = useAuth();
  return isAdmin ? <Outlet /> : <AccessDenied />;
}
