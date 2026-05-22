import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Params } from "../lib/api";
import type { AlertStatus } from "../types/api";

export const queryKeys = {
  health: ["health"],
  me: ["me"],
  summary: ["dashboard-summary"],
  alerts: (params?: Record<string, unknown>) => ["alerts", params ?? {}],
  tuning: ["detection-tuning"],
  mlReport: ["ml-report"],
  blockedIps: ["blocked-ips"]
};

export function useHealth() {
  return useQuery({ queryKey: queryKeys.health, queryFn: api.health, retry: 1, refetchInterval: 30_000 });
}

export function useMe(enabled: boolean) {
  return useQuery({ queryKey: queryKeys.me, queryFn: api.me, enabled, retry: false });
}

export function useDashboardSummary() {
  return useQuery({ queryKey: queryKeys.summary, queryFn: api.dashboardSummary, refetchInterval: 30_000 });
}

export function useAlerts(params: Params) {
  return useQuery({ queryKey: queryKeys.alerts(params), queryFn: () => api.alerts(params), refetchInterval: 30_000 });
}

export function useDetectionTuning() {
  return useQuery({ queryKey: queryKeys.tuning, queryFn: api.detectionTuning, refetchInterval: 60_000 });
}

export function useMlReport() {
  return useQuery({ queryKey: queryKeys.mlReport, queryFn: api.mlReport, refetchInterval: 60_000 });
}

export function useBlockedIps() {
  return useQuery({ queryKey: queryKeys.blockedIps, queryFn: api.blockedIps, refetchInterval: 30_000 });
}

export function useAlertStatusMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: AlertStatus }) => api.updateAlertStatus(id, status),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
      void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
      void queryClient.invalidateQueries({ queryKey: queryKeys.tuning });
    }
  });
}

export function useResponseMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.blockedIps });
    void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
  };
  return {
    blockIp: useMutation({
      mutationFn: ({ targetIp, reason, alertId }: { targetIp: string; reason: string; alertId?: number | null }) =>
        api.blockIp(targetIp, reason, alertId),
      onSuccess: invalidate
    }),
    unblockIp: useMutation({
      mutationFn: ({ targetIp, reason }: { targetIp: string; reason: string }) => api.unblockIp(targetIp, reason),
      onSuccess: invalidate
    })
  };
}
