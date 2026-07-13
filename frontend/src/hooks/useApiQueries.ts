import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import type { Params } from "../lib/api";
import type { AlertStatus, AssistantChatRequest, AssistantFeedbackRequest, MLLabelPayload, OperationImportSubmit } from "../types/api";

export const queryKeys = {
  health: ["health"],
  me: ["me"],
  oidcStatus: ["oidc-status"],
  mfuIamStatus: ["mfu-iam-status"],
  emailStatus: ["email-status"],
  devEmailOutbox: ["dev-email-outbox"],
  assistantStatus: ["assistant-status"],
  assistantHistory: ["assistant-history"],
  assistantFeedbackSummary: (params?: Record<string, unknown>) => ["assistant-feedback-summary", params ?? {}],
  assistantFeedbackRecent: (params?: Record<string, unknown>) => ["assistant-feedback-recent", params ?? {}],
  summary: ["dashboard-summary"],
  validationSummary: ["dashboard-validation-summary"],
  detectionMlProductization: ["dashboard-detection-ml-productization"],
  ingestionRuns: (params?: Record<string, unknown>) => ["ingestion-runs", params ?? {}],
  detectionRuns: (params?: Record<string, unknown>) => ["detection-runs", params ?? {}],
  jobs: (params?: Record<string, unknown>) => ["jobs", params ?? {}],
  jobsSummary: ["jobs-summary"],
  sources: (params?: Record<string, unknown>) => ["sources", params ?? {}],
  source: (id?: number | null) => ["source", id],
  alerts: (params?: Record<string, unknown>) => ["alerts", params ?? {}],
  alertsPage: (params?: Record<string, unknown>) => ["alerts-page", params ?? {}],
  alert: (id?: number | null) => ["alert", id],
  alertNotes: (id?: number | null) => ["alert-notes", id],
  alertTimeline: (id?: number | null) => ["alert-timeline", id],
  alertReport: (id?: number | null) => ["alert-report", id],
  alertCases: (params?: Record<string, unknown>) => ["alert-cases", params ?? {}],
  logs: (params?: Record<string, unknown>) => ["logs", params ?? {}],
  logsPage: (params?: Record<string, unknown>) => ["logs-page", params ?? {}],
  log: (id?: number | null) => ["log", id],
  audit: (params?: Record<string, unknown>) => ["audit", params ?? {}],
  auditPage: (params?: Record<string, unknown>) => ["audit-page", params ?? {}],
  suppressions: ["suppressions"],
  watchlists: ["watchlists"],
  tuning: ["detection-tuning"],
  mlReport: ["ml-report"],
  supervisedReport: ["supervised-report"],
  supervisedModels: ["supervised-models"],
  classTemporalCoverage: ["class-temporal-coverage"],
  mlLabels: (params?: Record<string, unknown>) => ["ml-labels", params ?? {}],
  mlReviewQueue: (params?: Record<string, unknown>) => ["ml-review-queue", params ?? {}],
  blockedIps: ["blocked-ips"],
  users: ["users"]
};

function invalidateAlerts(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: ["alerts"] });
  void queryClient.invalidateQueries({ queryKey: ["alerts-page"] });
  void queryClient.invalidateQueries({ queryKey: ["alert"] });
  void queryClient.invalidateQueries({ queryKey: ["alert-notes"] });
  void queryClient.invalidateQueries({ queryKey: ["alert-timeline"] });
  void queryClient.invalidateQueries({ queryKey: ["alert-report"] });
  void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
  void queryClient.invalidateQueries({ queryKey: queryKeys.tuning });
}

function invalidateAudit(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: ["audit"] });
  void queryClient.invalidateQueries({ queryKey: ["audit-page"] });
}

function invalidateEmailAdmin(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: queryKeys.users });
  void queryClient.invalidateQueries({ queryKey: queryKeys.emailStatus });
  void queryClient.invalidateQueries({ queryKey: queryKeys.devEmailOutbox });
  invalidateAudit(queryClient);
}

function invalidateThreatControls(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: queryKeys.suppressions });
  void queryClient.invalidateQueries({ queryKey: queryKeys.watchlists });
  void queryClient.invalidateQueries({ queryKey: queryKeys.blockedIps });
  void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
  void queryClient.invalidateQueries({ queryKey: queryKeys.tuning });
}

const mlGovernanceQueryOptions = {
  staleTime: 5 * 60_000,
  refetchInterval: false,
  refetchOnWindowFocus: false
} as const;

export function useHealth() {
  return useQuery({ queryKey: queryKeys.health, queryFn: api.health, retry: 1, refetchInterval: 30_000 });
}

export function useMe(enabled: boolean) {
  return useQuery({ queryKey: queryKeys.me, queryFn: api.me, enabled, retry: false });
}

export function useOidcStatus() {
  return useQuery({ queryKey: queryKeys.oidcStatus, queryFn: api.oidcStatus, retry: false });
}

export function useMfuIamStatus() {
  return useQuery({ queryKey: queryKeys.mfuIamStatus, queryFn: api.mfuIamStatus, retry: false });
}

export function useEmailStatus() {
  return useQuery({ queryKey: queryKeys.emailStatus, queryFn: api.emailStatus, retry: false, staleTime: 60_000 });
}

export function useDevEmailOutbox(enabled = true) {
  return useQuery({
    queryKey: queryKeys.devEmailOutbox,
    queryFn: () => api.devEmailOutbox({ limit: 10 }),
    enabled,
    retry: false,
    staleTime: 30_000
  });
}

export function useAssistantStatus() {
  return useQuery({ queryKey: queryKeys.assistantStatus, queryFn: api.assistantStatus, retry: false, staleTime: 60_000 });
}

export function useAssistantHistory() {
  return useQuery({ queryKey: queryKeys.assistantHistory, queryFn: () => api.assistantHistory({ limit: 8 }), retry: false, refetchInterval: 30_000 });
}

export function useAssistantFeedbackSummary(params: Params = {}) {
  return useQuery({
    queryKey: queryKeys.assistantFeedbackSummary(params),
    queryFn: () => api.assistantFeedbackSummary(params),
    retry: false,
    refetchInterval: 60_000
  });
}

export function useAssistantFeedbackRecent(params: Params = { limit: 8 }) {
  return useQuery({
    queryKey: queryKeys.assistantFeedbackRecent(params),
    queryFn: () => api.assistantFeedbackRecent(params),
    retry: false,
    refetchInterval: 60_000
  });
}

export function useAssistantMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: AssistantChatRequest) => api.assistantChat(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.assistantHistory });
    }
  });
}

export function useAssistantFeedbackMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: AssistantFeedbackRequest) => api.assistantFeedback(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["assistant-feedback-summary"] });
      void queryClient.invalidateQueries({ queryKey: ["assistant-feedback-recent"] });
      invalidateAudit(queryClient);
    }
  });
}

export function useDashboardSummary() {
  return useQuery({ queryKey: queryKeys.summary, queryFn: api.dashboardSummary, refetchInterval: 30_000 });
}

export function useDashboardValidationSummary() {
  return useQuery({
    queryKey: queryKeys.validationSummary,
    queryFn: api.dashboardValidationSummary,
    refetchInterval: 60_000,
    retry: 1
  });
}

export function useDetectionMlProductization() {
  return useQuery({
    queryKey: queryKeys.detectionMlProductization,
    queryFn: () => api.dashboardDetectionMlProductization(),
    ...mlGovernanceQueryOptions,
    retry: 1
  });
}

export function useIngestionRuns(params: Params = {}) {
  return useQuery({ queryKey: queryKeys.ingestionRuns(params), queryFn: () => api.ingestionRuns(params), refetchInterval: 30_000 });
}

export function useDetectionRuns(params: Params = {}) {
  return useQuery({ queryKey: queryKeys.detectionRuns(params), queryFn: () => api.detectionRuns(params), refetchInterval: 30_000 });
}

export function useJobs(params: Params = {}) {
  return useQuery({ queryKey: queryKeys.jobs(params), queryFn: () => api.jobs(params), refetchInterval: 10_000 });
}

export function useJobsSummary() {
  return useQuery({ queryKey: queryKeys.jobsSummary, queryFn: api.jobsSummary, refetchInterval: 10_000 });
}

function invalidateJobs(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: ["jobs"] });
  void queryClient.invalidateQueries({ queryKey: queryKeys.jobsSummary });
  void queryClient.invalidateQueries({ queryKey: ["ingestion-runs"] });
  void queryClient.invalidateQueries({ queryKey: ["detection-runs"] });
  void queryClient.invalidateQueries({ queryKey: queryKeys.summary });
}

export function useCancelJobMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: number) => api.cancelJob(jobId),
    onSuccess: () => invalidateJobs(queryClient)
  });
}

export function useRetryJobMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: number) => api.retryJob(jobId),
    onSuccess: () => invalidateJobs(queryClient)
  });
}

export function useResumeJobMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (jobId: number) => api.resumeJob(jobId),
    onSuccess: () => invalidateJobs(queryClient)
  });
}

export function useQueuedImportMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: OperationImportSubmit) => api.enqueueImport(payload),
    onSuccess: () => invalidateJobs(queryClient)
  });
}

export function useSources(params: Params = {}) {
  return useQuery({ queryKey: queryKeys.sources(params), queryFn: () => api.sources(params), refetchInterval: 30_000 });
}

export function useSource(id?: number | null) {
  return useQuery({ queryKey: queryKeys.source(id), queryFn: () => api.source(id as number), enabled: Boolean(id), refetchInterval: 30_000 });
}

export function useAlerts(params: Params) {
  return useQuery({ queryKey: queryKeys.alerts(params), queryFn: () => api.alerts(params), refetchInterval: 30_000 });
}

export function useAlertsPage(params: Params) {
  return useQuery({ queryKey: queryKeys.alertsPage(params), queryFn: () => api.alertsPage(params), refetchInterval: 30_000 });
}

export function useAlert(id?: number | null) {
  return useQuery({ queryKey: queryKeys.alert(id), queryFn: () => api.alert(id as number), enabled: Boolean(id), refetchInterval: 30_000 });
}

export function useAlertNotes(id?: number | null) {
  return useQuery({ queryKey: queryKeys.alertNotes(id), queryFn: () => api.alertNotes(id as number), enabled: Boolean(id) });
}

export function useAlertTimeline(id?: number | null) {
  return useQuery({ queryKey: queryKeys.alertTimeline(id), queryFn: () => api.alertTimeline(id as number), enabled: Boolean(id) });
}

export function useAlertReport(id?: number | null) {
  return useQuery({ queryKey: queryKeys.alertReport(id), queryFn: () => api.alertReport(id as number), enabled: Boolean(id) });
}

export function useAlertCases(params: Params = {}) {
  return useQuery({ queryKey: queryKeys.alertCases(params), queryFn: () => api.alertCases(params), refetchInterval: 60_000 });
}

export function useLogs(params: Params) {
  return useQuery({ queryKey: queryKeys.logs(params), queryFn: () => api.logs(params), refetchInterval: 30_000 });
}

export function useLogsPage(params: Params) {
  return useQuery({ queryKey: queryKeys.logsPage(params), queryFn: () => api.logsPage(params), refetchInterval: 30_000 });
}

export function useLog(id?: number | null) {
  return useQuery({ queryKey: queryKeys.log(id), queryFn: () => api.log(id as number), enabled: Boolean(id) });
}

export function useAudit(params: Params) {
  return useQuery({ queryKey: queryKeys.audit(params), queryFn: () => api.audit(params), refetchInterval: 30_000 });
}

export function useAuditPage(params: Params) {
  return useQuery({ queryKey: queryKeys.auditPage(params), queryFn: () => api.auditPage(params), refetchInterval: 30_000 });
}

export function useDetectionTuning() {
  return useQuery({ queryKey: queryKeys.tuning, queryFn: api.detectionTuning, refetchInterval: 60_000 });
}

export function useMlReport() {
  return useQuery({ queryKey: queryKeys.mlReport, queryFn: api.mlReport, ...mlGovernanceQueryOptions });
}

export function useSupervisedReport() {
  return useQuery({ queryKey: queryKeys.supervisedReport, queryFn: api.supervisedReport, ...mlGovernanceQueryOptions });
}

export function useSupervisedModels() {
  return useQuery({ queryKey: queryKeys.supervisedModels, queryFn: api.supervisedModels, ...mlGovernanceQueryOptions });
}

export function useClassTemporalCoverage() {
  return useQuery({ queryKey: queryKeys.classTemporalCoverage, queryFn: () => api.classTemporalCoverage(), ...mlGovernanceQueryOptions });
}

export function useMlLabels(params: Params, enabled = true) {
  return useQuery({ queryKey: queryKeys.mlLabels(params), queryFn: () => api.mlLabels(params), enabled, refetchInterval: 30_000 });
}

export function useMlReviewQueue(params: Params) {
  return useQuery({ queryKey: queryKeys.mlReviewQueue(params), queryFn: () => api.mlReviewQueue(params), ...mlGovernanceQueryOptions });
}

export function useBlockedIps() {
  return useQuery({ queryKey: queryKeys.blockedIps, queryFn: api.blockedIps, refetchInterval: 30_000 });
}

export function useSuppressions() {
  return useQuery({ queryKey: queryKeys.suppressions, queryFn: () => api.suppressions({ active_only: false }), refetchInterval: 30_000 });
}

export function useWatchlists() {
  return useQuery({ queryKey: queryKeys.watchlists, queryFn: () => api.watchlists({ active_only: false }), refetchInterval: 30_000 });
}

export function useUsers(enabled = true) {
  return useQuery({ queryKey: queryKeys.users, queryFn: api.users, enabled, retry: false });
}

export function useAlertStatusMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: AlertStatus }) => api.updateAlertStatus(id, status),
    onSuccess: () => invalidateAlerts(queryClient)
  });
}

export function useAlertWorkflowMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    invalidateAlerts(queryClient);
    invalidateAudit(queryClient);
  };
  return {
    assignToMe: useMutation({ mutationFn: (id: number) => api.assignAlertToMe(id), onSuccess: invalidate }),
    addNote: useMutation({ mutationFn: ({ id, note }: { id: number; note: string }) => api.addAlertNote(id, note), onSuccess: invalidate })
  };
}

export function useResponseMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    invalidateThreatControls(queryClient);
    invalidateAudit(queryClient);
    invalidateAlerts(queryClient);
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

export function useThreatControlMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    invalidateThreatControls(queryClient);
    invalidateAudit(queryClient);
    invalidateAlerts(queryClient);
  };
  return {
    createSuppression: useMutation({ mutationFn: api.createSuppression, onSuccess: invalidate }),
    disableSuppression: useMutation({ mutationFn: api.disableSuppression, onSuccess: invalidate }),
    reviewSuppression: useMutation({
      mutationFn: ({ id, status, notes }: { id: number; status: string; notes?: string }) => api.reviewSuppression(id, status, notes),
      onSuccess: invalidate
    }),
    createWatchlist: useMutation({ mutationFn: api.createWatchlist, onSuccess: invalidate }),
    disableWatchlist: useMutation({ mutationFn: api.disableWatchlist, onSuccess: invalidate })
  };
}

export function useUserMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    invalidateEmailAdmin(queryClient);
  };
  return {
    createUser: useMutation({ mutationFn: api.createUser, onSuccess: invalidate }),
    disableUser: useMutation({ mutationFn: api.disableUser, onSuccess: invalidate }),
    updateUser: useMutation({
      mutationFn: ({ id, payload }: { id: number; payload: Parameters<typeof api.updateUser>[1] }) => api.updateUser(id, payload),
      onSuccess: invalidate
    }),
    resetPassword: useMutation({
      mutationFn: ({ id, password }: { id: number; password: string }) => api.resetPassword(id, password),
      onSuccess: invalidate
    }),
    changeRole: useMutation({
      mutationFn: ({ id, role }: { id: number; role: string }) => api.changeUserRole(id, role),
      onSuccess: invalidate
    }),
    sendVerification: useMutation({
      mutationFn: (id: number) => api.sendUserVerification(id),
      onSuccess: invalidate
    })
  };
}

export function useDemoMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    void queryClient.invalidateQueries();
  };
  return {
    reset: useMutation({ mutationFn: api.demoReset, onSuccess: invalidate }),
    importSample: useMutation({ mutationFn: api.demoImportSample, onSuccess: invalidate }),
    runDetection: useMutation({ mutationFn: api.demoRunDetection, onSuccess: invalidate }),
    trainMl: useMutation({ mutationFn: api.demoTrainMl, onSuccess: invalidate }),
    applyMl: useMutation({ mutationFn: api.demoApplyMl, onSuccess: invalidate }),
    exportBundle: useMutation({ mutationFn: api.demoExportBundle, onSuccess: invalidate })
  };
}

export function useMlLabelMutations() {
  const queryClient = useQueryClient();
  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ["ml-labels"] });
    void queryClient.invalidateQueries({ queryKey: ["ml-review-queue"] });
    void queryClient.invalidateQueries({ queryKey: queryKeys.supervisedReport });
    void queryClient.invalidateQueries({ queryKey: queryKeys.supervisedModels });
    void queryClient.invalidateQueries({ queryKey: queryKeys.mlReport });
    void queryClient.invalidateQueries({ queryKey: ["logs"] });
    void queryClient.invalidateQueries({ queryKey: ["logs-page"] });
    invalidateAudit(queryClient);
  };
  return {
    create: useMutation({ mutationFn: (payload: MLLabelPayload) => api.createMlLabel(payload), onSuccess: invalidate }),
    update: useMutation({ mutationFn: ({ id, payload }: { id: number; payload: Partial<MLLabelPayload> }) => api.updateMlLabel(id, payload), onSuccess: invalidate }),
    importCsv: useMutation({
      mutationFn: (input: File | { file: File; params?: Record<string, string | number | boolean | null | undefined> }) =>
        input instanceof File ? api.importMlLabels(input) : api.importMlLabels(input.file, input.params),
      onSuccess: invalidate
    }),
    importBenchmarkCsv: useMutation({
      mutationFn: (file: File) =>
        api.importBenchmarkReview(file, {
          benchmark_kind: "external_holdout"
        }),
      onSuccess: () => {
        void queryClient.invalidateQueries({
          queryKey: queryKeys.validationSummary
        });
      }
    })
  };
}
