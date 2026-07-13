import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { SafeSelect } from "../components/SafeSelect";
import { useDevEmailOutbox, useEmailStatus, useMfuIamStatus, useOidcStatus, useUserMutations, useUsers } from "../hooks/useApiQueries";

export function UserAdmin() {
  const users = useUsers();
  const oidcStatus = useOidcStatus();
  const mfuIamStatus = useMfuIamStatus();
  const emailStatus = useEmailStatus();
  const devOutbox = useDevEmailOutbox(Boolean(emailStatus.data?.dev_outbox_available));
  const mutations = useUserMutations();
  const [form, setForm] = useState({
    username: "",
    email: "",
    full_name: "",
    role: "analyst",
    password: "",
    email_verified: false,
    auth_provider: "local",
    is_active: true
  });

  function createUser(event: FormEvent) {
    event.preventDefault();
    mutations.createUser.mutate({
      username: form.username,
      email: form.email || undefined,
      full_name: form.full_name || undefined,
      role: form.role,
      password: form.password || undefined,
      email_verified: form.email_verified,
      auth_provider: form.auth_provider,
      is_active: form.is_active
    });
  }

  const activeUsers = (users.data ?? []).filter((user) => user.is_active).length;
  const admins = (users.data ?? []).filter((user) => user.role === "admin").length;
  const verifiedEmails = (users.data ?? []).filter((user) => user.email_verified).length;
  const schoolDomains = emailStatus.data?.school_email_domains.length
    ? emailStatus.data.school_email_domains
    : oidcStatus.data?.school_email_domains ?? [];
  const mfuDomains = mfuIamStatus.data?.allowed_domains.length
    ? mfuIamStatus.data.allowed_domains
    : mfuIamStatus.data?.domain_hints ?? [];
  const canSendVerification = Boolean(emailStatus.data?.verification_enabled);
  const emailDeliveryLabel = emailStatus.data?.delivery_mode === "dev_outbox"
    ? "Dev outbox"
    : emailStatus.data?.delivery_mode === "log_only"
      ? "Log only"
      : emailStatus.data?.delivery_mode === "smtp"
        ? "SMTP configured"
        : "Disabled";
  const mfuModeLabel = mfuIamStatus.data?.mode === "template_shell_secure_handoff"
    ? "Secure template handoff"
    : mfuIamStatus.data?.mode === "template_shell_handoff_incomplete"
      ? "Handoff setup required"
    : mfuIamStatus.data?.mode === "mfu_iam_b2b_token"
      ? "MFU B2B token"
      : mfuIamStatus.data?.mode === "mfu_iam_mock"
        ? "Mock test harness"
        : mfuIamStatus.data?.enabled
          ? "Incomplete"
          : "Local login only";
  const lastValidationLabel = mfuIamStatus.data?.last_safe_validation_status === "passed"
    ? "Passed"
    : mfuIamStatus.data?.last_safe_validation_status === "failed"
      ? "Failed"
      : "Not run";

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">User Admin</div>
        <h1 className="mt-2 text-3xl font-black">Manage analyst and admin access.</h1>
        <p className="mt-2 text-muted">Password hashes and tokens are never exposed in this console.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-4">
        <MetricCard label="Users" value={users.data?.length ?? "-"} detail="Managed accounts" tone="teal" />
        <MetricCard label="Active Users" value={activeUsers} detail="Enabled accounts" tone="success" />
        <MetricCard label="Admins" value={admins} detail="Privileged operators" tone="amber" />
        <MetricCard label="Verified Emails" value={verifiedEmails} detail="Local account verification" tone="cyan" />
      </div>

      <section className="panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">External IAM</div>
            <h2 className="mt-1 text-xl font-black">School-email login groundwork</h2>
          </div>
          <Badge value={oidcStatus.data?.enabled ? "OIDC Ready" : "Local login only"} />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Status</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.enabled ? "OIDC enabled" : "Local login only"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Provider</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.provider_name ?? "Not configured"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Allowed Domains</div>
            <div className="mt-1 break-words font-bold">
              {oidcStatus.data?.allowed_domains.length ? oidcStatus.data.allowed_domains.join(", ") : "Not configured"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Default Role</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.default_role ?? "analyst"}</div>
          </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-3">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">School Email Policy</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.require_school_email ? "Required" : "Optional"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">School Domains</div>
            <div className="mt-1 break-words font-bold">
              {schoolDomains.length ? schoolDomains.join(", ") : "Not configured"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Email Login</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.local_email_login_enabled ? "Enabled" : "Disabled"}</div>
          </div>
        </div>
        <div className="mt-3 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
          Local username/password login remains active. OIDC login is configuration groundwork only until school provider details are approved.
        </div>
      </section>

      <section className="panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">MFU IAM Adapter</div>
            <h2 className="mt-1 text-xl font-black">School-email integration readiness</h2>
          </div>
          <Badge value={mfuModeLabel} />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Template Shell</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.template_shell_ready ? "Ready" : "Not ready"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Session Check</div>
            <div className="mt-1 font-bold">
              {mfuIamStatus.data?.template_shell_base_url_configured ? mfuIamStatus.data.template_shell_me_path : "Not configured"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">B2B Client</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.b2b_ready ? "Ready" : "Not ready"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Secure Handoff</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.handoff_ready ? "Ready" : "Not ready"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Admin API</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.admin_api_ready ? "Ready" : "Not ready"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Permission Bootstrap</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.permission_bootstrap_ready ? "Ready" : "Not ready"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">2FA Policy</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.auth_require_2fa ? "Required by template" : "Not required"}</div>
          </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">School Domains</div>
            <div className="mt-1 break-words font-bold">{mfuDomains.length ? mfuDomains.join(", ") : "Not configured"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Default Role</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.default_role ?? "analyst"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Admin Group Mapping</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.admin_group_mapping_configured ? "Configured" : "Not configured"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Test Harness</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.mock_enabled ? "Enabled" : "Disabled"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Permission Paths</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.permission_paths_count ?? 0}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Secrets</div>
            <div className="mt-1 font-bold">{mfuIamStatus.data?.secrets_exposed ? "Exposure detected" : "Hidden"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Last Safe Validation</div>
            <div className="mt-1 font-bold">{lastValidationLabel}</div>
            <div className="mt-1 text-xs text-muted">
              {mfuIamStatus.data?.last_safe_validation_at ?? mfuIamStatus.data?.last_safe_validation_reason ?? "No handoff event recorded"}
            </div>
          </div>
        </div>
        <div className="mt-3 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
          The supervisor template owns school login and 2FA, then launches ATDR through a single-use server-side handoff. ATDR keeps local login as a fallback and grants admin only through configured IAM groups.
        </div>
        {mfuIamStatus.isError ? <ErrorBanner error={mfuIamStatus.error} fallback="MFU IAM status is unavailable." /> : null}
      </section>

      <section className="panel">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Account Notifications</div>
            <h2 className="mt-1 text-xl font-black">Email verification foundation</h2>
          </div>
          <Badge value={emailStatus.data?.verification_enabled ? "Verification enabled" : "Verification disabled"} />
        </div>
        <div className="mt-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Notifications</div>
            <div className="mt-1 font-bold">{emailStatus.data?.notifications_enabled ? "Enabled" : "Disabled"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Delivery Mode</div>
            <div className="mt-1 font-bold">{emailDeliveryLabel}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Code TTL</div>
            <div className="mt-1 font-bold">{emailStatus.data?.code_ttl_minutes ?? 15} minutes</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">SMTP</div>
            <div className="mt-1 font-bold">{emailStatus.data?.smtp_configured ? "Configured" : "Not configured"}</div>
          </div>
        </div>
        <div className="mt-3 grid gap-3 md:grid-cols-4">
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Login Requirement</div>
            <div className="mt-1 font-bold">{emailStatus.data?.verification_required_for_login ? "Required" : "Not required"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Admin Action Requirement</div>
            <div className="mt-1 font-bold">{emailStatus.data?.verification_required_for_admin_actions ? "Required" : "Not required"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Allowed Domains</div>
            <div className="mt-1 break-words font-bold">{schoolDomains.length ? schoolDomains.join(", ") : "Not configured"}</div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Local Email Login</div>
            <div className="mt-1 font-bold">{emailStatus.data?.local_email_login_enabled === false ? "Disabled" : "Enabled"}</div>
          </div>
        </div>
        <div className="mt-3 rounded-lg border border-line bg-panel2 p-3 text-sm text-muted">
          Verification is optional by default. Real SMTP and school OIDC login stay disabled until provider details and secrets are approved.
        </div>
        {emailStatus.data?.dev_outbox_available ? (
          <details className="mt-4 rounded-lg border border-line bg-panel2 p-3">
            <summary className="cursor-pointer text-sm font-extrabold uppercase tracking-wide text-muted">Dev email outbox</summary>
            <div className="mt-3 overflow-auto">
              <table className="soc-table">
                <thead>
                  <tr>
                    <th>Created</th>
                    <th>Recipient</th>
                    <th>Purpose</th>
                    <th>Status</th>
                    <th>Preview</th>
                  </tr>
                </thead>
                <tbody>
                  {(devOutbox.data ?? []).map((item) => (
                    <tr key={item.id}>
                      <td>{item.created_at}</td>
                      <td className="break-all">{item.recipient_email}</td>
                      <td>{item.purpose}</td>
                      <td><Badge value={item.delivery_status} /></td>
                      <td className="max-w-xl whitespace-pre-wrap break-words">{item.body_preview}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!devOutbox.isLoading && !(devOutbox.data ?? []).length ? (
                <EmptyState title="No local email events" body="Verification codes appear here only when dev outbox mode is enabled." />
              ) : null}
            </div>
          </details>
        ) : null}
      </section>

      {users.isError ? <ErrorBanner error={users.error} fallback="User management backend endpoint is not available yet." /> : null}

      <div className="grid gap-4 xl:grid-cols-[0.75fr_1.25fr]">
        <form className="panel space-y-3" onSubmit={createUser}>
          <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Create User</div>
          <input className="input" placeholder="Username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} />
          <input className="input" type="email" placeholder="School email" value={form.email} onChange={(event) => setForm({ ...form, email: event.target.value })} />
          <input className="input" placeholder="Full name" value={form.full_name} onChange={(event) => setForm({ ...form, full_name: event.target.value })} />
          <SafeSelect
            value={form.role}
            options={[
              { value: "analyst", label: "Analyst" },
              { value: "admin", label: "Admin" }
            ]}
            onChange={(next) => setForm({ ...form, role: next })}
            ariaLabel="New user role"
          />
          <SafeSelect
            value={form.auth_provider}
            options={[
              { value: "local", label: "Local" },
              { value: "external", label: "External" }
            ]}
            onChange={(next) => setForm({ ...form, auth_provider: next })}
            ariaLabel="New user auth provider"
          />
          <input className="input" type="password" placeholder="Temporary password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
          <label className="flex items-center gap-2 text-sm font-bold text-muted">
            <input type="checkbox" checked={form.email_verified} onChange={(event) => setForm({ ...form, email_verified: event.target.checked })} />
            Email verified
          </label>
          <label className="flex items-center gap-2 text-sm font-bold text-muted">
            <input type="checkbox" checked={form.is_active} onChange={(event) => setForm({ ...form, is_active: event.target.checked })} />
            Account active
          </label>
          <button className="btn-primary w-full" disabled={mutations.createUser.isPending}>Create account</button>
          {mutations.createUser.isError ? <ErrorBanner error={mutations.createUser.error} /> : null}
          {mutations.createUser.data ? <div className="rounded-lg border border-success/30 bg-success/10 p-3 text-sm text-success">Created {mutations.createUser.data.username}</div> : null}
          {mutations.sendVerification.isError ? <ErrorBanner error={mutations.sendVerification.error} /> : null}
          {mutations.sendVerification.data ? (
            <div className="rounded-lg border border-cyan/30 bg-cyan/10 p-3 text-sm text-cyan">
              Verification: {mutations.sendVerification.data.status}. {mutations.sendVerification.data.message}
            </div>
          ) : null}
        </form>

        <section className="panel overflow-hidden">
          <div className="overflow-auto">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Full Name</th>
                  <th>Role</th>
                  <th>Provider</th>
                  <th>Status</th>
                  <th>Email Verified</th>
                  <th>Last Login</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(users.data ?? []).map((user) => (
                  <tr key={user.id}>
                    <td>{user.username}</td>
                    <td className="break-all">{user.email ?? "-"}</td>
                    <td>{user.full_name ?? "-"}</td>
                    <td><Badge value={user.role} /></td>
                    <td><Badge value={user.auth_provider ?? "local"} /></td>
                    <td><Badge value={user.is_active ? "ready" : "blocked"} /></td>
                    <td><Badge value={user.email_verified ? "ready" : "review"} /></td>
                    <td>{user.last_login_at ?? "-"}</td>
                    <td>{user.created_at ?? "-"}</td>
                    <td>
                      <div className="flex flex-wrap gap-2">
                        <button
                          className="btn-secondary"
                          onClick={() => {
                            const email = window.prompt(`Email for ${user.username}`, user.email ?? "");
                            if (email !== null) mutations.updateUser.mutate({ id: user.id, payload: { email } });
                          }}
                        >
                          Edit email
                        </button>
                        <button
                          className="btn-secondary"
                          onClick={() => mutations.updateUser.mutate({ id: user.id, payload: { email_verified: !user.email_verified } })}
                        >
                          {user.email_verified ? "Mark unverified" : "Verify email"}
                        </button>
                        <button
                          className="btn-secondary"
                          disabled={!user.email || !canSendVerification || mutations.sendVerification.isPending}
                          title={!canSendVerification ? "Email verification is disabled in the current configuration." : undefined}
                          onClick={() => mutations.sendVerification.mutate(user.id)}
                        >
                          Send verification
                        </button>
                        <button className="btn-secondary" onClick={() => mutations.changeRole.mutate({ id: user.id, role: user.role === "admin" ? "analyst" : "admin" })}>
                          Make {user.role === "admin" ? "analyst" : "admin"}
                        </button>
                        <button
                          className="btn-secondary"
                          onClick={() => {
                            const password = window.prompt(`New password for ${user.username}`);
                            if (password) mutations.resetPassword.mutate({ id: user.id, password });
                          }}
                        >
                          Reset password
                        </button>
                        <button className="btn-secondary" disabled={!user.is_active} onClick={() => window.confirm(`Disable ${user.username}?`) && mutations.disableUser.mutate(user.id)}>
                          Disable
                        </button>
                        {!user.is_active ? (
                          <button className="btn-secondary" onClick={() => mutations.updateUser.mutate({ id: user.id, payload: { is_active: true } })}>
                            Enable
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!users.isLoading && !(users.data ?? []).length ? <EmptyState title="No users" body="No managed users returned from the backend." /> : null}
        </section>
      </div>
    </div>
  );
}
