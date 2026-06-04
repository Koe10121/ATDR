import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { SafeSelect } from "../components/SafeSelect";
import { useOidcStatus, useUserMutations, useUsers } from "../hooks/useApiQueries";

export function UserAdmin() {
  const users = useUsers();
  const oidcStatus = useOidcStatus();
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

  return (
    <div className="space-y-5">
      <section className="hero-panel">
        <div className="text-sm font-extrabold uppercase tracking-wide text-cyan">User Admin</div>
        <h1 className="mt-2 text-3xl font-black">Manage analyst and admin access.</h1>
        <p className="mt-2 text-muted">Password hashes and tokens are never exposed in this console.</p>
      </section>

      <div className="grid gap-4 md:grid-cols-3">
        <MetricCard label="Users" value={users.data?.length ?? "-"} detail="Managed accounts" tone="teal" />
        <MetricCard label="Active Users" value={activeUsers} detail="Enabled accounts" tone="success" />
        <MetricCard label="Admins" value={admins} detail="Privileged operators" tone="amber" />
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
              {oidcStatus.data?.school_email_domains.length ? oidcStatus.data.school_email_domains.join(", ") : "Not configured"}
            </div>
          </div>
          <div className="rounded-lg border border-line bg-panel2 p-3">
            <div className="text-xs uppercase tracking-wide text-muted">Email Login</div>
            <div className="mt-1 font-bold">{oidcStatus.data?.local_email_login_enabled ? "Enabled" : "Disabled"}</div>
          </div>
        </div>
        <p className="mt-3 text-sm text-muted">
          External school-email login can be enabled later through OIDC. Local username/password login remains active.
        </p>
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
