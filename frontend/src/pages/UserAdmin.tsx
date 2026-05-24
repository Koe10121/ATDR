import { FormEvent, useState } from "react";
import { Badge } from "../components/Badge";
import { EmptyState } from "../components/EmptyState";
import { ErrorBanner } from "../components/ErrorBanner";
import { MetricCard } from "../components/MetricCard";
import { SafeSelect } from "../components/SafeSelect";
import { useUserMutations, useUsers } from "../hooks/useApiQueries";

export function UserAdmin() {
  const users = useUsers();
  const mutations = useUserMutations();
  const [form, setForm] = useState({ username: "", full_name: "", role: "analyst", password: "" });

  function createUser(event: FormEvent) {
    event.preventDefault();
    mutations.createUser.mutate({
      username: form.username,
      full_name: form.full_name || undefined,
      role: form.role,
      password: form.password
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

      {users.isError ? <ErrorBanner error={users.error} fallback="User management backend endpoint is not available yet." /> : null}

      <div className="grid gap-4 xl:grid-cols-[0.75fr_1.25fr]">
        <form className="panel space-y-3" onSubmit={createUser}>
          <div className="text-sm font-extrabold uppercase tracking-wide text-muted">Create User</div>
          <input className="input" placeholder="Username" value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} />
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
          <input className="input" type="password" placeholder="Temporary password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} />
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
                  <th>Full Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(users.data ?? []).map((user) => (
                  <tr key={user.id}>
                    <td>{user.username}</td>
                    <td>{user.full_name ?? "-"}</td>
                    <td><Badge value={user.role} /></td>
                    <td><Badge value={user.is_active ? "ready" : "blocked"} /></td>
                    <td>{user.created_at ?? "-"}</td>
                    <td>
                      <div className="flex flex-wrap gap-2">
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
