import { useEffect, useState } from 'react';
import { Wrench, Users, CheckCircle, XCircle, Shield } from 'lucide-react';
import api from '../api/client';
import { useAuthStore } from '../stores/authStore';
import SonarqubeOrgPanel from '../components/SonarqubeOrgPanel';

/* ---------- Types ---------- */

interface ToolConfig {
  name: string;
  type: string;
  status: 'configured' | 'not_configured';
  deployment: 'local' | 'external';
}

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
}

/* ---------- Page ---------- */

export default function Settings() {
  const hasRole = useAuthStore((s) => s.hasRole);
  const isAdmin = hasRole('admin');

  const [tools, setTools] = useState<ToolConfig[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [showNewUser, setShowNewUser] = useState(false);
  const [createdCreds, setCreatedCreds] = useState<{ email: string; password: string } | null>(null);
  const [loadingTools, setLoadingTools] = useState(true);
  const [loadingUsers, setLoadingUsers] = useState(true);
  const [error, setError] = useState('');

  /* Fetch tool configs */
  useEffect(() => {
    const loadTools = async () => {
      try {
        const { data } = await api.get('/settings/tools');
        setTools(data.items ?? data.results ?? data);
      } catch {
        setError('Failed to load tool configuration.');
      } finally {
        setLoadingTools(false);
      }
    };
    loadTools();
  }, []);

  /* Fetch users (admin only) */
  useEffect(() => {
    if (!isAdmin) {
      setLoadingUsers(false);
      return;
    }
    const loadUsers = async () => {
      try {
        const { data } = await api.get('/users');
        setUsers(data.items ?? data.results ?? data);
      } catch {
        /* non-critical if user list fails */
      } finally {
        setLoadingUsers(false);
      }
    };
    loadUsers();
  }, [isAdmin]);

  if (!isAdmin) {
    return (
      <div className="flex flex-col items-center justify-center py-24">
        <Shield className="h-16 w-16 text-gray-300" />
        <h2 className="mt-4 text-xl font-semibold text-gray-700">Access Denied</h2>
        <p className="mt-1 text-sm text-gray-500">
          You need administrator privileges to access this page.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* ---- Header ---- */}
      <h1 className="text-2xl font-bold text-gray-900">Settings</h1>

      {error && (
        <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {/* ---- Integrations ---- */}
      <SonarqubeOrgPanel />

      {/* ---- Tool Configuration ---- */}
      <div className="rounded-lg bg-white shadow">
        <div className="border-b border-gray-200 px-6 py-4">
          <div className="flex items-center gap-2">
            <Wrench className="h-5 w-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-800">Tool Configuration</h2>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {['Tool', 'Type', 'Status', 'Deployment'].map((h) => (
                  <th
                    key={h}
                    className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loadingTools
                ? Array.from({ length: 5 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 4 }).map((__, j) => (
                        <td key={j} className="px-6 py-4">
                          <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
                        </td>
                      ))}
                    </tr>
                  ))
                : tools.length === 0
                  ? (
                    <tr>
                      <td colSpan={4} className="px-6 py-12 text-center text-sm text-gray-500">
                        No tools configured.
                      </td>
                    </tr>
                  )
                  : tools.map((t) => (
                    <tr key={t.name} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap px-6 py-4 text-sm font-medium text-gray-900">
                        {t.name}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500 capitalize">
                        {t.type}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        {t.status === 'configured' ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                            <CheckCircle className="h-3 w-3" />
                            Configured
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
                            <XCircle className="h-3 w-3" />
                            Not Configured
                          </span>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${
                            t.deployment === 'local'
                              ? 'bg-blue-100 text-blue-800'
                              : 'bg-purple-100 text-purple-800'
                          }`}
                        >
                          {t.deployment}
                        </span>
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ---- User Management ---- */}
      <div className="rounded-lg bg-white shadow">
        <div className="flex items-center justify-between border-b border-gray-200 px-6 py-4">
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-800">User Management</h2>
          </div>
          <button onClick={() => setShowNewUser(true)}
            className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black">
            + New user
          </button>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                {['Name', 'Email', 'Role', 'Status'].map((h) => (
                  <th
                    key={h}
                    className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {loadingUsers
                ? Array.from({ length: 3 }).map((_, i) => (
                    <tr key={i}>
                      {Array.from({ length: 4 }).map((__, j) => (
                        <td key={j} className="px-6 py-4">
                          <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
                        </td>
                      ))}
                    </tr>
                  ))
                : users.length === 0
                  ? (
                    <tr>
                      <td colSpan={4} className="px-6 py-12 text-center text-sm text-gray-500">
                        No users found.
                      </td>
                    </tr>
                  )
                  : users.map((u) => (
                    <tr key={u.id} className="hover:bg-gray-50">
                      <td className="whitespace-nowrap px-6 py-4 text-sm font-medium text-gray-900">
                        {u.name}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {u.email}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <span
                          className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${
                            u.role === 'admin'
                              ? 'bg-purple-100 text-purple-800'
                              : u.role === 'security_engineer'
                                ? 'bg-blue-100 text-blue-800'
                                : u.role === 'developer'
                                  ? 'bg-green-100 text-green-800'
                                  : 'bg-gray-100 text-gray-800'
                          }`}
                        >
                          {u.role.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        {u.is_active ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
                            <CheckCircle className="h-3 w-3" />
                            Active
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full bg-gray-100 px-2.5 py-0.5 text-xs font-medium text-gray-600">
                            <XCircle className="h-3 w-3" />
                            Inactive
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
      </div>
      {showNewUser && (
        <NewUserModal
          onClose={() => setShowNewUser(false)}
          onCreated={(email, password) => {
            setShowNewUser(false);
            setCreatedCreds({ email, password });
            // refresh user list
            (async () => {
              try {
                const { data } = await api.get('/users');
                setUsers(data.items ?? data.results ?? data);
              } catch { /* noop */ }
            })();
          }}
        />
      )}
      {createdCreds && (
        <CredsRevealModal
          email={createdCreds.email}
          password={createdCreds.password}
          onClose={() => setCreatedCreds(null)}
        />
      )}
    </div>
  );
}

/* ───────────────────────────── Modals ───────────────────────────── */

function NewUserModal({ onClose, onCreated }: {
  onClose: () => void;
  onCreated: (email: string, password: string) => void;
}) {
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('viewer');
  const [autoGen, setAutoGen] = useState(true);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setBusy(true);
    try {
      const body: any = { email, name, role };
      if (!autoGen && password.trim()) body.password = password.trim();
      const { data } = await api.post('/users/', body);
      onCreated(data.user.email, data.temporary_password);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Failed to create user.');
    }
    setBusy(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div className="w-full max-w-md rounded-md bg-white shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="border-b border-gray-100 px-5 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">New user</p>
          <p className="mt-0.5 text-[12px] text-gray-500">
            We'll create the account and either auto-generate a temporary password or use the one you set.
            The user must change it on first login.
          </p>
        </div>
        <form onSubmit={submit} className="px-5 py-4 space-y-3">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Email</span>
            <input type="email" required value={email} onChange={e => setEmail(e.target.value)}
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm focus:outline-none focus:border-gray-400" />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Name</span>
            <input type="text" required value={name} onChange={e => setName(e.target.value)}
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm focus:outline-none focus:border-gray-400" />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Role</span>
            <select value={role} onChange={e => setRole(e.target.value)}
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm focus:outline-none focus:border-gray-400">
              <option value="viewer">Viewer — read-only</option>
              <option value="developer">Developer — can close findings</option>
              <option value="security_engineer">Security Engineer — can configure projects + scans</option>
              <option value="admin">Admin — full access incl. user management</option>
            </select>
          </label>
          <label className="flex items-center gap-2 text-[12px] text-gray-700">
            <input type="checkbox" checked={autoGen} onChange={e => setAutoGen(e.target.checked)}
              className="h-3 w-3 rounded border-gray-300" />
            Auto-generate temporary password
          </label>
          {!autoGen && (
            <label className="block">
              <span className="text-[10px] uppercase tracking-wider text-gray-400">Temporary password</span>
              <input type="text" required minLength={8} value={password} onChange={e => setPassword(e.target.value)}
                className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm font-mono focus:outline-none focus:border-gray-400" />
            </label>
          )}
          {error && <p className="text-[12px] text-red-700">{error}</p>}
          <div className="flex justify-end gap-2 pt-1">
            <button type="button" onClick={onClose} disabled={busy}
              className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50">
              Cancel
            </button>
            <button type="submit" disabled={busy}
              className="rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black disabled:opacity-50">
              {busy ? 'Creating…' : 'Create user'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function CredsRevealModal({ email, password, onClose }: {
  email: string;
  password: string;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* noop */ }
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div className="w-full max-w-md rounded-md bg-white shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="border-b border-gray-100 px-5 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-emerald-700">User created</p>
          <p className="mt-0.5 text-[12px] text-gray-500">
            Hand this off securely. We don't store the password in plaintext — close this dialog and it's gone.
          </p>
        </div>
        <div className="px-5 py-4 space-y-3 text-[13px]">
          <div className="flex items-center gap-2">
            <span className="text-gray-400 w-20 text-[11px] uppercase tracking-wider">Email</span>
            <span className="font-mono text-gray-800 break-all">{email}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-gray-400 w-20 text-[11px] uppercase tracking-wider">Password</span>
            <span className="font-mono text-gray-900 bg-gray-100 rounded px-2 py-1 break-all flex-1">{password}</span>
            <button onClick={copy}
              className="rounded-md border border-gray-200 px-2 py-1 text-[11px] font-medium text-gray-700 hover:bg-gray-50">
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
          <p className="text-[11px] text-gray-400">
            On first login the user will be required to change this password before they can do anything else.
          </p>
        </div>
        <div className="flex justify-end gap-2 border-t border-gray-100 px-5 py-3">
          <button onClick={onClose}
            className="rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black">
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
