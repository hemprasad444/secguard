import { useEffect, useState } from 'react';
import { Wrench, Users, CheckCircle, XCircle, Shield } from 'lucide-react';
import api from '../api/client';
import { useAuthStore } from '../stores/authStore';

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
        <div className="border-b border-gray-200 px-6 py-4">
          <div className="flex items-center gap-2">
            <Users className="h-5 w-5 text-gray-400" />
            <h2 className="text-lg font-semibold text-gray-800">User Management</h2>
          </div>
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
    </div>
  );
}
