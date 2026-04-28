import { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, ExternalLink, Trash2, Search, MoreHorizontal, X } from 'lucide-react';
import { getProjects, createProject, deleteProject } from '../api/projects';
import { getProjectsOverview } from '../api/dashboard';
import { useAuthStore } from '../stores/authStore';
import SonarqubeImportModal from '../components/SonarqubeImportModal';

interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  created_at: string;
}

interface Overview {
  project_id: string;
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixable_packages: number;
  no_fix_packages: number;
}

export default function Projects() {
  const navigate = useNavigate();
  const hasRole = useAuthStore((s) => s.hasRole);

  const [projects, setProjects] = useState<Project[]>([]);
  const [overview, setOverview] = useState<Record<string, Overview>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [menuOpen, setMenuOpen] = useState<string | null>(null);

  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  const [showModal, setShowModal] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [formName, setFormName] = useState('');
  const [formRepoUrl, setFormRepoUrl] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const reload = async () => {
    try {
      const res = await getProjects();
      setProjects(res.items ?? res.results ?? res);
    } catch {
      setError('Failed to load projects.');
    } finally {
      setLoading(false);
    }
    try {
      const res = await getProjectsOverview();
      const map: Record<string, Overview> = {};
      for (const item of res.data ?? []) map[item.project_id] = item;
      setOverview(map);
    } catch { /* noop */ }
  };

  useEffect(() => { reload(); }, []);

  useEffect(() => {
    if (!menuOpen) return;
    const close = () => setMenuOpen(null);
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, [menuOpen]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(''); setSubmitting(true);
    try {
      const newProject = await createProject({
        name: formName,
        repository_url: formRepoUrl || undefined,
        description: formDescription || undefined,
      });
      setProjects((prev) => [newProject, ...prev]);
      setShowModal(false);
      setFormName(''); setFormRepoUrl(''); setFormDescription('');
    } catch {
      setFormError('Failed to create project.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true); setDeleteError('');
    try {
      await deleteProject(deleteTarget.id);
      setProjects((prev) => prev.filter((p) => p.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch {
      setDeleteError('Failed to delete project.');
    } finally {
      setDeleting(false);
    }
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return projects;
    return projects.filter(p =>
      p.name.toLowerCase().includes(q) ||
      (p.description ?? '').toLowerCase().includes(q) ||
      (p.repository_url ?? '').toLowerCase().includes(q)
    );
  }, [projects, search]);

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-end justify-between pb-6">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">Projects</h1>
          <p className="mt-1 text-sm text-gray-500">
            Manage projects and track security across your codebase.
          </p>
        </div>
        {hasRole('security_engineer') && (
          <div className="flex items-center gap-2">
            <button onClick={() => setShowImport(true)}
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors">
              Import from SonarQube
            </button>
            <button onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white hover:bg-black transition-colors">
              <Plus className="h-4 w-4" /> New project
            </button>
          </div>
        )}
      </div>

      {error && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-4 py-2.5 text-sm text-red-700">{error}</div>
      )}

      {/* Search */}
      <div className="mb-4">
        <div className="relative max-w-sm">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search"
            className="w-full rounded-md border border-gray-200 bg-white py-2 pl-9 pr-3 text-sm focus:border-gray-400 focus:outline-none focus:ring-0 placeholder:text-gray-400"
          />
        </div>
      </div>

      {/* Table */}
      <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
        {loading ? (
          <div className="divide-y divide-gray-100">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="animate-pulse px-5 py-4">
                <div className="h-4 w-48 rounded bg-gray-100" />
                <div className="mt-2 h-3 w-72 rounded bg-gray-50" />
              </div>
            ))}
          </div>
        ) : filtered.length === 0 ? (
          <div className="py-20 text-center">
            <p className="text-sm font-medium text-gray-700">
              {projects.length === 0 ? 'No projects' : 'No matching projects'}
            </p>
            <p className="mt-1 text-sm text-gray-500">
              {projects.length === 0 ? 'Create your first project to start scanning.' : 'Try a different search.'}
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead className="border-b border-gray-100 bg-gray-50/30">
              <tr>
                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500">Name</th>
                <th className="px-5 py-2.5 text-left text-xs font-medium text-gray-500">Repository</th>
                <th className="px-5 py-2.5 text-right text-xs font-medium text-gray-500">Open findings</th>
                <th className="px-5 py-2.5 text-right text-xs font-medium text-gray-500">Severity</th>
                <th className="px-5 py-2.5 text-right text-xs font-medium text-gray-500">Created</th>
                <th className="w-8 px-2 py-2.5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {filtered.map((p) => {
                const ov = overview[p.id];
                const critical = ov?.critical ?? 0;
                const high = ov?.high ?? 0;
                return (
                  <tr key={p.id}
                    onClick={() => navigate(`/projects/${p.id}`)}
                    className="cursor-pointer hover:bg-gray-50 transition-colors">
                    <td className="px-5 py-3">
                      <div className="font-medium text-gray-900">{p.name}</div>
                      {p.description && <div className="text-xs text-gray-500 line-clamp-1 mt-0.5">{p.description}</div>}
                    </td>
                    <td className="px-5 py-3">
                      {p.repository_url ? (
                        <a href={p.repository_url} target="_blank" rel="noopener noreferrer"
                          onClick={e => e.stopPropagation()}
                          className="inline-flex items-center gap-1 text-sm text-gray-600 hover:text-gray-900 hover:underline">
                          <span className="truncate max-w-[240px]">{p.repository_url.replace(/^https?:\/\//,'')}</span>
                          <ExternalLink className="h-3 w-3 shrink-0 text-gray-400" />
                        </a>
                      ) : (
                        <span className="text-sm text-gray-300">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-right text-sm text-gray-900 tabular-nums">
                      {ov ? ov.total_findings.toLocaleString() : '—'}
                    </td>
                    <td className="px-5 py-3 text-right text-sm">
                      {critical > 0 || high > 0 ? (
                        <span className="inline-flex items-center gap-2 text-gray-600">
                          {critical > 0 && (
                            <span className="inline-flex items-center gap-1">
                              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                              <span className="tabular-nums">{critical}</span>
                            </span>
                          )}
                          {high > 0 && (
                            <span className="inline-flex items-center gap-1">
                              <span className="h-1.5 w-1.5 rounded-full bg-orange-500" />
                              <span className="tabular-nums">{high}</span>
                            </span>
                          )}
                        </span>
                      ) : ov ? (
                        <span className="inline-flex items-center gap-1 text-gray-400">
                          <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
                          Clean
                        </span>
                      ) : (
                        <span className="text-gray-300">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-right text-sm text-gray-500">
                      {new Date(p.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}
                    </td>
                    <td className="px-2 py-3 text-right">
                      {hasRole('admin') && (
                        <div className="relative inline-block">
                          <button onClick={e => { e.stopPropagation(); setMenuOpen(menuOpen === p.id ? null : p.id); }}
                            className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 transition-colors">
                            <MoreHorizontal className="h-4 w-4" />
                          </button>
                          {menuOpen === p.id && (
                            <div onClick={e => e.stopPropagation()}
                              className="absolute right-0 top-full mt-1 z-10 w-40 rounded-md border border-gray-200 bg-white shadow-sm py-1">
                              <button onClick={() => { setMenuOpen(null); setDeleteTarget(p); }}
                                className="flex w-full items-center gap-2 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
                                <Trash2 className="h-3.5 w-3.5 text-gray-400" /> Delete
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Footer summary */}
      {!loading && filtered.length > 0 && (
        <p className="mt-3 text-xs text-gray-500">
          {filtered.length} {filtered.length === 1 ? 'project' : 'projects'}
          {search && ` matching "${search}"`}
        </p>
      )}

      {/* Delete Modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" onClick={() => setDeleteTarget(null)}>
          <div className="w-full max-w-md rounded-md bg-white shadow-xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100">
              <h2 className="text-base font-medium text-gray-900">Delete project</h2>
              <button onClick={() => setDeleteTarget(null)} className="text-gray-400 hover:text-gray-600">
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="px-5 py-4">
              <p className="text-sm text-gray-700">
                Are you sure you want to delete <span className="font-medium">{deleteTarget.name}</span>?
              </p>
              <p className="mt-2 text-sm text-gray-500">
                All scans, findings, and reports associated with this project will be permanently removed. This cannot be undone.
              </p>
              {deleteError && (
                <div className="mt-3 rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{deleteError}</div>
              )}
            </div>
            <div className="flex justify-end gap-2 px-5 py-3 border-t border-gray-100">
              <button onClick={() => setDeleteTarget(null)} disabled={deleting}
                className="rounded-md px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-100">
                Cancel
              </button>
              <button onClick={handleDelete} disabled={deleting}
                className="rounded-md bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-60">
                {deleting ? 'Deleting...' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" onClick={() => setShowModal(false)}>
          <div className="w-full max-w-md rounded-md bg-white shadow-xl" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100">
              <h2 className="text-base font-medium text-gray-900">New project</h2>
              <button onClick={() => setShowModal(false)} className="text-gray-400 hover:text-gray-600">
                <X className="h-4 w-4" />
              </button>
            </div>
            <form onSubmit={handleCreate}>
              <div className="px-5 py-4 space-y-4">
                {formError && (
                  <div className="rounded border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700">Name</label>
                  <input required value={formName} onChange={e => setFormName(e.target.value)}
                    placeholder="payment-service"
                    className="mt-1.5 block w-full rounded-md border border-gray-200 px-3 py-1.5 text-sm focus:border-gray-400 focus:outline-none placeholder:text-gray-400" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Repository URL <span className="font-normal text-gray-400">— optional</span>
                  </label>
                  <input value={formRepoUrl} onChange={e => setFormRepoUrl(e.target.value)}
                    placeholder="https://github.com/org/repo"
                    className="mt-1.5 block w-full rounded-md border border-gray-200 px-3 py-1.5 text-sm focus:border-gray-400 focus:outline-none placeholder:text-gray-400" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">
                    Description <span className="font-normal text-gray-400">— optional</span>
                  </label>
                  <textarea value={formDescription} onChange={e => setFormDescription(e.target.value)} rows={2}
                    className="mt-1.5 block w-full rounded-md border border-gray-200 px-3 py-1.5 text-sm focus:border-gray-400 focus:outline-none" />
                </div>
              </div>
              <div className="flex justify-end gap-2 px-5 py-3 border-t border-gray-100">
                <button type="button" onClick={() => setShowModal(false)}
                  className="rounded-md px-3 py-1.5 text-sm font-medium text-gray-700 hover:bg-gray-100">
                  Cancel
                </button>
                <button type="submit" disabled={submitting}
                  className="rounded-md bg-gray-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-black disabled:opacity-60">
                  {submitting ? 'Creating...' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* SonarQube bulk-import wizard */}
      {showImport && (
        <SonarqubeImportModal
          onClose={() => setShowImport(false)}
          onImported={() => { reload(); }}
        />
      )}
    </div>
  );
}
