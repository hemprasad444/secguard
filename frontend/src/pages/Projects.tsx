import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, FolderGit2, ExternalLink, Trash2, AlertCircle, CheckCircle } from 'lucide-react';
import { getProjects, createProject, deleteProject } from '../api/projects';
import { getProjectsSbomOverview } from '../api/dashboard';
import { useAuthStore } from '../stores/authStore';

/* ---------- Types ---------- */

interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  created_at: string;
}

/* ---------- Page ---------- */

export default function Projects() {
  const navigate = useNavigate();
  const hasRole = useAuthStore((s) => s.hasRole);

  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  /* Delete state */
  const [deleteTarget, setDeleteTarget] = useState<Project | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');

  /* Modal state */
  const [showModal, setShowModal] = useState(false);
  const [formName, setFormName] = useState('');
  const [formRepoUrl, setFormRepoUrl] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formError, setFormError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  /* SBOM overview per project */
  const [sbomMap, setSbomMap] = useState<Record<string, { actionable: number; not_actionable: number; total: number }>>({});

  /* Fetch projects */
  useEffect(() => {
    const load = async () => {
      try {
        const res = await getProjects();
        setProjects(res.items ?? res.results ?? res);
      } catch {
        setError('Failed to load projects.');
      } finally {
        setLoading(false);
      }
    };
    load();
    // Fetch SBOM overview in parallel
    getProjectsSbomOverview().then(res => {
      const map: Record<string, { actionable: number; not_actionable: number; total: number }> = {};
      for (const item of (res.data ?? [])) {
        map[item.project_id] = { actionable: item.actionable, not_actionable: item.not_actionable, total: item.total_packages };
      }
      setSbomMap(map);
    }).catch(() => {});
  }, []);

  /* Create project */
  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setSubmitting(true);
    try {
      const newProject = await createProject({
        name: formName,
        repository_url: formRepoUrl || undefined,
        description: formDescription || undefined,
      });
      setProjects((prev) => [newProject, ...prev]);
      setShowModal(false);
      setFormName('');
      setFormRepoUrl('');
      setFormDescription('');
    } catch {
      setFormError('Failed to create project. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  /* Delete project */
  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleting(true);
    setDeleteError('');
    try {
      await deleteProject(deleteTarget.id);
      setProjects((prev) => prev.filter((p) => p.id !== deleteTarget.id));
      setDeleteTarget(null);
    } catch {
      setDeleteError('Failed to delete project. Please try again.');
    } finally {
      setDeleting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* ---- Header ---- */}
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Projects</h1>
        {hasRole('security_engineer') && (
          <button
            onClick={() => setShowModal(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm
                       font-semibold text-white shadow-sm transition-colors hover:bg-primary-700"
          >
            <Plus className="h-4 w-4" />
            New Project
          </button>
        )}
      </div>

      {/* ---- Error ---- */}
      {error && (
        <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {/* ---- Grid ---- */}
      {loading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="animate-pulse rounded-lg bg-white p-6 shadow">
              <div className="mb-3 h-5 w-3/4 rounded bg-gray-200" />
              <div className="mb-2 h-4 w-full rounded bg-gray-100" />
              <div className="h-4 w-1/2 rounded bg-gray-100" />
            </div>
          ))}
        </div>
      ) : projects.length === 0 ? (
        <div className="rounded-lg bg-white py-16 text-center shadow">
          <FolderGit2 className="mx-auto h-12 w-12 text-gray-300" />
          <p className="mt-3 text-sm text-gray-500">No projects yet. Create your first project to get started.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {projects.map((project) => (
            <div
              key={project.id}
              onClick={() => navigate(`/projects/${project.id}`)}
              className="group relative cursor-pointer rounded-lg bg-white p-6 shadow transition-shadow hover:shadow-md"
            >
              {hasRole('admin') && (
                <button
                  onClick={(e) => { e.stopPropagation(); setDeleteTarget(project); }}
                  className="absolute right-3 top-3 hidden rounded-md p-1.5 text-gray-400 transition-colors
                             hover:bg-red-50 hover:text-red-600 group-hover:flex"
                  title="Delete project"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
              <h3 className="text-lg font-semibold text-gray-900">{project.name}</h3>
              {project.description && (
                <p className="mt-1 line-clamp-2 text-sm text-gray-500">
                  {project.description}
                </p>
              )}
              {project.repository_url && (
                <div className="mt-3 flex items-center gap-1 text-xs text-primary-600">
                  <ExternalLink className="h-3 w-3" />
                  <span className="truncate">{project.repository_url}</span>
                </div>
              )}
              {sbomMap[project.id] && sbomMap[project.id].total > 0 && (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-semibold text-red-700">
                    <AlertCircle className="h-3 w-3" />
                    {sbomMap[project.id].actionable} actionable
                  </span>
                  <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2 py-0.5 text-xs font-semibold text-green-700">
                    <CheckCircle className="h-3 w-3" />
                    {sbomMap[project.id].not_actionable} ok
                  </span>
                  <span className="text-xs text-gray-400">
                    {sbomMap[project.id].total} pkgs
                  </span>
                </div>
              )}
              <p className="mt-3 text-xs text-gray-400">
                Created {new Date(project.created_at).toLocaleDateString()}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* ---- Delete Confirmation Modal ---- */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
          <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
            <h2 className="mb-2 text-xl font-bold text-gray-900">Delete Project</h2>
            <p className="mb-1 text-sm text-gray-600">
              Are you sure you want to delete <span className="font-semibold text-gray-900">{deleteTarget.name}</span>?
            </p>
            <p className="mb-5 text-sm text-red-600">
              This will permanently delete all scans, findings, and reports associated with this project.
            </p>

            {deleteError && (
              <div className="mb-3 rounded-lg bg-red-50 p-3 text-sm text-red-700">{deleteError}</div>
            )}

            <div className="flex justify-end gap-3">
              <button
                onClick={() => { setDeleteTarget(null); setDeleteError(''); }}
                disabled={deleting}
                className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700
                           transition-colors hover:bg-gray-50 disabled:opacity-60"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                disabled={deleting}
                className="rounded-lg bg-red-600 px-4 py-2 text-sm font-semibold text-white
                           transition-colors hover:bg-red-700 disabled:opacity-60"
              >
                {deleting ? 'Deleting...' : 'Delete Project'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Create Modal ---- */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
          <div className="w-full max-w-lg rounded-xl bg-white p-6 shadow-xl">
            <h2 className="mb-4 text-xl font-bold text-gray-900">New Project</h2>

            {formError && (
              <div className="mb-3 rounded-lg bg-red-50 p-3 text-sm text-red-700">{formError}</div>
            )}

            <form onSubmit={handleCreate} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Project Name <span className="text-red-500">*</span>
                </label>
                <input
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                             focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Repository URL
                </label>
                <input
                  value={formRepoUrl}
                  onChange={(e) => setFormRepoUrl(e.target.value)}
                  placeholder="https://github.com/org/repo"
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                             focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Description
                </label>
                <textarea
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  rows={3}
                  className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                             focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setShowModal(false)}
                  className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700
                             transition-colors hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className="rounded-lg bg-primary-600 px-4 py-2 text-sm font-semibold text-white
                             transition-colors hover:bg-primary-700 disabled:opacity-60"
                >
                  {submitting ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
