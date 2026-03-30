import { useEffect, useState, useCallback } from 'react';
import { ChevronDown, ChevronUp, Filter, CheckSquare } from 'lucide-react';
import { getFindings, updateFinding, bulkUpdateFindings } from '../api/findings';
import { getProjects } from '../api/projects';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
import FindingCloseModal from '../components/FindingCloseModal';

/* ---------- Types ---------- */

interface Finding {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  tool_name: string;
  file_path: string | null;
  line_number: number | null;
  status: string;
  remediation: string | null;
  raw_data: Record<string, unknown> | null;
  assigned_to: string | null;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
  created_at: string;
}

interface Project {
  id: string;
  name: string;
}

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
const STATUSES = ['open', 'in_progress', 'resolved', 'false_positive', 'accepted'] as const;
const TOOLS = ['trivy', 'gitleaks', 'semgrep', 'kubescape', 'zap', 'burpsuite', 'nessus', 'sonarqube'] as const;

/* ---------- Page ---------- */

export default function Findings() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  /* Pagination */
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);

  /* Filters */
  const [filterSeverity, setFilterSeverity] = useState('');
  const [filterTool, setFilterTool] = useState('');
  const [filterStatus, setFilterStatus] = useState('');
  const [filterProject, setFilterProject] = useState('');

  /* Selection & bulk */
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkUpdating, setBulkUpdating] = useState(false);
  const [closingFinding, setClosingFinding] = useState<Finding | null>(null);

  /* Expanded row */
  const [expandedId, setExpandedId] = useState<string | null>(null);

  /* Fetch projects (once) */
  useEffect(() => {
    getProjects()
      .then((res) => setProjects(res.items ?? res.results ?? res))
      .catch(() => {});
  }, []);

  /* Fetch findings */
  const fetchFindings = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const params: Record<string, string | number> = { page, page_size: pageSize };
      if (filterSeverity) params.severity = filterSeverity;
      if (filterTool) params.tool_name = filterTool;
      if (filterStatus) params.status = filterStatus;
      if (filterProject) params.project_id = filterProject;

      const res = await getFindings(params);
      const items = res.items ?? res.results ?? res;
      setFindings(Array.isArray(items) ? items : []);
      setTotal(res.total ?? res.count ?? items.length ?? 0);
    } catch {
      setError('Failed to load findings.');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, filterSeverity, filterTool, filterStatus, filterProject]);

  useEffect(() => {
    fetchFindings();
  }, [fetchFindings]);

  /* Selection helpers */
  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === findings.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(findings.map((f) => f.id)));
    }
  };

  /* Bulk update */
  const handleBulkUpdate = async () => {
    if (!bulkStatus || selected.size === 0) return;
    setBulkUpdating(true);
    try {
      await bulkUpdateFindings({
        ids: Array.from(selected),
        status: bulkStatus,
      });
      setSelected(new Set());
      setBulkStatus('');
      fetchFindings();
    } catch {
      setError('Bulk update failed.');
    } finally {
      setBulkUpdating(false);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="space-y-6">
      {/* ---- Header ---- */}
      <h1 className="text-2xl font-bold text-gray-900">Security Findings</h1>

      {error && (
        <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {/* ---- Filter bar ---- */}
      <div className="flex flex-wrap items-center gap-3">
        <Filter className="h-4 w-4 text-gray-400" />

        <select
          value={filterSeverity}
          onChange={(e) => { setFilterSeverity(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm
                     focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>

        <select
          value={filterTool}
          onChange={(e) => { setFilterTool(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm
                     focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Tools</option>
          {TOOLS.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>

        <select
          value={filterStatus}
          onChange={(e) => { setFilterStatus(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm
                     focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Statuses</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
          ))}
        </select>

        <select
          value={filterProject}
          onChange={(e) => { setFilterProject(e.target.value); setPage(1); }}
          className="rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm
                     focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500"
        >
          <option value="">All Projects</option>
          {projects.map((p) => (
            <option key={p.id} value={p.id}>{p.name}</option>
          ))}
        </select>
      </div>

      {/* ---- Bulk actions ---- */}
      {selected.size > 0 && (
        <div className="flex items-center gap-3 rounded-lg bg-primary-50 px-4 py-3">
          <CheckSquare className="h-4 w-4 text-primary-600" />
          <span className="text-sm font-medium text-primary-700">
            {selected.size} selected
          </span>
          <select
            value={bulkStatus}
            onChange={(e) => setBulkStatus(e.target.value)}
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm shadow-sm"
          >
            <option value="">Set status...</option>
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <button
            onClick={handleBulkUpdate}
            disabled={!bulkStatus || bulkUpdating}
            className="rounded-lg bg-primary-600 px-3 py-1.5 text-sm font-semibold text-white
                       transition-colors hover:bg-primary-700 disabled:opacity-60"
          >
            {bulkUpdating ? 'Updating...' : 'Apply'}
          </button>
        </div>
      )}

      {/* ---- Table ---- */}
      <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white shadow-sm">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3">
                <input
                  type="checkbox"
                  checked={findings.length > 0 && selected.size === findings.length}
                  onChange={toggleAll}
                  className="h-4 w-4 rounded border-gray-300 text-primary-600
                             focus:ring-primary-500"
                />
              </th>
              {['Severity', 'Title', 'Tool', 'File', 'Status', 'Assigned To', 'Date', ''].map(
                (h) => (
                  <th
                    key={h}
                    className="px-6 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500"
                  >
                    {h}
                  </th>
                )
              )}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {loading
              ? Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i}>
                    {Array.from({ length: 9 }).map((__, j) => (
                      <td key={j} className="px-6 py-4">
                        <div className="h-4 w-3/4 animate-pulse rounded bg-gray-200" />
                      </td>
                    ))}
                  </tr>
                ))
              : findings.length === 0
                ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-12 text-center text-sm text-gray-500">
                      No findings match the current filters.
                    </td>
                  </tr>
                )
                : findings.map((f) => (
                  <>
                    <tr
                      key={f.id}
                      className="cursor-pointer hover:bg-gray-50"
                      onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                    >
                      <td className="px-4 py-4" onClick={(e) => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selected.has(f.id)}
                          onChange={() => toggleSelect(f.id)}
                          className="h-4 w-4 rounded border-gray-300 text-primary-600
                                     focus:ring-primary-500"
                        />
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="max-w-xs truncate px-6 py-4 text-sm text-gray-700">
                        {f.title}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {f.tool_name}
                      </td>
                      <td className="max-w-[180px] truncate px-6 py-4 text-sm text-gray-500">
                        {f.file_path || '--'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4">
                        <StatusBadge status={f.status} />
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {f.assigned_to || '--'}
                      </td>
                      <td className="whitespace-nowrap px-6 py-4 text-sm text-gray-500">
                        {new Date(f.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-4 py-4 text-gray-400">
                        {expandedId === f.id ? (
                          <ChevronUp className="h-4 w-4" />
                        ) : (
                          <ChevronDown className="h-4 w-4" />
                        )}
                      </td>
                    </tr>

                    {/* ---- Expanded detail ---- */}
                    {expandedId === f.id && (
                      <tr key={`${f.id}-detail`}>
                        <td colSpan={9} className="bg-gray-50 px-8 py-6">
                          <div className="space-y-4">
                            {f.description && (
                              <div>
                                <h4 className="text-sm font-semibold text-gray-700">Description</h4>
                                <p className="mt-1 text-sm text-gray-600 whitespace-pre-wrap">{f.description}</p>
                              </div>
                            )}
                            {f.remediation && (
                              <div>
                                <h4 className="text-sm font-semibold text-gray-700">Remediation</h4>
                                <p className="mt-1 text-sm text-gray-600 whitespace-pre-wrap">{f.remediation}</p>
                              </div>
                            )}
                            {f.file_path && (
                              <div>
                                <h4 className="text-sm font-semibold text-gray-700">Location</h4>
                                <p className="mt-1 font-mono text-sm text-gray-600">
                                  {f.file_path}
                                  {f.line_number ? `:${f.line_number}` : ''}
                                </p>
                              </div>
                            )}
                            {f.raw_data && (
                              <div>
                                <h4 className="text-sm font-semibold text-gray-700">Raw Data</h4>
                                <pre className="mt-1 max-h-48 overflow-auto rounded-lg bg-gray-900 p-4 text-xs text-green-400">
                                  {JSON.stringify(f.raw_data, null, 2)}
                                </pre>
                              </div>
                            )}
                            {/* Close / Reopen actions */}
                            <div className="flex items-center gap-3 flex-wrap">
                              <span className="text-sm font-medium text-gray-700">Actions:</span>
                              <button onClick={() => setClosingFinding(f)}
                                className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-colors ${
                                  ['resolved', 'accepted', 'false_positive'].includes(f.status)
                                    ? 'bg-amber-50 text-amber-700 hover:bg-amber-100 border border-amber-200'
                                    : 'bg-green-50 text-green-700 hover:bg-green-100 border border-green-200'
                                }`}>
                                {['resolved', 'accepted', 'false_positive'].includes(f.status) ? 'View / Reopen' : 'Close Finding'}
                              </button>
                              {f.status === 'open' && (
                                <button onClick={async () => {
                                  try {
                                    await updateFinding(f.id, { status: 'in_progress' });
                                    setFindings(prev => prev.map(x => x.id === f.id ? { ...x, status: 'in_progress' } : x));
                                  } catch { setError('Failed to update.'); }
                                }} className="rounded-lg bg-yellow-50 border border-yellow-200 px-3 py-1.5 text-xs font-semibold text-yellow-700 hover:bg-yellow-100">
                                  Mark In Progress
                                </button>
                              )}
                              {f.close_reason && (
                                <span className="text-xs text-gray-400">
                                  {f.close_reason.replace(/_/g, ' ')}
                                  {f.closed_at && ` ${new Date(f.closed_at).toLocaleDateString()}`}
                                </span>
                              )}
                              {f.justification && (
                                <span className="text-xs text-gray-500 italic max-w-xs truncate" title={f.justification}>
                                  "{f.justification}"
                                </span>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                ))}
          </tbody>
        </table>
      </div>

      {/* ---- Pagination ---- */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm text-gray-500">
          <span>Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => { setPageSize(Number(e.target.value)); setPage(1); }}
            className="rounded border border-gray-300 px-2 py-1 text-sm"
          >
            {[10, 20, 50, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <span className="ml-4">
            Showing {Math.min((page - 1) * pageSize + 1, total)}–{Math.min(page * pageSize, total)} of {total}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700
                       transition-colors hover:bg-gray-50 disabled:opacity-40"
          >
            Previous
          </button>
          <span className="text-sm text-gray-600">
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded-lg border border-gray-300 px-3 py-1.5 text-sm font-medium text-gray-700
                       transition-colors hover:bg-gray-50 disabled:opacity-40"
          >
            Next
          </button>
        </div>
      </div>

      {/* Close modal */}
      {closingFinding && (
        <FindingCloseModal
          finding={closingFinding as any}
          onClose={() => setClosingFinding(null)}
          onUpdated={(updated: any) => {
            setFindings(prev => prev.map(f => f.id === updated.id ? { ...f, ...updated } : f));
          }}
        />
      )}
    </div>
  );
}
