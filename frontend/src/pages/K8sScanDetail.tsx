import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, RefreshCw, Server, Shield,
  ChevronDown, ChevronRight, Search, ExternalLink,
  Lock, FileText, Globe, Box, Layers,
} from 'lucide-react';
import { getScan, getScanFindings } from '../api/scans';
import FindingCloseModal from '../components/FindingCloseModal';

/* ------------------------------------------------------------------ */
/* Types                                                                 */
/* ------------------------------------------------------------------ */
interface Scan {
  id: string;
  tool_name: string;
  scan_type: string;
  status: string;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  error_message?: string | null;
  config_json?: Record<string, any> | null;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  tool_name: string;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
}

/* ------------------------------------------------------------------ */
/* Constants                                                              */
/* ------------------------------------------------------------------ */
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const KIND_ICONS: Record<string, typeof Box> = {
  Deployment: Layers, StatefulSet: Layers, DaemonSet: Layers, ReplicaSet: Layers,
  Pod: Box, ConfigMap: FileText, ClusterRole: Shield, Role: Shield,
  ServiceAccount: Lock, Namespace: Globe, Node: Server,
};

function sevDot(sev: string) {
  return sev === 'critical' ? 'bg-red-500'
    : sev === 'high' ? 'bg-amber-500'
    : sev === 'medium' ? 'bg-yellow-400'
    : sev === 'low' ? 'bg-blue-400' : 'bg-gray-300';
}
function sevText(sev: string) {
  return sev === 'critical' ? 'text-red-700'
    : sev === 'high' ? 'text-amber-700'
    : sev === 'medium' ? 'text-yellow-700'
    : sev === 'low' ? 'text-blue-700' : 'text-gray-500';
}

/* ------------------------------------------------------------------ */
/* Main Page                                                              */
/* ------------------------------------------------------------------ */
export default function K8sScanDetail() {
  const { projectId, scanId } = useParams<{ projectId: string; scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  /* Filters */
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [nsFilter, setNsFilter] = useState('all');
  const [catFilter, setCatFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [closingFinding, setClosingFinding] = useState<Finding | null>(null);

  useEffect(() => {
    if (!scanId) return;
    (async () => {
      setLoading(true);
      try {
        const s: Scan = await getScan(scanId);
        setScan(s);
        const data = await getScanFindings(scanId, 1, 1000);
        const items: Finding[] = Array.isArray(data) ? data : (data.items ?? data.results ?? []);
        setFindings(items);
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [scanId]);

  if (loading || !scan) {
    return (
      <div className="flex h-64 items-center justify-center">
        <RefreshCw className="h-6 w-6 animate-spin text-gray-400" />
      </div>
    );
  }

  /* Helpers */
  const rd = (f: Finding) => f.raw_data ?? {};

  /* Unique filter options */
  const allKinds = [...new Set(findings.map(f => rd(f).k8s_resource_kind).filter(Boolean))].sort();
  const allNamespaces = [...new Set(findings.map(f => rd(f).k8s_namespace).filter(Boolean))].sort();
  const allCategories = [...new Set(findings.map(f => rd(f).category ?? rd(f).Type).filter(Boolean))].sort();

  /* Status counts (before filtering) */
  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const openCount = findings.filter(f => !closedStatuses.includes(f.status)).length;
  const closedCount = findings.filter(f => closedStatuses.includes(f.status)).length;

  /* Apply filters */
  const filtered = findings.filter(f => {
    if (statusFilter === 'open' && closedStatuses.includes(f.status)) return false;
    if (statusFilter === 'closed' && !closedStatuses.includes(f.status)) return false;
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
    if (kindFilter !== 'all' && rd(f).k8s_resource_kind !== kindFilter) return false;
    if (nsFilter !== 'all' && rd(f).k8s_namespace !== nsFilter) return false;
    if (catFilter !== 'all' && (rd(f).category ?? rd(f).Type) !== catFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const r = rd(f);
      if (
        !f.title.toLowerCase().includes(q) &&
        !(r.k8s_resource_name ?? '').toLowerCase().includes(q) &&
        !(r.k8s_resource_kind ?? '').toLowerCase().includes(q) &&
        !(r.controlID ?? r.ID ?? '').toLowerCase().includes(q) &&
        !(f.description ?? '').toLowerCase().includes(q) &&
        !(f.remediation ?? r.Resolution ?? '').toLowerCase().includes(q)
      ) return false;
    }
    return true;
  });

  /* Group by resource */
  type ResourceGroup = {
    kind: string; name: string; namespace: string; findings: Finding[];
    critical: number; high: number; medium: number; low: number; info: number;
  };
  const groupMap = new Map<string, ResourceGroup>();
  for (const f of filtered) {
    const key = `${rd(f).k8s_resource_kind ?? 'Unknown'}/${rd(f).k8s_resource_name ?? f.title}/${rd(f).k8s_namespace ?? ''}`;
    if (!groupMap.has(key)) {
      groupMap.set(key, {
        kind: rd(f).k8s_resource_kind ?? 'Unknown',
        name: rd(f).k8s_resource_name ?? f.title,
        namespace: rd(f).k8s_namespace ?? '',
        findings: [], critical: 0, high: 0, medium: 0, low: 0, info: 0,
      });
    }
    const g = groupMap.get(key)!;
    g.findings.push(f);
    const s = f.severity as keyof Pick<ResourceGroup, 'critical'|'high'|'medium'|'low'|'info'>;
    if (s in g) (g as any)[s]++;
  }

  const groups = [...groupMap.values()].sort((a, b) =>
    b.critical - a.critical || b.high - a.high || b.medium - a.medium || b.findings.length - a.findings.length
  );

  for (const g of groups) {
    g.findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  }

  /* Global severity counts */
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of filtered) {
    const s = f.severity as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  const uniqueNamespaces = new Set(filtered.map(f => rd(f).k8s_namespace).filter(Boolean)).size;

  const toggle = (key: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const expandAll = () => {
    const keys = groups.map(g => `${g.kind}/${g.name}/${g.namespace}`);
    setExpanded(new Set(keys));
  };

  const collapseAll = () => setExpanded(new Set());

  /* Download */
  const downloadReport = () => {
    const rows: Record<string, string>[] = findings.map(f => {
      const r = f.raw_data ?? {};
      return {
        'Resource Kind': r.k8s_resource_kind ?? '',
        'Resource Name': r.k8s_resource_name ?? '',
        'Namespace': r.k8s_namespace ?? '',
        'Severity': f.severity.charAt(0).toUpperCase() + f.severity.slice(1),
        'Control ID': r.controlID ?? r.ID ?? '',
        'Category': r.category ?? r.Type ?? '',
        'Title': f.title,
        'Description': f.description ?? '',
        'Remediation': f.remediation ?? r.Resolution ?? '',
        'Message': r.Message ?? '',
        'Reference': r.PrimaryURL ?? '',
        'Tool': scan.tool_name,
      };
    });
    const ws = XLSX.utils.json_to_sheet(rows);
    ws['!cols'] = [14, 22, 14, 10, 12, 24, 30, 50, 50, 50, 40, 10].map(w => ({ wch: w }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'K8s Findings');
    XLSX.writeFile(wb, `K8s-Security-${scan.tool_name}-${scan.id.slice(0, 8)}.xlsx`);
  };

  const toolLabel = scan.tool_name.charAt(0).toUpperCase() + scan.tool_name.slice(1);

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <button onClick={() => navigate(`/projects/${projectId}/scan-types/k8s`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to K8s Scans
      </button>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <Server className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-gray-400">K8s Security</p>
            <h1 className="mt-0.5 text-lg font-semibold text-gray-900">{toolLabel}</h1>
            <p className="mt-1 text-xs text-gray-500">
              {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : ''}
            </p>
          </div>
        </div>
        <button onClick={downloadReport} disabled={findings.length === 0}
          className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 disabled:opacity-40 transition-colors">
          <Download className="h-4 w-4" /> Export
        </button>
      </div>

      {/* Stats strip */}
      {findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{filtered.length}</span> findings
          </span>
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{groups.length}</span> resources
          </span>
          {uniqueNamespaces > 0 && (
            <span className="text-gray-500">
              <span className="font-semibold text-gray-900 tabular-nums">{uniqueNamespaces}</span> namespaces
            </span>
          )}
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> open
          </span>
          {closedCount > 0 && (
            <span className="text-gray-500">
              <span className="font-semibold text-gray-900 tabular-nums">{closedCount}</span> closed
            </span>
          )}
          {sevCounts.critical > 0 && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
              <span className="font-semibold text-gray-900 tabular-nums">{sevCounts.critical}</span> critical
            </span>
          )}
          {sevCounts.high > 0 && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
              <span className="font-semibold text-gray-900 tabular-nums">{sevCounts.high}</span> high
            </span>
          )}
        </div>
      )}

      {/* Toolbar — inline, no panel wrapper */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search resources, controls, descriptions…"
            className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400" />
        </div>
        <div className="inline-flex rounded-md border border-gray-200 bg-white p-0.5">
          {[
            { k: 'all', label: `All ${findings.length}` },
            { k: 'open', label: `Open ${openCount}` },
            { k: 'closed', label: `Closed ${closedCount}` },
          ].map(s => (
            <button key={s.k} onClick={() => setStatusFilter(s.k)}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                statusFilter === s.k ? 'bg-gray-900 text-white' : 'text-gray-600 hover:text-gray-900'
              }`}>
              {s.label}
            </button>
          ))}
        </div>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
          <option value="all">All severities</option>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({sevCounts[s]})</option>
          ))}
        </select>
        {allKinds.length > 1 && (
          <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All kinds</option>
            {allKinds.map(k => <option key={k} value={k}>{k}</option>)}
          </select>
        )}
        {allNamespaces.length > 1 && (
          <select value={nsFilter} onChange={e => setNsFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All namespaces</option>
            {allNamespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
        )}
        {allCategories.length > 1 && (
          <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All categories</option>
            {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        )}
        <div className="ml-auto inline-flex items-center gap-1">
          <button onClick={expandAll} className="rounded px-2 py-1 text-[11px] text-gray-500 hover:text-gray-900 transition-colors">Expand all</button>
          <span className="text-gray-300">·</span>
          <button onClick={collapseAll} className="rounded px-2 py-1 text-[11px] text-gray-500 hover:text-gray-900 transition-colors">Collapse all</button>
        </div>
      </div>

      {/* Resource list */}
      {groups.length === 0 ? (
        <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
          {findings.length === 0 ? 'No findings for this scan.' : 'No findings match the selected filters.'}
        </div>
      ) : (
        <div className="space-y-2">
          {groups.map(g => {
            const key = `${g.kind}/${g.name}/${g.namespace}`;
            const isOpen = expanded.has(key);
            const KindIcon = KIND_ICONS[g.kind] ?? Box;

            return (
              <div key={key} className="rounded-md border border-gray-200 bg-white overflow-hidden">
                {/* Resource header */}
                <button onClick={() => toggle(key)}
                  className="group flex w-full items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-gray-50/60">
                  <KindIcon className="h-4 w-4 shrink-0 text-gray-400" strokeWidth={1.75} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                      <span className="text-[10px] uppercase tracking-wider text-gray-400">{g.kind}</span>
                      <span className="text-sm font-medium text-gray-900 truncate">{g.name}</span>
                      {g.namespace && (
                        <span className="font-mono text-[11px] text-gray-500">ns: {g.namespace}</span>
                      )}
                    </div>
                  </div>
                  {/* Severity counts as compact dots */}
                  <div className="flex items-center gap-2.5 shrink-0 text-[11px]">
                    {g.critical > 0 && (
                      <span className="inline-flex items-center gap-1 text-gray-600">
                        <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                        <span className="tabular-nums font-semibold">{g.critical}</span>
                      </span>
                    )}
                    {g.high > 0 && (
                      <span className="inline-flex items-center gap-1 text-gray-600">
                        <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                        <span className="tabular-nums font-semibold">{g.high}</span>
                      </span>
                    )}
                    {g.medium > 0 && (
                      <span className="inline-flex items-center gap-1 text-gray-500">
                        <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
                        <span className="tabular-nums">{g.medium}</span>
                      </span>
                    )}
                    {g.low > 0 && (
                      <span className="inline-flex items-center gap-1 text-gray-500">
                        <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                        <span className="tabular-nums">{g.low}</span>
                      </span>
                    )}
                    <span className="text-gray-400 tabular-nums">
                      {g.findings.length} finding{g.findings.length !== 1 ? 's' : ''}
                    </span>
                  </div>
                  {isOpen
                    ? <ChevronDown className="h-4 w-4 shrink-0 text-gray-400" />
                    : <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />}
                </button>

                {/* Findings list — compact rows; click navigates to finding detail page */}
                {isOpen && (
                  <div className="border-t border-gray-100 divide-y divide-gray-100">
                    {g.findings.map(f => {
                      const r = rd(f);
                      const controlId = r.controlID ?? r.ID ?? '';
                      const category = r.category ?? r.Type ?? '';
                      const isClosed = closedStatuses.includes(f.status);

                      return (
                        <button
                          key={f.id}
                          onClick={() => navigate(`/projects/${projectId}/k8s/${scan.id}/findings/${f.id}`)}
                          className={`group flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-gray-50/60 ${isClosed ? 'opacity-60' : ''}`}
                        >
                          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevDot(f.severity)}`} />
                          <span className={`w-16 shrink-0 text-[10px] uppercase tracking-wider font-medium ${sevText(f.severity)}`}>{f.severity}</span>
                          {controlId && (
                            <span className="shrink-0 font-mono text-[11px] text-gray-700">{controlId}</span>
                          )}
                          <span className="min-w-0 flex-1 truncate text-[13px] text-gray-800">{f.title}</span>
                          {category && (
                            <span className="hidden md:inline shrink-0 text-[11px] text-gray-500 truncate max-w-[180px]">{category}</span>
                          )}
                          <span
                            onClick={(e) => { e.stopPropagation(); setClosingFinding({ ...f, tool_name: scan.tool_name }); }}
                            role="button"
                            tabIndex={0}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                e.stopPropagation();
                                setClosingFinding({ ...f, tool_name: scan.tool_name });
                              }
                            }}
                            className={`shrink-0 cursor-pointer rounded-md border px-2 py-0.5 text-[11px] font-medium transition-colors ${
                              isClosed
                                ? 'border-gray-200 bg-white text-emerald-700 hover:bg-gray-50'
                                : 'border-gray-200 bg-white text-gray-700 hover:border-gray-900 hover:bg-gray-900 hover:text-white'
                            }`}>
                            {isClosed ? (f.status === 'resolved' ? 'Closed' : f.status.replace(/_/g, ' ')) : 'Close'}
                          </span>
                          <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      {/* Close modal */}
      {closingFinding && (
        <FindingCloseModal
          finding={closingFinding}
          onClose={() => setClosingFinding(null)}
          onUpdated={(updated) => {
            setFindings(prev => prev.map(f => f.id === updated.id ? { ...f, ...updated } : f));
          }}
        />
      )}
    </div>
  );
}
