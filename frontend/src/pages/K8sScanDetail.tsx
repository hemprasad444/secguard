import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, RefreshCw, Server, Shield, AlertTriangle,
  ChevronDown, ChevronUp, Search, Info, ExternalLink,
  Lock, FileText, Globe, Box, Layers,
} from 'lucide-react';
import { getScan, getScanFindings } from '../api/scans';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
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

const SEV_BADGE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-50', text: 'text-red-700', border: 'border-red-200' },
  high:     { bg: 'bg-orange-50', text: 'text-orange-700', border: 'border-orange-200' },
  medium:   { bg: 'bg-yellow-50', text: 'text-yellow-700', border: 'border-yellow-200' },
  low:      { bg: 'bg-blue-50', text: 'text-blue-700', border: 'border-blue-200' },
  info:     { bg: 'bg-gray-50', text: 'text-gray-600', border: 'border-gray-200' },
};

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
    <div className="space-y-6">
      {/* Breadcrumb */}
      <button onClick={() => navigate(`/projects/${projectId}/scan-types/k8s`)}
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800">
        <ArrowLeft className="h-4 w-4" /> Back to K8s Scans
      </button>

      {/* Header */}
      <div className="rounded-2xl border border-green-200 bg-gradient-to-r from-green-50 to-emerald-50 px-6 py-5">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-green-100">
              <Server className="h-6 w-6 text-green-600" />
            </div>
            <div>
              <div className="flex items-center gap-3">
                <h1 className="text-xl font-bold text-gray-900">K8s Security - {toolLabel}</h1>
                <StatusBadge status={scan.status} />
              </div>
              <p className="mt-1 text-sm text-gray-500">
                Scanned {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
              </p>
              {/* Top-level stats */}
              <div className="mt-3 flex flex-wrap items-center gap-3">
                <div className="rounded-lg border border-gray-200 bg-white px-3 py-1.5">
                  <span className="text-lg font-bold text-gray-800">{filtered.length}</span>
                  <span className="ml-1.5 text-xs text-gray-500">Findings</span>
                </div>
                <div className="rounded-lg border border-gray-200 bg-white px-3 py-1.5">
                  <span className="text-lg font-bold text-gray-800">{groups.length}</span>
                  <span className="ml-1.5 text-xs text-gray-500">Resources</span>
                </div>
                <div className="rounded-lg border border-gray-200 bg-white px-3 py-1.5">
                  <span className="text-lg font-bold text-gray-800">{uniqueNamespaces}</span>
                  <span className="ml-1.5 text-xs text-gray-500">Namespaces</span>
                </div>
                {sevCounts.critical > 0 && (
                  <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5">
                    <span className="text-lg font-bold text-red-600">{sevCounts.critical}</span>
                    <span className="ml-1.5 text-xs text-red-500">Critical</span>
                  </div>
                )}
                {sevCounts.high > 0 && (
                  <div className="rounded-lg border border-orange-200 bg-orange-50 px-3 py-1.5">
                    <span className="text-lg font-bold text-orange-600">{sevCounts.high}</span>
                    <span className="ml-1.5 text-xs text-orange-500">High</span>
                  </div>
                )}
                {sevCounts.medium > 0 && (
                  <div className="rounded-lg border border-yellow-200 bg-yellow-50 px-3 py-1.5">
                    <span className="text-lg font-bold text-yellow-600">{sevCounts.medium}</span>
                    <span className="ml-1.5 text-xs text-yellow-500">Medium</span>
                  </div>
                )}
                {sevCounts.low > 0 && (
                  <div className="rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5">
                    <span className="text-lg font-bold text-blue-600">{sevCounts.low}</span>
                    <span className="ml-1.5 text-xs text-blue-500">Low</span>
                  </div>
                )}
                <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-1.5">
                  <span className="text-lg font-bold text-red-600">{openCount}</span>
                  <span className="ml-1.5 text-xs text-red-500">Open</span>
                </div>
                <div className="rounded-lg border border-green-200 bg-green-50 px-3 py-1.5">
                  <span className="text-lg font-bold text-green-600">{closedCount}</span>
                  <span className="ml-1.5 text-xs text-green-500">Closed</span>
                </div>
              </div>
            </div>
          </div>
          <button onClick={downloadReport} disabled={findings.length === 0}
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-4 py-2 text-sm font-medium text-gray-600 shadow-sm hover:bg-gray-50 disabled:opacity-40">
            <Download className="h-4 w-4" /> Export XLSX
          </button>
        </div>
      </div>

      {/* Filters bar */}
      <div className="flex flex-wrap items-center gap-2 rounded-xl border border-gray-200 bg-white px-4 py-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-400" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search resources, controls, descriptions, remediation…"
            className="w-full rounded-lg border border-gray-200 py-2 pl-9 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-green-400" />
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Status ({findings.length})</option>
          <option value="open">Open ({openCount})</option>
          <option value="closed">Closed ({closedCount})</option>
        </select>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Severities ({filtered.length})</option>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({sevCounts[s]})</option>
          ))}
        </select>
        <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Resource Kinds</option>
          {allKinds.map(k => <option key={k} value={k}>{k}</option>)}
        </select>
        {allNamespaces.length > 0 && (
          <select value={nsFilter} onChange={e => setNsFilter(e.target.value)}
            className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600 focus:outline-none">
            <option value="all">All Namespaces</option>
            {allNamespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
        )}
        <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Categories</option>
          {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="ml-auto flex items-center gap-1">
          <button onClick={expandAll} className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100">Expand All</button>
          <button onClick={collapseAll} className="rounded px-2 py-1 text-xs text-gray-500 hover:bg-gray-100">Collapse All</button>
        </div>
      </div>

      {/* Resource list */}
      {groups.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-gray-200 py-16 text-center text-sm text-gray-400">
          {findings.length === 0 ? 'No findings for this scan.' : 'No findings match the selected filters.'}
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map(g => {
            const key = `${g.kind}/${g.name}/${g.namespace}`;
            const isOpen = expanded.has(key);
            const KindIcon = KIND_ICONS[g.kind] ?? Box;
            const worstSev = g.critical > 0 ? 'critical' : g.high > 0 ? 'high' : g.medium > 0 ? 'medium' : g.low > 0 ? 'low' : 'info';
            const colors = SEV_BADGE_COLORS[worstSev] ?? SEV_BADGE_COLORS.info;

            return (
              <div key={key} className={`rounded-xl border ${colors.border} bg-white overflow-hidden shadow-sm`}>
                {/* Resource header */}
                <button onClick={() => toggle(key)}
                  className="flex w-full items-center gap-3 px-5 py-4 text-left hover:bg-gray-50/50 transition-colors">
                  <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${colors.bg}`}>
                    <KindIcon className={`h-5 w-5 ${colors.text}`} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="rounded bg-slate-200 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-600">{g.kind}</span>
                      <span className="text-base font-semibold text-gray-800 truncate">{g.name}</span>
                      {g.namespace && (
                        <span className="rounded bg-blue-50 border border-blue-100 px-2 py-0.5 text-[10px] font-medium text-blue-600">ns: {g.namespace}</span>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-gray-400">{g.findings.length} finding{g.findings.length !== 1 ? 's' : ''}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {g.critical > 0 && <span className="rounded-full bg-red-100 px-2.5 py-1 text-xs font-bold text-red-700">{g.critical} Critical</span>}
                    {g.high > 0 && <span className="rounded-full bg-orange-100 px-2.5 py-1 text-xs font-bold text-orange-700">{g.high} High</span>}
                    {g.medium > 0 && <span className="rounded-full bg-yellow-100 px-2.5 py-1 text-xs font-bold text-yellow-700">{g.medium} Med</span>}
                    {g.low > 0 && <span className="rounded-full bg-blue-100 px-2.5 py-1 text-xs font-bold text-blue-700">{g.low} Low</span>}
                    {isOpen ? <ChevronUp className="h-5 w-5 text-gray-400" /> : <ChevronDown className="h-5 w-5 text-gray-400" />}
                  </div>
                </button>

                {/* Findings list */}
                {isOpen && (
                  <div className="border-t divide-y divide-gray-100">
                    {g.findings.map(f => {
                      const r = rd(f);
                      const controlId = r.controlID ?? r.ID ?? '';
                      const category = r.category ?? r.Type ?? '';
                      const refUrl = r.PrimaryURL;
                      const references = r.References as string[] | undefined;
                      const message = r.Message ?? '';
                      const resolution = f.remediation ?? r.Resolution ?? '';
                      const causeLines = r.CauseMetadata?.Code?.Lines as Array<{ Number: number; Content: string; IsCause: boolean }> | undefined;

                      return (
                        <div key={f.id} className="px-5 py-4 space-y-3">
                          {/* Finding header */}
                          <div className="flex items-start justify-between gap-3">
                            <div className="flex items-start gap-2 flex-wrap">
                              <SeverityBadge severity={f.severity} />
                              {controlId && (
                                <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs font-semibold text-gray-700">{controlId}</span>
                              )}
                              {category && (
                                <span className="rounded bg-indigo-50 border border-indigo-100 px-2 py-0.5 text-[10px] font-medium text-indigo-600">{category}</span>
                              )}
                            </div>
                            {['resolved', 'accepted', 'false_positive'].includes(f.status) ? (
                              <button onClick={(e) => { e.stopPropagation(); setClosingFinding({ ...f, tool_name: scan.tool_name }); }}
                                className="inline-flex items-center gap-1 rounded-lg bg-green-100 border border-green-200 px-2.5 py-1 text-xs font-semibold text-green-700 hover:bg-green-200 cursor-pointer transition-colors">
                                {f.status === 'resolved' ? 'Closed' : f.status.replace(/_/g, ' ')}
                              </button>
                            ) : (
                              <button onClick={(e) => { e.stopPropagation(); setClosingFinding({ ...f, tool_name: scan.tool_name }); }}
                                className="inline-flex items-center gap-1 rounded-lg bg-red-50 border border-red-200 px-2.5 py-1 text-xs font-semibold text-red-600 hover:bg-red-100 cursor-pointer transition-colors">
                                Close
                              </button>
                            )}
                          </div>

                          {/* Title */}
                          <h3 className="text-sm font-semibold text-gray-900">{f.title}</h3>

                          {/* Description */}
                          {f.description && (
                            <p className="text-sm text-gray-600 leading-relaxed">{f.description}</p>
                          )}

                          {/* Specific failure message */}
                          {message && message !== f.description && (
                            <div className="flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
                              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-500" />
                              <div>
                                <p className="text-xs font-semibold text-amber-800">Issue Detail</p>
                                <p className="mt-0.5 text-sm text-amber-700">{message}</p>
                              </div>
                            </div>
                          )}

                          {/* Affected configuration code (Trivy) */}
                          {causeLines && causeLines.length > 0 && (
                            <div className="rounded-lg border border-gray-200 bg-gray-900 overflow-hidden">
                              <div className="flex items-center justify-between px-4 py-2 bg-gray-800">
                                <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Affected Configuration</span>
                                <span className="text-[10px] text-gray-500">
                                  Lines {causeLines[0]?.Number}–{causeLines[causeLines.length - 1]?.Number}
                                </span>
                              </div>
                              <pre className="px-4 py-3 text-xs leading-6 overflow-x-auto">
                                {causeLines.filter(l => l.Content !== undefined).map((l, i) => (
                                  <div key={i} className={`flex ${l.IsCause ? 'bg-red-900/30 -mx-4 px-4' : ''}`}>
                                    <span className="w-10 shrink-0 text-right text-gray-500 select-none pr-4">{l.Number}</span>
                                    <span className={l.IsCause ? 'text-red-300' : 'text-gray-400'}>{l.Content}</span>
                                  </div>
                                ))}
                              </pre>
                            </div>
                          )}

                          {/* Failed paths & fix paths (Kubescape) */}
                          {!causeLines && ((r.failedPaths as string[])?.length > 0 || (r.fixPaths as Array<{path: string; value: string}>)?.length > 0) && (
                            <div className="rounded-lg border border-gray-200 bg-gray-900 overflow-hidden">
                              <div className="px-4 py-2 bg-gray-800">
                                <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Affected Paths</span>
                              </div>
                              <div className="px-4 py-3 space-y-2">
                                {(r.failedPaths as string[])?.length > 0 && (
                                  <div>
                                    <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Failed:</span>
                                    {(r.failedPaths as string[]).map((p, i) => (
                                      <div key={i} className="mt-1 font-mono text-xs text-red-300">{p}</div>
                                    ))}
                                  </div>
                                )}
                                {(r.fixPaths as Array<{path: string; value: string}>)?.length > 0 && (
                                  <div className="mt-2">
                                    <span className="text-[10px] font-semibold text-green-400 uppercase tracking-wider">Fix:</span>
                                    {(r.fixPaths as Array<{path: string; value: string}>).map((fix, i) => (
                                      <div key={i} className="mt-1 font-mono text-xs">
                                        <span className="text-green-300">{fix.path}</span>
                                        {fix.value && <span className="text-gray-500"> = </span>}
                                        {fix.value && <span className="text-green-200">{fix.value}</span>}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Remediation */}
                          {resolution && (
                            <div className="flex items-start gap-3 rounded-lg border border-green-200 bg-green-50 px-4 py-3">
                              <Info className="mt-0.5 h-4 w-4 shrink-0 text-green-600" />
                              <div>
                                <p className="text-xs font-bold text-green-800 uppercase tracking-wide">Remediation</p>
                                <p className="mt-1 text-sm text-green-700 leading-relaxed">{resolution}</p>
                              </div>
                            </div>
                          )}

                          {/* References */}
                          {(refUrl || (references && references.length > 0)) && (
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">References:</span>
                              {refUrl && (
                                <a href={refUrl} target="_blank" rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 rounded bg-blue-50 border border-blue-100 px-2 py-0.5 text-xs text-blue-600 hover:bg-blue-100 hover:underline">
                                  <ExternalLink className="h-3 w-3" /> {new URL(refUrl).hostname}
                                </a>
                              )}
                              {references?.filter(r => r !== refUrl).map((ref, i) => (
                                <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 rounded bg-gray-50 border border-gray-200 px-2 py-0.5 text-xs text-gray-500 hover:bg-gray-100 hover:underline">
                                  <ExternalLink className="h-3 w-3" /> {(() => { try { return new URL(ref).hostname; } catch { return ref; } })()}
                                </a>
                              ))}
                            </div>
                          )}
                        </div>
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
