import { useState } from 'react';
import {
  ChevronDown, ChevronUp, AlertTriangle, Info, Search,
  Shield, Lock, FileText, Globe, Server, Box, Layers,
} from 'lucide-react';
import SeverityBadge from './common/SeverityBadge';

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const KIND_ICONS: Record<string, typeof Box> = {
  Deployment: Layers, StatefulSet: Layers, DaemonSet: Layers, ReplicaSet: Layers,
  Pod: Box, ConfigMap: FileText, ClusterRole: Shield, Role: Shield,
  ServiceAccount: Lock, Namespace: Globe, Node: Server,
};

export default function K8sFindingsView({ findings }: { findings: Finding[] }) {
  const [search, setSearch] = useState('');
  const [kindFilter, setKindFilter] = useState('all');
  const [nsFilter, setNsFilter] = useState('all');
  const [catFilter, setCatFilter] = useState('all');
  const [sevFilter, setSevFilter] = useState('all');
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  if (findings.length === 0)
    return <p className="py-12 text-center text-sm text-gray-400">No findings for this scan.</p>;

  const rd = (f: Finding) => f.raw_data ?? {};
  const resourceKey = (f: Finding) =>
    `${rd(f).k8s_resource_kind ?? 'Unknown'}/${rd(f).k8s_resource_name ?? f.title}/${rd(f).k8s_namespace ?? ''}`;

  const allKinds = [...new Set(findings.map(f => rd(f).k8s_resource_kind).filter(Boolean))].sort();
  const allNamespaces = [...new Set(findings.map(f => rd(f).k8s_namespace).filter(Boolean))].sort();
  const allCategories = [...new Set(findings.map(f => rd(f).category).filter(Boolean))].sort();

  const filtered = findings.filter(f => {
    if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
    if (kindFilter !== 'all' && rd(f).k8s_resource_kind !== kindFilter) return false;
    if (nsFilter !== 'all' && rd(f).k8s_namespace !== nsFilter) return false;
    if (catFilter !== 'all' && rd(f).category !== catFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const r = rd(f);
      if (
        !f.title.toLowerCase().includes(q) &&
        !(r.k8s_resource_name ?? '').toLowerCase().includes(q) &&
        !(r.k8s_resource_kind ?? '').toLowerCase().includes(q) &&
        !(r.controlID ?? r.ID ?? '').toLowerCase().includes(q) &&
        !(f.description ?? '').toLowerCase().includes(q)
      ) return false;
    }
    return true;
  });

  type ResourceGroup = {
    kind: string; name: string; namespace: string; findings: Finding[];
    critical: number; high: number; medium: number; low: number;
  };
  const groupMap = new Map<string, ResourceGroup>();
  for (const f of filtered) {
    const key = resourceKey(f);
    if (!groupMap.has(key)) {
      groupMap.set(key, {
        kind: rd(f).k8s_resource_kind ?? 'Unknown',
        name: rd(f).k8s_resource_name ?? f.title,
        namespace: rd(f).k8s_namespace ?? '',
        findings: [],
        critical: 0, high: 0, medium: 0, low: 0,
      });
    }
    const g = groupMap.get(key)!;
    g.findings.push(f);
    if (f.severity === 'critical') g.critical++;
    else if (f.severity === 'high') g.high++;
    else if (f.severity === 'medium') g.medium++;
    else if (f.severity === 'low') g.low++;
  }

  const groups = [...groupMap.values()].sort((a, b) =>
    b.critical - a.critical || b.high - a.high || b.findings.length - a.findings.length,
  );

  for (const g of groups) {
    g.findings.sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  }

  const toggle = (key: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of filtered) {
    const s = f.severity as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2.5 text-center">
          <p className="text-lg font-bold text-gray-800">{filtered.length}</p>
          <p className="text-xs text-gray-500">Findings</p>
        </div>
        <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2.5 text-center">
          <p className="text-lg font-bold text-gray-800">{groups.length}</p>
          <p className="text-xs text-gray-500">Resources</p>
        </div>
        <div className="rounded-lg border border-red-200 bg-red-50 px-3 py-2.5 text-center">
          <p className="text-lg font-bold text-red-600">{sevCounts.critical}</p>
          <p className="text-xs text-red-500">Critical</p>
        </div>
        <div className="rounded-lg border border-orange-200 bg-orange-50 px-3 py-2.5 text-center">
          <p className="text-lg font-bold text-orange-600">{sevCounts.high}</p>
          <p className="text-xs text-orange-500">High</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-gray-400" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search resources, controls, descriptions…"
            className="w-full rounded-lg border border-gray-200 py-1.5 pl-9 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" />
        </div>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({sevCounts[s as keyof typeof sevCounts]})</option>
          ))}
        </select>
        <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Kinds</option>
          {allKinds.map(k => <option key={k} value={k}>{k}</option>)}
        </select>
        {allNamespaces.length > 0 && (
          <select value={nsFilter} onChange={e => setNsFilter(e.target.value)}
            className="rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-600 focus:outline-none">
            <option value="all">All Namespaces</option>
            {allNamespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
        )}
        <select value={catFilter} onChange={e => setCatFilter(e.target.value)}
          className="rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-600 focus:outline-none">
          <option value="all">All Categories</option>
          {allCategories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {/* Resource groups */}
      <div className="space-y-3">
        {groups.map(g => {
          const key = `${g.kind}/${g.name}/${g.namespace}`;
          const isOpen = expanded.has(key);
          const KindIcon = KIND_ICONS[g.kind] ?? Box;
          return (
            <div key={key} className="rounded-xl border border-gray-200 bg-white overflow-hidden">
              {/* Resource header */}
              <button onClick={() => toggle(key)}
                className="flex w-full items-center gap-3 px-4 py-3 text-left hover:bg-gray-50 transition-colors">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100">
                  <KindIcon className="h-4 w-4 text-slate-600" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-600">{g.kind}</span>
                    <span className="font-semibold text-gray-800 truncate">{g.name}</span>
                    {g.namespace && (
                      <span className="rounded bg-blue-50 px-1.5 py-0.5 text-[10px] font-medium text-blue-600">ns: {g.namespace}</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  {g.critical > 0 && <span className="flex items-center gap-0.5 rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-bold text-red-700">{g.critical} C</span>}
                  {g.high > 0 && <span className="flex items-center gap-0.5 rounded-full bg-orange-100 px-2 py-0.5 text-[10px] font-bold text-orange-700">{g.high} H</span>}
                  {g.medium > 0 && <span className="flex items-center gap-0.5 rounded-full bg-yellow-100 px-2 py-0.5 text-[10px] font-bold text-yellow-700">{g.medium} M</span>}
                  {g.low > 0 && <span className="flex items-center gap-0.5 rounded-full bg-blue-100 px-2 py-0.5 text-[10px] font-bold text-blue-700">{g.low} L</span>}
                  <span className="ml-1 text-xs text-gray-400">{g.findings.length}</span>
                  {isOpen ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
                </div>
              </button>

              {/* Expanded findings */}
              {isOpen && (
                <div className="border-t divide-y divide-gray-100">
                  {g.findings.map(f => {
                    const r = rd(f);
                    const controlId = r.controlID ?? r.ID ?? '';
                    const category = r.category ?? r.Type ?? '';
                    const refUrl = r.PrimaryURL;
                    const message = r.Message ?? '';
                    const resolution = f.remediation ?? r.Resolution ?? '';
                    const causeLines = r.CauseMetadata?.Code?.Lines as Array<{ Number: number; Content: string; IsCause: boolean }> | undefined;

                    return (
                      <div key={f.id} className="px-4 py-3 space-y-2">
                        {/* Finding header */}
                        <div className="flex items-start gap-2 flex-wrap">
                          <SeverityBadge severity={f.severity} />
                          {controlId && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-600">{controlId}</span>}
                          {category && <span className="rounded bg-indigo-50 px-2 py-0.5 text-[10px] font-medium text-indigo-600">{category}</span>}
                          {refUrl && (
                            <a href={refUrl} target="_blank" rel="noopener noreferrer"
                              className="ml-auto rounded bg-blue-50 px-2 py-0.5 text-xs text-blue-600 hover:bg-blue-100 hover:underline"
                              onClick={e => e.stopPropagation()}>
                              Reference ↗
                            </a>
                          )}
                        </div>
                        <p className="text-sm font-medium text-gray-800">{f.title}</p>

                        {/* Description / message */}
                        {(f.description || message) && (
                          <p className="text-xs text-gray-500 leading-relaxed">
                            {f.description || message}
                          </p>
                        )}
                        {message && f.description && message !== f.description && (
                          <div className="flex items-start gap-1.5 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2">
                            <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-500" />
                            <p className="text-xs text-amber-700">{message}</p>
                          </div>
                        )}

                        {/* Cause code snippet (Trivy) */}
                        {causeLines && causeLines.length > 0 && (
                          <div className="rounded-lg border border-gray-200 bg-gray-900 overflow-hidden">
                            <div className="px-3 py-1.5 bg-gray-800 text-[10px] font-medium text-gray-400 uppercase tracking-wider">
                              Affected Configuration
                            </div>
                            <pre className="px-3 py-2 text-xs leading-5 overflow-x-auto">
                              {causeLines.filter(l => l.Content !== undefined).map((l, i) => (
                                <div key={i} className={`flex ${l.IsCause ? 'bg-red-900/30' : ''}`}>
                                  <span className="w-8 shrink-0 text-right text-gray-500 select-none pr-3">{l.Number}</span>
                                  <span className={l.IsCause ? 'text-red-300' : 'text-gray-400'}>{l.Content}</span>
                                </div>
                              ))}
                            </pre>
                          </div>
                        )}

                        {/* Failed/fix paths (Kubescape) */}
                        {!causeLines && ((r.failedPaths as string[])?.length > 0 || (r.fixPaths as Array<{path: string; value: string}>)?.length > 0) && (
                          <div className="rounded-lg border border-gray-200 bg-gray-900 overflow-hidden">
                            <div className="px-3 py-1.5 bg-gray-800 text-[10px] font-medium text-gray-400 uppercase tracking-wider">Affected Paths</div>
                            <div className="px-3 py-2 space-y-1.5">
                              {(r.failedPaths as string[])?.map((p: string, i: number) => (
                                <div key={i} className="font-mono text-xs text-red-300">{p}</div>
                              ))}
                              {(r.fixPaths as Array<{path: string; value: string}>)?.map((fix: {path: string; value: string}, i: number) => (
                                <div key={i} className="font-mono text-xs">
                                  <span className="text-green-300">{fix.path}</span>
                                  {fix.value && <span className="text-gray-500"> = </span>}
                                  {fix.value && <span className="text-green-200">{fix.value}</span>}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Remediation */}
                        {resolution && (
                          <div className="flex items-start gap-2 rounded-lg border border-green-200 bg-green-50 px-3 py-2">
                            <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-green-600" />
                            <div>
                              <span className="text-xs font-semibold text-green-700">Remediation</span>
                              <p className="text-xs text-green-600 mt-0.5">{resolution}</p>
                            </div>
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
      {groups.length === 0 && (
        <p className="py-8 text-center text-sm text-gray-400">No findings match the selected filters.</p>
      )}
    </div>
  );
}
