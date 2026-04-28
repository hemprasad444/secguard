import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ChevronDown, ChevronRight, Search,
  Shield, Lock, FileText, Globe, Server, Box, Layers,
} from 'lucide-react';

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

export default function K8sFindingsView({ findings, projectId, scanId }: {
  findings: Finding[];
  projectId?: string;
  scanId?: string;
}) {
  const navigate = useNavigate();
  const canNavigate = !!(projectId && scanId);
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
  const uniqueNamespaces = new Set(filtered.map(f => rd(f).k8s_namespace).filter(Boolean)).size;

  return (
    <div className="space-y-4">
      {/* Stats strip */}
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

      {/* Toolbar — inline */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search resources, controls, descriptions…"
            className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400" />
        </div>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
          <option value="all">All severities</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({sevCounts[s as keyof typeof sevCounts]})</option>
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
      </div>

      {/* Resource groups */}
      {groups.length === 0 ? (
        <p className="rounded-md border border-dashed border-gray-200 py-12 text-center text-sm text-gray-400">
          No findings match the selected filters.
        </p>
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

                {/* Expanded findings — compact rows; click navigates if route is known */}
                {isOpen && (
                  <div className="border-t border-gray-100 divide-y divide-gray-100">
                    {g.findings.map(f => {
                      const r = rd(f);
                      const controlId = r.controlID ?? r.ID ?? '';
                      const category = r.category ?? r.Type ?? '';
                      const isClosed = ['resolved', 'accepted', 'false_positive'].includes(f.status);

                      const rowContent = (
                        <>
                          <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevDot(f.severity)}`} />
                          <span className={`w-16 shrink-0 text-[10px] uppercase tracking-wider font-medium ${sevText(f.severity)}`}>{f.severity}</span>
                          {controlId && (
                            <span className="shrink-0 font-mono text-[11px] text-gray-700">{controlId}</span>
                          )}
                          <span className="min-w-0 flex-1 truncate text-[13px] text-gray-800">{f.title}</span>
                          {category && (
                            <span className="hidden md:inline shrink-0 text-[11px] text-gray-500 truncate max-w-[180px]">{category}</span>
                          )}
                          {canNavigate && (
                            <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />
                          )}
                        </>
                      );

                      const baseClass = `group flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                        canNavigate ? 'hover:bg-gray-50/60' : ''
                      } ${isClosed ? 'opacity-60' : ''}`;

                      if (canNavigate) {
                        return (
                          <button
                            key={f.id}
                            onClick={() => navigate(`/projects/${projectId}/k8s/${scanId}/findings/${f.id}`)}
                            className={baseClass}
                          >
                            {rowContent}
                          </button>
                        );
                      }
                      return (
                        <div key={f.id} className={baseClass}>
                          {rowContent}
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
    </div>
  );
}
