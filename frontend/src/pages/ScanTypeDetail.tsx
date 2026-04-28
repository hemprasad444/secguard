import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, Filter, ArrowUpDown, RefreshCw, X, Search,
  Shield, Lock, FileText, Code, Globe, Server, Trash2, FileDown, ChevronRight, Play,
} from 'lucide-react';
import { getScans, getScanFindings, getScanSbom, deleteScan, triggerScan } from '../api/scans';
import { getProject } from '../api/projects';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
import K8sFindingsView from '../components/K8sFindingsView';

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
  created_at?: string;
  error_message?: string | null;
  config_json?: Record<string, any> | null;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  cve_id?: string;
  cvss_score?: number;
  file_path?: string;
  line_number?: number;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
}

/* ------------------------------------------------------------------ */
/* Constants                                                              */
/* ------------------------------------------------------------------ */
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SCAN_TYPES = [
  { key: 'dependency', label: 'Dependency Scan',  icon: Shield,   colorBg: 'bg-blue-50',   colorIcon: 'text-blue-600'   },
  { key: 'secrets',    label: 'Secret Detection', icon: Lock,     colorBg: 'bg-red-50',    colorIcon: 'text-red-600'    },
  { key: 'sbom',       label: 'SBOM Generation',  icon: FileText, colorBg: 'bg-purple-50', colorIcon: 'text-purple-600' },
  { key: 'sast',       label: 'SAST',             icon: Code,     colorBg: 'bg-yellow-50', colorIcon: 'text-yellow-600' },
  { key: 'dast',       label: 'DAST',             icon: Globe,    colorBg: 'bg-orange-50', colorIcon: 'text-orange-600' },
  { key: 'k8s',        label: 'K8s Security',     icon: Server,   colorBg: 'bg-green-50',  colorIcon: 'text-green-600'  },
] as const;

/* ------------------------------------------------------------------ */
/* Helpers                                                               */
/* ------------------------------------------------------------------ */
function scanTypeKey(scan: Scan): string {
  const sub = scan.config_json?.scan_subtype;
  if (sub === 'secrets') return 'secrets';
  if (sub === 'sbom') return 'sbom';
  if (sub === 'k8s') return 'k8s';
  if (scan.tool_name === 'semgrep' || scan.tool_name === 'sonarqube') return 'sast';
  if (scan.tool_name === 'zap') return 'dast';
  if (scan.tool_name === 'kubescape') return 'k8s';
  return 'dependency';
}

function targetLabel(scan: Scan): string {
  const cfg = scan.config_json ?? {};
  if (cfg.target) {
    const t: string = cfg.target;
    const filename = t.split('/').pop() ?? t;
    return filename.replace(/^[0-9a-f-]{36}_/, '');
  }
  return '—';
}

function scanLabel(scan: Scan): string {
  const subtype = scan.config_json?.scan_subtype;
  if (subtype === 'secrets') return 'Secret Detection';
  if (subtype === 'sbom') return 'SBOM Generation';
  if (subtype === 'k8s') return 'K8s Security';
  if (scan.tool_name === 'semgrep') return 'SAST';
  if (scan.tool_name === 'zap') return 'DAST';
  if (scan.tool_name === 'kubescape') return 'K8s Security';
  return 'Dependency Scan';
}

function highestVersion(raw: string): string {
  if (!raw) return '';
  const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
  if (parts.length <= 1) return parts[0] ?? '';
  return parts.reduce((best, v) => {
    const toNums = (s: string) => s.replace(/[^0-9.]/g, '').split('.').map(n => parseInt(n) || 0);
    const a = toNums(best), b = toNums(v);
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
      if ((b[i] ?? 0) > (a[i] ?? 0)) return v;
      if ((a[i] ?? 0) > (b[i] ?? 0)) return best;
    }
    return best;
  });
}

function cvssColor(score: number) {
  if (score >= 9) return 'bg-red-100 text-red-700';
  if (score >= 7) return 'bg-orange-100 text-orange-700';
  if (score >= 4) return 'bg-yellow-100 text-yellow-700';
  return 'bg-gray-100 text-gray-600';
}

/* ------------------------------------------------------------------ */
/* Confirm Modal                                                          */
/* ------------------------------------------------------------------ */
function ConfirmModal({ title, message, onConfirm, onCancel }: {
  title: string; message: string; onConfirm: () => void; onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4" onClick={onCancel}>
      <div className="w-full max-w-sm rounded-2xl bg-white shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="px-6 pt-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
            <Trash2 className="h-5 w-5 text-red-600" />
          </div>
          <h3 className="mt-4 text-base font-semibold text-gray-900">{title}</h3>
          <p className="mt-1.5 text-sm text-gray-500">{message}</p>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4">
          <button onClick={onCancel} className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">Cancel</button>
          <button onClick={onConfirm} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">Delete</button>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SBOM View                                                              */
/* ------------------------------------------------------------------ */
function SbomView({ sbom }: { sbom: any }) {
  const [search, setSearch] = useState('');
  if (!sbom?.components)
    return <p className="py-12 text-center text-sm text-gray-400">No SBOM data available.</p>;
  const components = (sbom.components ?? []).filter((c: any) =>
    !search || c.name?.toLowerCase().includes(search.toLowerCase())
  );
  return (
    <div className="space-y-4">
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search components…"
        className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" />
      <div className="overflow-x-auto rounded-lg border border-gray-200">
        <table className="min-w-full divide-y divide-gray-100 text-sm">
          <thead className="bg-gray-50">
            <tr>
              {['Component', 'Version', 'Type', 'Licenses'].map(h => (
                <th key={h} className="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wider text-gray-400">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {components.map((c: any, i: number) => (
              <tr key={i} className="hover:bg-gray-50">
                <td className="px-4 py-2 font-medium text-gray-800">{c.name}</td>
                <td className="px-4 py-2 font-mono text-xs text-gray-500">{c.version ?? '—'}</td>
                <td className="px-4 py-2 text-xs text-gray-400">{c.type ?? '—'}</td>
                <td className="px-4 py-2 text-xs text-gray-400">
                  {(c.licenses ?? []).map((l: any) => l?.license?.id ?? l?.expression ?? '').filter(Boolean).join(', ') || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Findings View                                                          */
/* ------------------------------------------------------------------ */
function FindingsView({ findings, total }: { findings: Finding[]; total: number }) {
  if (total === 0)
    return <p className="py-12 text-center text-sm text-gray-400">No findings for this scan.</p>;
  if (findings.length === 0)
    return <p className="py-8 text-center text-sm text-gray-400">No findings match the selected filter.</p>;

  type Group = { key: string; pkg: string | null; filePath: string; installed: string; items: Finding[] };
  const groups: Group[] = [];
  const idx = new Map<string, number>();
  for (const f of findings) {
    const pkg = (f.raw_data?.PkgName ?? f.raw_data?.pkg_name) as string | undefined;
    if (!pkg) {
      groups.push({ key: f.id, pkg: null, filePath: f.file_path ?? '', installed: '', items: [f] });
      continue;
    }
    const installed = (f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '') as string;
    const key = `${pkg}||${installed}`;
    const pos = idx.get(key);
    if (pos !== undefined) { groups[pos].items.push(f); }
    else { idx.set(key, groups.length); groups.push({ key, pkg, filePath: f.file_path ?? '', installed, items: [f] }); }
  }

  return (
    <div className="space-y-3">
      {groups.map(group => {
        const allFixed = group.items.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version ?? '').filter(Boolean).join(',');
        const fixed = highestVersion(allFixed);
        const worstSev = group.items.reduce(
          (w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w,
          group.items[0].severity,
        );

        if (!group.pkg) {
          const f = group.items[0];
          const refUrl = f.raw_data?.PrimaryURL;
          return (
            <div key={group.key} className="rounded-xl border border-gray-200 p-4 hover:border-gray-300 transition-colors">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={f.severity} />
                {f.cve_id && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-600">{f.cve_id}</span>}
                {f.cvss_score != null && <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cvssColor(f.cvss_score)}`}>CVSS {Number(f.cvss_score).toFixed(1)}</span>}
                {refUrl && <a href={refUrl} target="_blank" rel="noopener noreferrer" className="rounded bg-blue-50 px-2 py-0.5 font-mono text-xs text-blue-600 hover:underline" onClick={e => e.stopPropagation()}>Reference ↗</a>}
              </div>
              <p className="mt-2 text-sm font-semibold text-gray-800">{f.title}</p>
              {f.file_path && <p className="mt-1 font-mono text-xs text-gray-400">{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</p>}
              {f.description && <p className="mt-1.5 text-xs text-gray-500 line-clamp-2">{f.description}</p>}
              {fixed && (
                <div className="mt-3 flex items-center gap-2 rounded-lg border border-green-200 bg-green-50 px-3 py-2">
                  <span className="text-xs font-semibold text-green-700">Fix Available</span>
                  <span className="text-xs text-green-600">— Upgrade to</span>
                  <span className="rounded bg-green-700 px-2 py-0.5 font-mono text-xs font-bold text-white">{fixed}</span>
                </div>
              )}
            </div>
          );
        }

        return (
          <div key={group.key} className="rounded-xl border border-gray-200 p-4 hover:border-gray-300 transition-colors">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={worstSev} />
                <span className="font-semibold text-gray-800">{group.pkg}</span>
                {group.installed && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-500">{group.installed}</span>}
              </div>
              <span className="text-xs text-gray-400">{group.items.length} CVE{group.items.length !== 1 ? 's' : ''}</span>
            </div>
            {(() => {
              const topCve = group.items.reduce((best, f) => {
                const bs = best.cvss_score ?? 0, fs = f.cvss_score ?? 0;
                if (fs > bs) return f;
                if (fs === bs && (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[best.severity] ?? 9)) return f;
                return best;
              });
              const refUrl = topCve.raw_data?.PrimaryURL;
              return (
                <div className="mt-3 overflow-hidden rounded-lg border border-gray-100">
                  <div className="flex flex-wrap items-center gap-2 bg-gray-50 px-3 py-2">
                    <SeverityBadge severity={topCve.severity} />
                    {topCve.cve_id && <span className="rounded bg-white border border-gray-200 px-2 py-0.5 font-mono text-xs text-gray-600">{topCve.cve_id}</span>}
                    {topCve.cvss_score != null && <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cvssColor(topCve.cvss_score)}`}>CVSS {Number(topCve.cvss_score).toFixed(1)}</span>}
                    {refUrl && <a href={refUrl} target="_blank" rel="noopener noreferrer" className="rounded bg-blue-50 px-2 py-0.5 font-mono text-xs text-blue-600 hover:underline" onClick={e => e.stopPropagation()}>Reference ↗</a>}
                    {topCve.description && <span className="ml-auto max-w-xs truncate text-xs text-gray-400">{topCve.description}</span>}
                  </div>
                </div>
              );
            })()}
            {fixed && (
              <div className="mt-3 flex items-center gap-2 rounded-lg border border-green-200 bg-green-50 px-3 py-2">
                <span className="text-xs font-semibold text-green-700">Fix Available</span>
                <span className="text-xs text-green-600">— Upgrade <span className="font-semibold">{group.pkg}</span> to</span>
                <span className="rounded bg-green-700 px-2 py-0.5 font-mono text-xs font-bold text-white">{fixed}</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Results Drawer                                                         */
/* ------------------------------------------------------------------ */
function ScanResultsDrawer({ scan, onClose }: { scan: Scan; onClose: () => void }) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sbom, setSbom] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'severity' | 'cvss' | 'title'>('severity');
  const [fixableOnly, setFixableOnly] = useState(false);

  const isSbom = scan.config_json?.scan_subtype === 'sbom';
  const isK8s = scan.config_json?.scan_subtype === 'k8s' || scan.tool_name === 'kubescape';

  useEffect(() => {
    (async () => {
      setLoading(true);
      try {
        if (isSbom) {
          setSbom(await getScanSbom(scan.id));
        } else {
          const data = await getScanFindings(scan.id, 1, 1000);
          setFindings(Array.isArray(data) ? data : (data.items ?? data.results ?? []));
        }
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [scan.id, isSbom]);

  const pkgKey = (f: Finding) => {
    const pkg = f.raw_data?.PkgName ?? f.raw_data?.pkg_name;
    if (!pkg) return f.id;
    return `${pkg}||${f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? ''}`;
  };

  const uniquePkgCount = new Set(findings.map(pkgKey)).size;
  const fixableCount = new Set(
    findings.filter(f => f.raw_data?.FixedVersion || f.raw_data?.fixed_version).map(pkgKey)
  ).size;

  const filtered = findings
    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
    .filter(f => !fixableOnly || (f.raw_data?.FixedVersion || f.raw_data?.fixed_version))
    .sort((a, b) => {
      if (sortBy === 'severity') return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
      if (sortBy === 'cvss') return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      return a.title.localeCompare(b.title);
    });

  const severityCounts = ['critical', 'high', 'medium', 'low', 'info'].reduce((acc, sev) => {
    acc[sev] = new Set(findings.filter(f => f.severity === sev).map(pkgKey)).size;
    return acc;
  }, {} as Record<string, number>);
  const filteredUniquePkgCount = new Set(filtered.map(pkgKey)).size;

  const downloadSbom = () => {
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url;
    a.download = `sbom-${scan.id.slice(0, 8)}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const downloadReport = () => {
    if (isK8s) {
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
          'Reference': r.PrimaryURL ?? '',
          'Tool': scan.tool_name,
        };
      });
      const ws = XLSX.utils.json_to_sheet(rows);
      ws['!cols'] = [14, 22, 14, 10, 12, 24, 30, 50, 50, 40, 10].map(w => ({ wch: w }));
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, ws, 'K8s Findings');
      XLSX.writeFile(wb, `K8s-Security-${scan.tool_name}-${scan.id.slice(0, 8)}.xlsx`);
      return;
    }
    type Group = { pkg: string | null; filePath: string; installed: string; items: Finding[] };
    const groups: Group[] = [];
    const idx = new Map<string, number>();
    for (const f of findings) {
      const pkg = (f.raw_data?.PkgName ?? f.raw_data?.pkg_name) as string | undefined;
      if (!pkg) { groups.push({ pkg: null, filePath: f.file_path ?? '', installed: '', items: [f] }); continue; }
      const installed = (f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '') as string;
      const key = `${pkg}||${installed}`;
      const pos = idx.get(key);
      if (pos !== undefined) { groups[pos].items.push(f); }
      else { idx.set(key, groups.length); groups.push({ pkg, filePath: f.file_path ?? '', installed, items: [f] }); }
    }
    const rows: Record<string, string | number>[] = [];
    for (const group of groups) {
      const allFixed = group.items.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version ?? '').filter(Boolean).join(',');
      const fixedVer = highestVersion(allFixed);
      const topCve = group.items.reduce((best, f) => ((f.cvss_score ?? 0) > (best.cvss_score ?? 0) ? f : best));
      const worstSev = group.items.reduce((w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w, group.items[0].severity);
      rows.push({
        'Package': group.pkg ?? topCve.title,
        'Installed Version': group.installed,
        'Severity': worstSev.charAt(0).toUpperCase() + worstSev.slice(1),
        'CVE IDs': [...new Set(group.items.map(f => f.cve_id).filter(Boolean))].join(', '),
        'Highest CVSS': topCve.cvss_score != null ? Number(topCve.cvss_score) : '',
        'Fixed Version': fixedVer,
        'Description': topCve.description ?? '',
        'Reference URLs': [...new Set(group.items.map(f => f.raw_data?.PrimaryURL).filter(Boolean))].join(', '),
      });
    }
    const ws = XLSX.utils.json_to_sheet(rows);
    ws['!cols'] = [22, 18, 10, 50, 12, 18, 60, 60].map(w => ({ wch: w }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Vulnerabilities');
    XLSX.writeFile(wb, `${scanLabel(scan)}-${targetLabel(scan)}-report.xlsx`);
  };

  /* K8s header stats */
  const k8sResourceCount = isK8s ? new Set(findings.map(f => {
    const r = f.raw_data ?? {};
    return `${r.k8s_resource_kind}/${r.k8s_resource_name}/${r.k8s_namespace}`;
  })).size : 0;
  const k8sNsCount = isK8s ? new Set(findings.map(f => f.raw_data?.k8s_namespace).filter(Boolean)).size : 0;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
      <div className="relative flex h-full w-full max-w-3xl flex-col bg-white shadow-2xl" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-start justify-between border-b px-6 py-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-wide text-gray-400">{scanLabel(scan)}</p>
            <p className="mt-0.5 font-semibold text-gray-900">
              {isK8s ? `${scan.tool_name.charAt(0).toUpperCase() + scan.tool_name.slice(1)} Scan` : targetLabel(scan)}
            </p>
            <p className="mt-0.5 text-xs text-gray-400">
              {isSbom ? (
                <>{scan.findings_count} components · {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}</>
              ) : loading ? (
                <>Loading…</>
              ) : isK8s ? (
                <>
                  <span className="font-medium text-gray-600">{findings.length}</span> findings
                  {' · '}
                  <span className="font-medium text-gray-600">{k8sResourceCount}</span> resources
                  {' · '}
                  <span className="font-medium text-gray-600">{k8sNsCount}</span> namespaces
                  {' · '}
                  {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
                </>
              ) : (
                <>
                  <span className="font-medium text-green-600">{fixableCount}</span> fixable
                  {' · '}
                  <span className="font-medium text-red-500">{uniquePkgCount - fixableCount}</span> no fix
                  {' · '}
                  {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
                </>
              )}
            </p>
          </div>
          <div className="flex items-center gap-2">
            {isSbom && sbom && (
              <button onClick={downloadSbom} className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-50">
                <Download className="h-4 w-4" /> Download JSON
              </button>
            )}
            {!isSbom && findings.length > 0 && (
              <button onClick={downloadReport} className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-50">
                <Download className="h-4 w-4" /> Download Report
              </button>
            )}
            <button onClick={onClose} className="rounded-lg p-1.5 hover:bg-gray-100">
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Filters -not for K8s (K8sFindingsView has its own) */}
        {!isSbom && !isK8s && !loading && findings.length > 0 && (
          <div className="flex flex-wrap items-center gap-3 border-b bg-gray-50 px-6 py-3">
            <div className="flex items-center gap-1.5">
              <Filter className="h-3.5 w-3.5 text-gray-400" />
              {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  className={`rounded-full px-2.5 py-0.5 text-xs font-medium capitalize transition-colors ${
                    severityFilter === s ? 'bg-gray-800 text-white' : 'bg-white border border-gray-200 text-gray-500 hover:bg-gray-100'
                  }`}>
                  {s === 'all' ? `All (${filteredUniquePkgCount})` : `${s}${severityCounts[s] ? ` (${severityCounts[s]})` : ''}`}
                </button>
              ))}
            </div>
            <div className="ml-auto flex items-center gap-2">
              <button onClick={() => setFixableOnly(v => !v)}
                className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors ${
                  fixableOnly ? 'bg-green-600 border-green-600 text-white' : 'bg-white border-gray-200 text-gray-500 hover:bg-gray-100'
                }`}>
                {fixableOnly ? `Fixable only (${fixableCount})` : `Fix Available: ${fixableCount} / ${uniquePkgCount}`}
              </button>
              <ArrowUpDown className="h-3.5 w-3.5 text-gray-400" />
              <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
                className="rounded-lg border border-gray-200 bg-white px-2 py-1 text-xs text-gray-600 focus:outline-none">
                <option value="severity">Sort: Severity</option>
                <option value="cvss">Sort: CVSS Score</option>
                <option value="title">Sort: Name</option>
              </select>
            </div>
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-6">
          {loading ? (
            <div className="space-y-3">
              {[...Array(6)].map((_, i) => <div key={i} className="h-20 animate-pulse rounded-lg bg-gray-100" />)}
            </div>
          ) : isSbom ? (
            <SbomView sbom={sbom} />
          ) : isK8s ? (
            <K8sFindingsView findings={findings} />
          ) : (
            <FindingsView findings={filtered} total={findings.length} />
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Rescan Modal                                                           */
/* ------------------------------------------------------------------ */
interface RescanEntry { id: string; target: string; config: Record<string, any>; }

function RescanModal({ failed, projectId, onClose, onDone }: {
  failed: Scan[];
  projectId: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [entries, setEntries] = useState<RescanEntry[]>(() =>
    failed.map(s => ({
      id: s.id,
      target: s.config_json?.target ?? '',
      config: { ...(s.config_json ?? {}) },
    }))
  );
  const [regUser, setRegUser] = useState(() => failed[0]?.config_json?.registry_username ?? '');
  const [regPass, setRegPass] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  const updateTarget = (id: string, val: string) =>
    setEntries(prev => prev.map(e => e.id === id ? { ...e, target: val } : e));

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setProgress({ done: 0, total: entries.length });
    for (let i = 0; i < entries.length; i++) {
      try {
        const entry = entries[i];
        const cfg: Record<string, any> = { ...entry.config };
        delete cfg.unique_packages_count;
        if (entry.target) cfg.target = entry.target;
        if (regUser) cfg.registry_username = regUser;
        if (regPass) cfg.registry_password = regPass;
        await triggerScan({ project_id: projectId, tool_name: failed[i].tool_name, config: cfg });
      } catch { /* noop */ }
      setProgress({ done: i + 1, total: entries.length });
    }
    setSubmitting(false);
    onDone();
  };

  const inputCls = 'block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
      <div className="w-full max-w-2xl rounded-2xl bg-white shadow-2xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between border-b px-6 py-4">
          <div>
            <h2 className="text-base font-bold text-gray-900">Rescan Failed Images</h2>
            <p className="text-xs text-gray-400 mt-0.5">Edit image tags or credentials before re-triggering</p>
          </div>
          <button onClick={onClose} disabled={submitting} className="rounded-lg p-1.5 hover:bg-gray-100 disabled:opacity-40">
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col overflow-hidden">
          {/* Image list */}
          <div className="overflow-y-auto px-6 py-4 space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-gray-400 mb-3">
              Images ({entries.length})
            </p>
            {entries.map((entry, idx) => (
              <div key={entry.id} className="flex items-center gap-2">
                <span className="w-5 shrink-0 text-right text-xs text-gray-400">{idx + 1}</span>
                <input
                  type="text"
                  value={entry.target}
                  onChange={e => updateTarget(entry.id, e.target.value)}
                  placeholder="ghcr.io/org/image:tag"
                  className={`${inputCls} font-mono text-xs`}
                />
              </div>
            ))}
          </div>

          {/* Credentials */}
          <div className="border-t px-6 py-4 bg-gray-50 space-y-3">
            <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">
              Registry Credentials <span className="font-normal normal-case text-gray-400">(applies to all -leave blank to keep existing)</span>
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
                <input type="text" value={regUser} onChange={e => setRegUser(e.target.value)}
                  placeholder="github-username" className={inputCls} />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Password / Token</label>
                <input type="password" value={regPass} onChange={e => setRegPass(e.target.value)}
                  placeholder="Leave blank to keep existing" className={inputCls} />
              </div>
            </div>
          </div>

          {/* Progress bar */}
          {progress && (
            <div className="px-6 py-3 border-t space-y-1.5">
              <div className="flex justify-between text-xs text-gray-500">
                <span>Triggering scans…</span>
                <span className="font-medium text-gray-700">{progress.done} / {progress.total}</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100">
                <div className="h-2 rounded-full bg-gray-800 transition-all duration-300"
                  style={{ width: `${(progress.done / progress.total) * 100}%` }} />
              </div>
            </div>
          )}

          {/* Footer */}
          <div className="flex justify-end gap-3 border-t px-6 py-4">
            <button type="button" onClick={onClose} disabled={submitting}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-40">
              Cancel
            </button>
            <button type="submit" disabled={submitting}
              className="inline-flex items-center gap-2 rounded-lg bg-gray-900 px-4 py-2 text-sm font-semibold text-white hover:bg-gray-800 disabled:opacity-60">
              {submitting
                ? <><RefreshCw className="h-4 w-4 animate-spin" /> Rescanning {progress?.done}/{progress?.total}…</>
                : <><Play className="h-4 w-4" /> Rescan {entries.length} image{entries.length !== 1 ? 's' : ''}</>
              }
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main Page                                                              */
/* ------------------------------------------------------------------ */
export default function ScanTypeDetail() {
  const { projectId, typeKey } = useParams<{ projectId: string; typeKey: string }>();
  const navigate = useNavigate();

  const typeInfo = SCAN_TYPES.find(t => t.key === typeKey) ?? SCAN_TYPES[0];
  const Icon = typeInfo.icon;

  const [projectName, setProjectName] = useState('');
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [confirmScan, setConfirmScan] = useState<Scan | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [deletingFailed, setDeletingFailed] = useState(false);
  const [deletingAll, setDeletingAll] = useState(false);
  const [showRescanModal, setShowRescanModal] = useState(false);
  const [confirmDeleteAll, setConfirmDeleteAll] = useState(false);
  const [imageSearch, setImageSearch] = useState('');
  const [sortKey, setSortKey] = useState<'date-desc' | 'date-asc' | 'name-asc' | 'name-desc' | 'fixable-desc' | 'nofix-desc' | 'count-desc' | 'status'>('date-desc');
  const [latestOnly, setLatestOnly] = useState(true);
  const [expandedBases, setExpandedBases] = useState<Set<string>>(new Set());

  const fetchScans = useCallback(async () => {
    if (!projectId) return;
    const res = await getScans({ project_id: projectId, page_size: 200 });
    const all: Scan[] = Array.isArray(res) ? res : (res.items ?? res.results ?? []);
    const typed = all
      .filter(s => scanTypeKey(s) === typeKey)
      .sort((a, b) => new Date(b.created_at ?? b.started_at ?? '').getTime() - new Date(a.created_at ?? a.started_at ?? '').getTime());
    setScans(typed);
  }, [projectId, typeKey]);

  useEffect(() => {
    if (!projectId) return;
    (async () => {
      try {
        const [proj] = await Promise.all([getProject(projectId), fetchScans()]);
        setProjectName(proj.name);
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [projectId, fetchScans]);

  // Auto-poll while running
  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running');
    if (!hasActive) return;
    const t = setInterval(fetchScans, 5000);
    return () => clearInterval(t);
  }, [scans, fetchScans]);

  const deleteAllFailed = useCallback(async () => {
    const failed = scans.filter(s => s.status === 'failed');
    if (failed.length === 0) return;
    setDeletingFailed(true);
    await Promise.allSettled(failed.map(s => deleteScan(s.id)));
    await fetchScans();
    setDeletingFailed(false);
  }, [scans, fetchScans]);

  const deleteAll = useCallback(async () => {
    setConfirmDeleteAll(false);
    setDeletingAll(true);
    await Promise.allSettled(scans.map(s => deleteScan(s.id)));
    await fetchScans();
    setDeletingAll(false);
  }, [scans, fetchScans]);


  const handleDelete = useCallback((e: React.MouseEvent, scan: Scan) => {
    e.stopPropagation();
    setConfirmScan(scan);
  }, []);

  const confirmDelete = useCallback(async () => {
    if (!confirmScan) return;
    const scan = confirmScan;
    setConfirmScan(null);
    setDeletingId(scan.id);
    try {
      await deleteScan(scan.id);
      if (selectedScan?.id === scan.id) setSelectedScan(null);
      await fetchScans();
    } catch { /* noop */ }
    setDeletingId(null);
  }, [confirmScan, fetchScans, selectedScan]);

  const handleDownload = useCallback(async (e: React.MouseEvent, scan: Scan) => {
    e.stopPropagation();
    setDownloadingId(scan.id);
    try {
      const data = await getScanFindings(scan.id, 1, 1000);
      const allFindings: Finding[] = Array.isArray(data) ? data : (data.items ?? data.results ?? []);
      const scanIsK8s = scan.config_json?.scan_subtype === 'k8s' || scan.tool_name === 'kubescape';

      if (scanIsK8s) {
        const rows: Record<string, string>[] = allFindings.map(f => {
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
            'Reference': r.PrimaryURL ?? '',
            'Tool': scan.tool_name,
          };
        });
        const ws = XLSX.utils.json_to_sheet(rows);
        ws['!cols'] = [14, 22, 14, 10, 12, 24, 30, 50, 50, 40, 10].map(w => ({ wch: w }));
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'K8s Findings');
        XLSX.writeFile(wb, `K8s-Security-${scan.tool_name}-${scan.id.slice(0, 8)}.xlsx`);
      } else {
        type Group = { pkg: string | null; filePath: string; installed: string; items: Finding[] };
        const groups: Group[] = [];
        const idx = new Map<string, number>();
        for (const f of allFindings) {
          const pkg = (f.raw_data?.PkgName ?? f.raw_data?.pkg_name) as string | undefined;
          if (!pkg) { groups.push({ pkg: null, filePath: f.file_path ?? '', installed: '', items: [f] }); continue; }
          const installed = (f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '') as string;
          const key = `${pkg}||${installed}`;
          const pos = idx.get(key);
          if (pos !== undefined) { groups[pos].items.push(f); }
          else { idx.set(key, groups.length); groups.push({ pkg, filePath: f.file_path ?? '', installed, items: [f] }); }
        }
        const rows: Record<string, string | number>[] = [];
        for (const group of groups) {
          const allFixed = group.items.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version ?? '').filter(Boolean).join(',');
          const fixedVer = highestVersion(allFixed);
          const topCve = group.items.reduce((best, f) => ((f.cvss_score ?? 0) > (best.cvss_score ?? 0) ? f : best));
          const worstSev = group.items.reduce((w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w, group.items[0].severity);
          rows.push({
            'Package': group.pkg ?? topCve.title,
            'Installed Version': group.installed,
            'Severity': worstSev.charAt(0).toUpperCase() + worstSev.slice(1),
            'CVE IDs': [...new Set(group.items.map(f => f.cve_id).filter(Boolean))].join(', '),
            'Highest CVSS': topCve.cvss_score != null ? Number(topCve.cvss_score) : '',
            'Fixed Version': fixedVer,
            'Description': topCve.description ?? '',
            'Reference URLs': [...new Set(group.items.map(f => f.raw_data?.PrimaryURL).filter(Boolean))].join(', '),
          });
        }
        const ws = XLSX.utils.json_to_sheet(rows);
        ws['!cols'] = [22, 18, 10, 50, 12, 18, 60, 60].map(w => ({ wch: w }));
        const wb = XLSX.utils.book_new();
        XLSX.utils.book_append_sheet(wb, ws, 'Vulnerabilities');
        XLSX.writeFile(wb, `${scanLabel(scan)}-${targetLabel(scan)}-report.xlsx`);
      }
    } catch { /* noop */ }
    setDownloadingId(null);
  }, []);

  const failedCount = scans.filter(s => s.status === 'failed').length;
  const runningCount = scans.filter(s => s.status === 'pending' || s.status === 'running').length;
  const completedCount = scans.filter(s => s.status === 'completed').length;
  const isK8sSection = typeKey === 'k8s';

  // Search + sort
  const searchKey = (s: Scan) =>
    (scanTypeKey(s) === 'k8s' ? s.tool_name : targetLabel(s)).toLowerCase();

  // Base image key (strip tag for dependency/secrets/sbom images; K8s uses tool name)
  const baseKey = (s: Scan) => {
    if (scanTypeKey(s) === 'k8s') return s.tool_name;
    const t = (s.config_json?.target as string) ?? targetLabel(s);
    return (t.split(':')[0] || t).toLowerCase();
  };

  // Exact-target key — used to collapse identical re-scans (same image:tag, different run times)
  const exactTargetKey = (s: Scan) => {
    if (scanTypeKey(s) === 'k8s') return s.tool_name;
    return (s.config_json?.target as string) ?? targetLabel(s);
  };

  const statusRank: Record<string, number> = { running: 0, pending: 1, failed: 2, completed: 3 };

  // Step 1: collapse same-exact-target re-scans — keep only the most recent per (image:tag).
  // This is the user's real mental model: "the image itself", not "every time we ran scan on it".
  const latestPerExactTarget = new Map<string, Scan>();
  for (const s of scans) {
    const k = exactTargetKey(s);
    const prev = latestPerExactTarget.get(k);
    if (!prev) { latestPerExactTarget.set(k, s); continue; }
    const prevTs = new Date(prev.completed_at ?? prev.created_at ?? '').getTime();
    const curTs = new Date(s.completed_at ?? s.created_at ?? '').getTime();
    if (curTs > prevTs) latestPerExactTarget.set(k, s);
  }
  const tagUniqueScans = [...latestPerExactTarget.values()];

  const sortedFiltered = tagUniqueScans
    .filter(s => !imageSearch || searchKey(s).includes(imageSearch.toLowerCase()))
    .sort((a, b) => {
      switch (sortKey) {
        case 'date-desc':
          return new Date(b.completed_at ?? b.created_at ?? '').getTime() - new Date(a.completed_at ?? a.created_at ?? '').getTime();
        case 'date-asc':
          return new Date(a.completed_at ?? a.created_at ?? '').getTime() - new Date(b.completed_at ?? b.created_at ?? '').getTime();
        case 'name-asc':
          return searchKey(a).localeCompare(searchKey(b));
        case 'name-desc':
          return searchKey(b).localeCompare(searchKey(a));
        case 'fixable-desc':
          return ((b.config_json?.fixable_count ?? 0) as number)
               - ((a.config_json?.fixable_count ?? 0) as number);
        case 'nofix-desc':
          return ((b.config_json?.no_fix_count ?? 0) as number)
               - ((a.config_json?.no_fix_count ?? 0) as number);
        case 'count-desc':
          return (b.findings_count ?? 0) - (a.findings_count ?? 0);
        case 'status':
          return (statusRank[a.status] ?? 9) - (statusRank[b.status] ?? 9);
        default:
          return 0;
      }
    });

  // Build per-base history (always newest first within a base) so we can show "N older" chips
  const baseHistory = new Map<string, Scan[]>();
  for (const s of sortedFiltered) {
    const k = baseKey(s);
    const arr = baseHistory.get(k) ?? [];
    arr.push(s);
    baseHistory.set(k, arr);
  }
  for (const [, arr] of baseHistory) {
    arr.sort((a, b) => new Date(b.completed_at ?? b.created_at ?? '').getTime() - new Date(a.completed_at ?? a.created_at ?? '').getTime());
  }

  // visibleScans: when latestOnly, emit only the freshest-per-base (plus expanded siblings).
  const visibleScans: Scan[] = [];
  const seenBases = new Set<string>();
  for (const s of sortedFiltered) {
    const k = baseKey(s);
    if (!latestOnly) { visibleScans.push(s); continue; }
    if (seenBases.has(k)) {
      // Only include if this base is expanded
      if (expandedBases.has(k)) visibleScans.push(s);
      continue;
    }
    seenBases.add(k);
    visibleScans.push(s);
  }

  const toggleBase = (k: string) => {
    setExpandedBases(prev => {
      const next = new Set(prev);
      if (next.has(k)) next.delete(k); else next.add(k);
      return next;
    });
  };

  // Column layout per scan type
  //   dependency   : Image | Status | Fixable | No fix | Completed | Actions  (6 cols)
  //   k8s          : Tool  | Status | Findings | Severity | Completed | Actions  (6 cols)
  //   secrets/sbom : Image | Status | <Count>  |           Completed | Actions  (5 cols)
  const countLabel =
    typeKey === 'secrets' ? 'Secrets'
      : typeKey === 'sbom' ? 'Components'
      : typeKey === 'sast' ? 'Issues'
      : typeKey === 'dast' ? 'Issues'
      : 'Findings';
  const isDependency = typeKey === 'dependency';
  const gridCols = isDependency
    ? 'grid-cols-[minmax(0,1fr)_100px_100px_100px_170px_72px]'
    : isK8sSection
      ? 'grid-cols-[minmax(0,1fr)_100px_100px_160px_170px_72px]'
      : 'grid-cols-[minmax(0,1fr)_100px_100px_170px_72px]';

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <button onClick={() => navigate(`/projects/${projectId}`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" />
        {projectName || 'Back to project'}
      </button>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <Icon className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-gray-400">Scan type</p>
            <h1 className="mt-0.5 text-lg font-semibold text-gray-900">{typeInfo.label}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
              <span>
                <span className="font-semibold text-gray-900 tabular-nums">{scans.length}</span> scan{scans.length !== 1 ? 's' : ''}
              </span>
              {completedCount > 0 && (
                <span>
                  <span className="font-semibold text-gray-900 tabular-nums">{completedCount}</span> completed
                </span>
              )}
              {runningCount > 0 && (
                <span className="inline-flex items-center gap-1 text-amber-700">
                  <RefreshCw className="h-3 w-3 animate-spin" />
                  <span className="font-semibold tabular-nums">{runningCount}</span> running
                </span>
              )}
              {failedCount > 0 && (
                <span className="inline-flex items-center gap-1.5 text-gray-500">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                  <span className="font-semibold text-gray-900 tabular-nums">{failedCount}</span> failed
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-wrap items-center gap-2">
          {typeKey !== 'k8s' && failedCount > 0 && (
            <button onClick={() => setShowRescanModal(true)} disabled={deletingFailed || deletingAll}
              className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black transition-colors disabled:opacity-50">
              <Play className="h-3.5 w-3.5" /> Rescan failed ({failedCount})
            </button>
          )}
          {failedCount > 0 && (
            <button onClick={deleteAllFailed} disabled={deletingFailed || deletingAll}
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-50">
              {deletingFailed
                ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Deleting…</>
                : <><Trash2 className="h-3.5 w-3.5" /> Delete failed</>
              }
            </button>
          )}
          {scans.length > 0 && (
            <button onClick={() => setConfirmDeleteAll(true)} disabled={deletingAll || deletingFailed}
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors disabled:opacity-50">
              {deletingAll
                ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Deleting…</>
                : <><Trash2 className="h-3.5 w-3.5" /> Delete all</>
              }
            </button>
          )}
          <button onClick={fetchScans}
            className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Toolbar — search + sort */}
      {!loading && scans.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative flex-1 min-w-[200px] max-w-md">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
            <input
              type="text"
              value={imageSearch}
              onChange={e => setImageSearch(e.target.value)}
              placeholder={isK8sSection ? 'Search by tool…' : 'Search by image name…'}
              className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400"
            />
          </div>
          <div className="inline-flex items-center gap-1.5">
            <ArrowUpDown className="h-3.5 w-3.5 text-gray-400" />
            <select
              value={sortKey}
              onChange={e => setSortKey(e.target.value as typeof sortKey)}
              className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400"
            >
              <option value="date-desc">Newest first</option>
              <option value="date-asc">Oldest first</option>
              <option value="name-asc">Name A–Z</option>
              <option value="name-desc">Name Z–A</option>
              {isDependency && (
                <>
                  <option value="fixable-desc">Most fixable</option>
                  <option value="nofix-desc">Most no-fix</option>
                </>
              )}
              {!isDependency && (
                <option value="count-desc">Most {countLabel.toLowerCase()}</option>
              )}
              <option value="status">By status</option>
            </select>
          </div>
          {imageSearch && (
            <span className="text-[11px] text-gray-500 tabular-nums">
              {visibleScans.length} of {scans.length}
            </span>
          )}
          <label className="ml-auto inline-flex items-center gap-1.5 text-[11px] text-gray-600 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={latestOnly}
              onChange={e => setLatestOnly(e.target.checked)}
              className="h-3 w-3 rounded border-gray-300 text-gray-900 focus:ring-0 focus:ring-offset-0"
            />
            Latest per image only
          </label>
        </div>
      )}

      {/* Scans list */}
      {loading ? (
        <div className="space-y-2">
          {[...Array(4)].map((_, i) => <div key={i} className="h-12 animate-pulse rounded-md bg-gray-100" />)}
        </div>
      ) : scans.length === 0 ? (
        <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
          No {typeInfo.label.toLowerCase()} scans yet
        </div>
      ) : visibleScans.length === 0 ? (
        <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
          No scans match "{imageSearch}"
        </div>
      ) : (
        <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
          {/* Column headers — matching row grid template */}
          <div className={`hidden md:grid ${gridCols} items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400`}>
            <span>{isK8sSection ? 'Tool' : 'Image'}</span>
            <span className="text-right">Status</span>
            {isDependency ? (
              <>
                <span className="text-right">Fixable</span>
                <span className="text-right">No fix</span>
              </>
            ) : isK8sSection ? (
              <>
                <span className="text-right">Findings</span>
                <span>Severity</span>
              </>
            ) : (
              <span className="text-right">{countLabel}</span>
            )}
            <span className="text-right">Completed</span>
            <span />
          </div>

          {visibleScans.map(s => {
            const isClickable = s.status === 'completed';
            const isRunning = s.status === 'pending' || s.status === 'running';
            const isK8sScan = s.config_json?.scan_subtype === 'k8s' || s.tool_name === 'kubescape';

            const statusText =
              s.status === 'completed' ? <span className="text-emerald-700">Completed</span>
              : s.status === 'failed' ? <span className="text-red-600">Failed</span>
              : s.status === 'running' ? <span className="inline-flex items-center gap-1 text-amber-700"><RefreshCw className="h-3 w-3 animate-spin" /> Running</span>
              : <span className="text-amber-700">Pending</span>;

            const handleRowClick = () => {
              if (!isClickable) return;
              if (isK8sScan) navigate(`/projects/${projectId}/k8s/${s.id}`);
              else navigate(`/projects/${projectId}/scans/${s.id}`);
            };

            const completedDate = s.completed_at
              ? new Date(s.completed_at).toLocaleString(undefined, {
                  year: 'numeric', month: 'short', day: 'numeric',
                  hour: '2-digit', minute: '2-digit',
                })
              : '—';

            return (
              <div
                key={s.id}
                onClick={handleRowClick}
                className={`group grid ${gridCols} items-center gap-3 border-b border-gray-100 px-4 py-3 text-sm transition-colors last:border-b-0 ${
                  isClickable ? 'cursor-pointer hover:bg-gray-50/60' : ''
                }`}
              >
                {/* Image / Tool name */}
                <div className="min-w-0">
                  <div className="flex items-center gap-2 min-w-0">
                    {isK8sScan ? (
                      <span className="text-sm font-medium text-gray-900 capitalize">{s.tool_name}</span>
                    ) : (
                      <span className="block font-mono text-[12px] text-gray-800 truncate">{targetLabel(s)}</span>
                    )}
                    {(() => {
                      const bk = baseKey(s);
                      const history = baseHistory.get(bk) ?? [];
                      const isLatest = history[0]?.id === s.id;
                      const olderCount = history.length - 1;
                      if (latestOnly && isLatest && olderCount > 0) {
                        const isOpen = expandedBases.has(bk);
                        return (
                          <button
                            onClick={e => { e.stopPropagation(); toggleBase(bk); }}
                            className="shrink-0 rounded border border-gray-200 bg-white px-1.5 py-0.5 text-[10px] font-medium text-gray-500 hover:border-gray-400 hover:text-gray-800 transition-colors"
                            title={isOpen ? 'Hide older versions' : `Show ${olderCount} older version${olderCount !== 1 ? 's' : ''}`}
                          >
                            {isOpen ? '− hide history' : `+ ${olderCount} older`}
                          </button>
                        );
                      }
                      if (latestOnly && !isLatest) {
                        return (
                          <span className="shrink-0 text-[10px] uppercase tracking-wider text-gray-400">previous</span>
                        );
                      }
                      return null;
                    })()}
                  </div>
                  {s.status === 'failed' && s.error_message && (
                    <details className="mt-0.5">
                      <summary className="cursor-pointer truncate text-[11px] text-red-600 hover:text-red-700 list-none">
                        {s.error_message.length > 80 ? s.error_message.slice(0, 80) + '…' : s.error_message}
                      </summary>
                      <p className="mt-1 whitespace-pre-wrap break-all rounded bg-gray-50 border border-gray-200 p-2 text-[11px] text-gray-700 font-mono">
                        {s.error_message}
                      </p>
                    </details>
                  )}
                </div>

                {/* Status */}
                <div className="hidden md:block text-right text-xs">
                  {statusText}
                </div>

                {/* Count/severity columns — layout depends on section type */}
                {isDependency ? (
                  <>
                    <div className="hidden md:block text-right">
                      {s.status === 'completed' && s.config_json?.fixable_count != null
                        ? <span className="font-mono text-[12px] text-emerald-700 tabular-nums">{s.config_json.fixable_count}</span>
                        : <span className="text-[11px] text-gray-300">—</span>}
                    </div>
                    <div className="hidden md:block text-right">
                      {s.status === 'completed' && s.config_json?.no_fix_count != null
                        ? <span className="font-mono text-[12px] text-gray-700 tabular-nums">{s.config_json.no_fix_count}</span>
                        : <span className="text-[11px] text-gray-300">—</span>}
                    </div>
                  </>
                ) : isK8sSection ? (
                  <>
                    <div className="hidden md:block text-right">
                      {s.status === 'completed'
                        ? <span className="font-mono text-[12px] text-gray-800 tabular-nums">{s.findings_count}</span>
                        : <span className="text-[11px] text-gray-300">—</span>}
                    </div>
                    <div className="hidden md:block">
                      {s.status === 'completed' && s.findings_count > 0 ? (
                        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                          {(s.config_json?.severity_critical ?? 0) > 0 && (
                            <span className="inline-flex items-center gap-1 text-gray-600">
                              <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                              <span className="tabular-nums font-semibold">{s.config_json?.severity_critical}</span>
                            </span>
                          )}
                          {(s.config_json?.severity_high ?? 0) > 0 && (
                            <span className="inline-flex items-center gap-1 text-gray-600">
                              <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                              <span className="tabular-nums font-semibold">{s.config_json?.severity_high}</span>
                            </span>
                          )}
                          {(s.config_json?.severity_medium ?? 0) > 0 && (
                            <span className="inline-flex items-center gap-1 text-gray-500">
                              <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
                              <span className="tabular-nums font-semibold">{s.config_json?.severity_medium}</span>
                            </span>
                          )}
                          {(s.config_json?.severity_low ?? 0) > 0 && (
                            <span className="inline-flex items-center gap-1 text-gray-500">
                              <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                              <span className="tabular-nums font-semibold">{s.config_json?.severity_low}</span>
                            </span>
                          )}
                        </div>
                      ) : <span className="text-[11px] text-gray-300">—</span>}
                    </div>
                  </>
                ) : (
                  <div className="hidden md:block text-right">
                    {s.status === 'completed'
                      ? <span className="font-mono text-[12px] text-gray-800 tabular-nums">{s.findings_count}</span>
                      : <span className="text-[11px] text-gray-300">—</span>}
                  </div>
                )}

                {/* Completed timestamp */}
                <div className="hidden md:block text-right text-[11px] text-gray-500 font-mono tabular-nums whitespace-nowrap">
                  {completedDate}
                </div>

                {/* Actions */}
                <div className="flex items-center justify-end gap-0.5">
                  {isClickable && (
                    <button onClick={e => handleDownload(e, s)} disabled={downloadingId === s.id}
                      title="Download report"
                      className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 transition-colors disabled:opacity-40">
                      {downloadingId === s.id ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
                    </button>
                  )}
                  <button onClick={e => handleDelete(e, s)} disabled={deletingId === s.id}
                    title="Delete scan"
                    className="rounded p-1 text-gray-400 hover:bg-gray-100 hover:text-gray-700 transition-colors disabled:opacity-40">
                    {deletingId === s.id ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                  </button>
                  {isClickable && <ChevronRight className="h-4 w-4 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Results Drawer */}
      {selectedScan && (
        <ScanResultsDrawer scan={selectedScan} onClose={() => setSelectedScan(null)} />
      )}

      {/* Rescan modal */}
      {showRescanModal && projectId && (
        <RescanModal
          failed={scans.filter(s => s.status === 'failed')}
          projectId={projectId}
          onClose={() => setShowRescanModal(false)}
          onDone={() => { setShowRescanModal(false); fetchScans(); }}
        />
      )}

      {/* Delete single confirm */}
      {confirmScan && (
        <ConfirmModal
          title="Delete scan?"
          message={`This will permanently delete the scan for "${targetLabel(confirmScan)}" and all its findings.`}
          onConfirm={confirmDelete}
          onCancel={() => setConfirmScan(null)}
        />
      )}

      {/* Delete all confirm */}
      {confirmDeleteAll && (
        <ConfirmModal
          title={`Delete all ${scans.length} scans?`}
          message={`This will permanently delete all ${scans.length} scans and their findings for this scan type. This cannot be undone.`}
          onConfirm={deleteAll}
          onCancel={() => setConfirmDeleteAll(false)}
        />
      )}
    </div>
  );
}
