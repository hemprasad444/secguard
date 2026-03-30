import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, Filter, ArrowUpDown, RefreshCw, X,
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
  if (scan.tool_name === 'semgrep') return 'sast';
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

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div>
        <button onClick={() => navigate(`/projects/${projectId}`)}
          className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800">
          <ArrowLeft className="h-4 w-4" />
          {projectName || 'Back to Project'}
        </button>
      </div>

      {/* Header */}
      <div className="flex items-center gap-4">
        <div className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl ${typeInfo.colorBg}`}>
          <Icon className={`h-6 w-6 ${typeInfo.colorIcon}`} />
        </div>
        <div>
          <h1 className="text-xl font-bold text-gray-900">{typeInfo.label}</h1>
          <p className="text-sm text-gray-400">{scans.length} scan{scans.length !== 1 ? 's' : ''} total</p>
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          {typeKey !== 'k8s' && scans.some(s => s.status === 'failed') && (
            <button onClick={() => setShowRescanModal(true)} disabled={deletingFailed || deletingAll}
              className="inline-flex items-center gap-1.5 rounded-lg border border-green-200 bg-green-50 px-3 py-1.5 text-xs font-medium text-green-700 hover:bg-green-100 transition-colors disabled:opacity-50">
              <Play className="h-3.5 w-3.5" /> Rescan failed ({scans.filter(s => s.status === 'failed').length})
            </button>
          )}
          {scans.some(s => s.status === 'failed') && (
            <button onClick={deleteAllFailed} disabled={deletingFailed || deletingAll}
              className="inline-flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3 py-1.5 text-xs font-medium text-red-600 hover:bg-red-100 transition-colors disabled:opacity-50">
              {deletingFailed
                ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Deleting…</>
                : <><Trash2 className="h-3.5 w-3.5" /> Delete failed ({scans.filter(s => s.status === 'failed').length})</>
              }
            </button>
          )}
          {scans.length > 0 && (
            <button onClick={() => setConfirmDeleteAll(true)} disabled={deletingAll || deletingFailed}
              className="inline-flex items-center gap-1.5 rounded-lg border border-gray-300 bg-white px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 transition-colors disabled:opacity-50">
              {deletingAll
                ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Deleting…</>
                : <><Trash2 className="h-3.5 w-3.5" /> Delete all</>
              }
            </button>
          )}
          <button onClick={fetchScans}
            className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-500 hover:bg-gray-50 transition-colors">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </button>
        </div>
      </div>

      {/* Scans table */}
      {loading ? (
        <div className="space-y-3">
          {[...Array(3)].map((_, i) => <div key={i} className="h-14 animate-pulse rounded-xl bg-gray-100" />)}
        </div>
      ) : scans.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-gray-200 py-16 text-center text-sm text-gray-400">
          No {typeInfo.label.toLowerCase()} scans yet
        </div>
      ) : (
        <div className="overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm">
          <table className="min-w-full divide-y divide-gray-100 text-sm">
            <thead className="bg-gray-50">
              <tr>
                {typeKey === 'k8s'
                  ? ['Tool', 'Status', 'Findings', 'Severity', 'Completed', ''].map(h => (
                      <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400">{h}</th>
                    ))
                  : ['Target / Image', 'Status', 'Fixable Pkgs', 'No Fix Pkgs', 'Completed', ''].map(h => (
                      <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-400">{h}</th>
                    ))
                }
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {scans.map(s => {
                const isClickable = s.status === 'completed';
                const isRunning = s.status === 'pending' || s.status === 'running';
                const isK8sScan = s.config_json?.scan_subtype === 'k8s' || s.tool_name === 'kubescape';
                return (
                  <tr key={s.id}
                    onClick={() => isClickable && (isK8sScan ? navigate(`/projects/${projectId}/k8s/${s.id}`) : navigate(`/projects/${projectId}/scans/${s.id}`))}
                    className={`transition-colors ${isClickable ? 'cursor-pointer hover:bg-blue-50' : ''} ${s.status === 'failed' ? 'bg-red-50/60' : ''}`}>
                    <td className="px-5 py-3.5 max-w-[260px]">
                      {isK8sScan ? (
                        <div className="flex items-center gap-2">
                          <span className="inline-flex items-center gap-1.5 rounded-full bg-green-50 px-2.5 py-0.5 text-xs font-semibold text-green-700">
                            <Server className="h-3 w-3" />
                            {s.tool_name.charAt(0).toUpperCase() + s.tool_name.slice(1)}
                          </span>
                        </div>
                      ) : (
                        <span className="block font-mono text-xs text-gray-700 truncate">{targetLabel(s)}</span>
                      )}
                      {s.status === 'failed' && s.error_message && (
                        <details className="mt-0.5">
                          <summary className="cursor-pointer truncate text-xs text-red-500 hover:text-red-700 list-none">
                            {s.error_message.length > 80 ? s.error_message.slice(0, 80) + '…  (click to expand)' : s.error_message}
                          </summary>
                          <p className="mt-1 whitespace-pre-wrap break-all rounded bg-red-50 p-2 text-xs text-red-700 font-mono">
                            {s.error_message}
                          </p>
                        </details>
                      )}
                    </td>
                    <td className="px-5 py-3.5">
                      {isRunning ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-yellow-600">
                          <RefreshCw className="h-3 w-3 animate-spin" />
                          {s.status === 'running' ? 'Running…' : 'Pending…'}
                        </span>
                      ) : <StatusBadge status={s.status} />}
                    </td>
                    {isK8sScan ? (
                      <>
                        <td className="px-5 py-3.5">
                          {s.status === 'completed'
                            ? <span className="font-semibold text-gray-800">{s.findings_count}</span>
                            : <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-5 py-3.5">
                          {s.status === 'completed' && s.findings_count > 0 ? (
                            <div className="flex items-center gap-1">
                              {(s.config_json?.severity_critical ?? 0) > 0 && <span className="rounded-full bg-red-100 px-1.5 py-0.5 text-[10px] font-bold text-red-700">{s.config_json?.severity_critical}C</span>}
                              {(s.config_json?.severity_high ?? 0) > 0 && <span className="rounded-full bg-orange-100 px-1.5 py-0.5 text-[10px] font-bold text-orange-700">{s.config_json?.severity_high}H</span>}
                              {(s.config_json?.severity_medium ?? 0) > 0 && <span className="rounded-full bg-yellow-100 px-1.5 py-0.5 text-[10px] font-bold text-yellow-700">{s.config_json?.severity_medium}M</span>}
                              {(s.config_json?.severity_low ?? 0) > 0 && <span className="rounded-full bg-blue-100 px-1.5 py-0.5 text-[10px] font-bold text-blue-700">{s.config_json?.severity_low}L</span>}
                              {!s.config_json?.severity_critical && !s.config_json?.severity_high && !s.config_json?.severity_medium && !s.config_json?.severity_low && (
                                <span className="text-xs text-gray-400">{s.findings_count} total</span>
                              )}
                            </div>
                          ) : <span className="text-gray-400">—</span>}
                        </td>
                      </>
                    ) : (
                      <>
                        <td className="px-5 py-3.5">
                          {s.status === 'completed' && s.config_json?.fixable_count != null
                            ? <span className="font-semibold text-green-600">{s.config_json.fixable_count}</span>
                            : <span className="text-gray-400">—</span>}
                        </td>
                        <td className="px-5 py-3.5">
                          {s.status === 'completed' && s.config_json?.no_fix_count != null
                            ? <span className="font-semibold text-red-500">{s.config_json.no_fix_count}</span>
                            : <span className="text-gray-400">—</span>}
                        </td>
                      </>
                    )}
                    <td className="px-5 py-3.5 text-xs text-gray-400 whitespace-nowrap">
                      {s.completed_at ? new Date(s.completed_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-5 py-3.5">
                      <div className="flex items-center justify-end gap-1">
                        {isClickable && <ChevronRight className="h-4 w-4 text-gray-300" />}
                        {isClickable && (
                          <button onClick={e => handleDownload(e, s)} disabled={downloadingId === s.id}
                            title="Download report"
                            className="rounded p-1.5 text-gray-400 hover:bg-blue-50 hover:text-blue-500 transition-colors disabled:opacity-40">
                            {downloadingId === s.id ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <FileDown className="h-3.5 w-3.5" />}
                          </button>
                        )}
                        <button onClick={e => handleDelete(e, s)} disabled={deletingId === s.id}
                          title="Delete scan"
                          className="rounded p-1.5 text-gray-400 hover:bg-red-50 hover:text-red-500 transition-colors disabled:opacity-40">
                          {deletingId === s.id ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
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
