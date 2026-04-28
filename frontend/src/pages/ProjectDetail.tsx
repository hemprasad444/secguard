import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ExternalLink, Play, RefreshCw, X, ChevronRight, ChevronDown, ChevronUp,
  Shield, Lock, FileText, Code, Globe, Server, ArrowLeft,
  ArrowUpDown, Filter, Download, Trash2, FileDown,
} from 'lucide-react';
import { getProject } from '../api/projects';
import { getScans, getScanFindings, getScanSbom, deleteScan } from '../api/scans';
import { getSummary } from '../api/dashboard';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
import K8sFindingsView from '../components/K8sFindingsView';
import SonarqubePanel from '../components/SonarqubePanel';

/* ------------------------------------------------------------------ */
/* Types                                                                 */
/* ------------------------------------------------------------------ */
interface Project {
  id: string;
  name: string;
  description: string | null;
  repository_url: string | null;
  created_at: string;
}

interface Scan {
  id: string;
  tool_name: string;
  scan_type: string;
  status: string;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
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
/* Helpers                                                               */
/* ------------------------------------------------------------------ */
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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

function scanIcon(scan: Scan) {
  const subtype = scan.config_json?.scan_subtype;
  if (subtype === 'secrets') return Lock;
  if (subtype === 'sbom') return FileText;
  if (subtype === 'k8s') return Server;
  if (scan.tool_name === 'semgrep') return Code;
  if (scan.tool_name === 'zap') return Globe;
  if (scan.tool_name === 'kubescape') return Server;
  return Shield;
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
function ConfirmModal({ title, message, confirmLabel = 'Delete', onConfirm, onCancel }: {
  title: string; message: string; confirmLabel?: string;
  onConfirm: () => void; onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4" onClick={onCancel}>
      <div className="w-full max-w-sm rounded-2xl bg-white shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="px-6 pt-6">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-red-100">
            <Trash2 className="h-5 w-5 text-red-600" />
          </div>
          <h3 className="mt-4 text-base font-semibold text-gray-900">{title}</h3>
          <p className="mt-1.5 text-sm text-gray-500">{message}</p>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4">
          <button onClick={onCancel} className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
          <button onClick={onConfirm} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700">
            {confirmLabel}
          </button>
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
  const meta = sbom.metadata?.component;
  return (
    <div className="space-y-4">
      {meta && (
        <div className="rounded-lg border border-purple-200 bg-purple-50 p-3">
          <p className="text-sm font-semibold text-purple-800">{meta.name}{meta.version ? ` @ ${meta.version}` : ''}</p>
          <p className="text-xs text-purple-500">{sbom.components.length} total components</p>
        </div>
      )}
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search components…"
        className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" />
      <div className="overflow-x-auto rounded-lg border border-gray-200">
        <table className="min-w-full divide-y divide-gray-200 text-sm">
          <thead className="bg-gray-50">
            <tr>
              {['Component', 'Version', 'Type', 'Licenses'].map(h => (
                <th key={h} className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-gray-500">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {components.map((c: any, i: number) => (
              <tr key={i} className="hover:bg-gray-50">
                <td className="px-4 py-2 font-medium text-gray-800">{c.name}</td>
                <td className="px-4 py-2 font-mono text-xs text-gray-500">{c.version ?? '—'}</td>
                <td className="px-4 py-2 text-xs text-gray-500">{c.type ?? '—'}</td>
                <td className="px-4 py-2 text-xs text-gray-500">
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
              <div className="flex items-start justify-between gap-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  {f.cve_id && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-600">{f.cve_id}</span>}
                  {f.cvss_score != null && <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cvssColor(f.cvss_score)}`}>CVSS {Number(f.cvss_score).toFixed(1)}</span>}
                  {refUrl && <a href={refUrl} target="_blank" rel="noopener noreferrer" className="rounded bg-blue-50 px-2 py-0.5 font-mono text-xs text-blue-600 hover:bg-blue-100 hover:underline" onClick={e => e.stopPropagation()}>Reference ↗</a>}
                </div>
                <StatusBadge status={f.status} />
              </div>
              <p className="mt-2 text-sm font-semibold text-gray-800">{f.title}</p>
              {f.file_path && <p className="mt-1.5 font-mono text-xs text-gray-400">{f.file_path}{f.line_number ? `:${f.line_number}` : ''}</p>}
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
                {group.installed && (
                  <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-500">{group.installed}</span>
                )}
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
                    {refUrl && <a href={refUrl} target="_blank" rel="noopener noreferrer" className="rounded bg-blue-50 px-2 py-0.5 font-mono text-xs text-blue-600 hover:bg-blue-100 hover:underline" onClick={e => e.stopPropagation()}>Reference ↗</a>}
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

  const downloadK8sReport = () => {
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

  const downloadReport = () => {
    if (isK8s) { downloadK8sReport(); return; }
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

  const Icon = scanIcon(scan);

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/40" onClick={onClose}>
      <div className="relative flex h-full w-full max-w-3xl flex-col bg-white shadow-2xl" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-start justify-between border-b px-6 py-4">
          <div className="flex items-start gap-3">
            <div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${isK8s ? 'bg-green-100' : 'bg-gray-100'}`}>
              <Icon className={`h-5 w-5 ${isK8s ? 'text-green-600' : 'text-gray-600'}`} />
            </div>
            <div>
              <p className="text-xs font-medium uppercase tracking-wide text-gray-400">{scanLabel(scan)}</p>
              <p className="mt-0.5 font-semibold text-gray-900">
                {isK8s ? `${scan.tool_name.charAt(0).toUpperCase() + scan.tool_name.slice(1)} Scan` : targetLabel(scan)}
              </p>
              <p className="mt-0.5 text-xs text-gray-400">
                {isSbom ? (
                  <>{scan.findings_count} components · {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}</>
                ) : loading ? (
                  <>{scan.findings_count} findings</>
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
                    <span className="font-medium text-gray-600">{findings.length}</span> total
                    {' · '}
                    <span className="font-medium text-gray-600">{uniquePkgCount}</span> unique packages
                    {' · '}
                    {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : '—'}
                  </>
                )}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {isSbom && sbom && (
              <button onClick={downloadSbom}
                className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-50">
                <Download className="h-4 w-4" /> Download JSON
              </button>
            )}
            {!isSbom && findings.length > 0 && (
              <button onClick={downloadReport}
                className="inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium text-gray-600 hover:bg-gray-50">
                <Download className="h-4 w-4" /> Download Report
              </button>
            )}
            <button onClick={onClose} className="rounded-lg p-1.5 hover:bg-gray-100">
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Filters — only for non-K8s, non-SBOM scans (K8s has its own filters built into K8sFindingsView) */}
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
/* Scan type definitions                                                  */
/* ------------------------------------------------------------------ */
const SCAN_TYPES = [
  { key: 'dependency', label: 'Dependency', icon: Shield },
  { key: 'secrets',    label: 'Secrets',    icon: Lock },
  { key: 'sbom',       label: 'SBOM',       icon: FileText },
  { key: 'sast',       label: 'SAST',       icon: Code },
  { key: 'dast',       label: 'DAST',       icon: Globe },
  { key: 'k8s',        label: 'Kubernetes', icon: Server },
] as const;

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

/* ------------------------------------------------------------------ */
/* Relative time helper                                                    */
/* ------------------------------------------------------------------ */
function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

/* ------------------------------------------------------------------ */
/* Scan type stats (from projects-overview endpoint)                      */
/* ------------------------------------------------------------------ */
interface TypeStats {
  total_findings: number;
  open_findings: number;
  closed_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixable_packages: number;
  no_fix_packages: number;
}

/* Map card key → backend label expected by dashboard endpoints */
const TYPE_LABEL: Record<string, string> = {
  dependency: 'Dependency',
  secrets:    'Secrets',
  sbom:       'SBOM',
  sast:       'SAST',
  dast:       'DAST',
  k8s:        'K8s',
};

/* ------------------------------------------------------------------ */
/* Scan type block                                                        */
/* ------------------------------------------------------------------ */
function ScanTypeBlock({ type, scans, stats, onTypeClick }: {
  type: typeof SCAN_TYPES[number];
  scans: Scan[];
  stats?: TypeStats;
  onView: (s: Scan) => void;
  onDownload: (e: React.MouseEvent, s: Scan) => void;
  onDelete: (e: React.MouseEvent, s: Scan) => void;
  onTypeClick: () => void;
  downloadingId: string | null;
  deletingId: string | null;
}) {
  const Icon = type.icon;
  const running = scans.filter(s => s.status === 'pending' || s.status === 'running').length;
  const completed = scans.filter(s => s.status === 'completed').length;
  const failed = scans.filter(s => s.status === 'failed').length;
  const isEmpty = scans.length === 0;
  const latest = scans[0];

  const critical = stats?.critical ?? 0;
  const high = stats?.high ?? 0;
  const totalFindings = stats?.total_findings ?? scans.reduce((s, x) => s + (x.findings_count || 0), 0);
  const openCount = stats?.open_findings ?? totalFindings;
  const closedCount = stats?.closed_findings ?? 0;
  const fixable = stats?.fixable_packages ?? 0;
  const noFix = stats?.no_fix_packages ?? 0;
  const isDependency = type.key === 'dependency';

  /* Health state - drives the single status dot */
  const health: 'empty' | 'running' | 'critical' | 'warning' | 'clean' | 'error' =
    isEmpty ? 'empty'
    : running > 0 ? 'running'
    : failed > 0 && completed === 0 ? 'error'
    : openCount === 0 && completed > 0 ? 'clean'
    : critical > 0 ? 'critical'
    : high > 0 ? 'warning'
    : totalFindings === 0 ? 'clean'
    : 'warning';

  const dotClass = {
    empty:    'bg-gray-300',
    running:  'bg-amber-500',
    critical: 'bg-red-500',
    warning:  'bg-amber-500',
    clean:    'bg-emerald-500',
    error:    'bg-red-500',
  }[health];

  const hasCritical = critical > 0 && openCount > 0;
  void health; void dotClass; // computed but unused in stripped-down card

  return (
    <button
      onClick={onTypeClick}
      className="group flex w-full items-center gap-4 border-b border-gray-100 bg-white px-4 py-3.5 text-left transition-colors last:border-b-0 hover:bg-gray-50/60"
    >
      {/* Icon + name */}
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <Icon className="h-4 w-4 shrink-0 text-gray-400" strokeWidth={2} />
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <h3 className="truncate text-[13px] font-medium text-gray-900">
              {type.label}
            </h3>
            {running > 0 && (
              <span className="inline-flex items-center gap-1 text-[11px] text-gray-500">
                <RefreshCw className="h-3 w-3 animate-spin" />
                running
              </span>
            )}
          </div>
          <p className="mt-0.5 truncate text-[11px] leading-4 text-gray-500">
            {isEmpty
              ? 'Not configured'
              : latest?.completed_at
                ? `${completed} completed${failed > 0 ? ` · ${failed} failed` : ''} · last ${relativeTime(latest.completed_at)}`
                : `${scans.length} scan${scans.length !== 1 ? 's' : ''}`}
          </p>
        </div>
      </div>

      {/* Metrics — three columns, fixed width, plain text */}
      {!isEmpty && (
        <div className="hidden sm:flex items-center gap-6 shrink-0">
          <div className="min-w-[52px] text-right">
            <div className={`text-[15px] font-semibold leading-none tabular-nums ${
              hasCritical ? 'text-gray-900' : openCount > 0 ? 'text-gray-800' : 'text-gray-300'
            }`}>
              {openCount.toLocaleString()}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-gray-400">Open</div>
          </div>
          <div className="min-w-[52px] text-right">
            <div className="text-[15px] font-semibold leading-none text-gray-400 tabular-nums">
              {closedCount.toLocaleString()}
            </div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-gray-400">Closed</div>
          </div>
          {isDependency && (
            <div className="min-w-[52px] text-right">
              <div className="text-[15px] font-semibold leading-none text-gray-800 tabular-nums">
                {fixable.toLocaleString()}
              </div>
              <div className="mt-1 text-[10px] uppercase tracking-wider text-gray-400">Fixable</div>
            </div>
          )}
        </div>
      )}

      <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />
    </button>
  );
}

/* Small inline svg dots/checks — sized to sit on the baseline */
function CheckDot({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 12 12" className={`h-3 w-3 ${className}`} aria-hidden>
      <circle cx="6" cy="6" r="5.25" fill="none" stroke="currentColor" strokeWidth="1.5" />
      <path d="M3.5 6.1l1.7 1.7 3.3-3.6" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function CheckCircleDot({ className = '' }: { className?: string }) {
  return (
    <svg viewBox="0 0 14 14" className={className} aria-hidden>
      <circle cx="7" cy="7" r="6.25" fill="currentColor" opacity="0.12" />
      <path d="M4.2 7.2l2 2 3.6-4" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/* ------------------------------------------------------------------ */
/* Main page                                                              */
/* ------------------------------------------------------------------ */
export default function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [statsByType, setStatsByType] = useState<Record<string, TypeStats>>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirmScan, setConfirmScan] = useState<Scan | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const fetchScans = useCallback(async () => {
    if (!id) return;
    const res = await getScans({ project_id: id, page_size: 200 });
    setScans(Array.isArray(res) ? res : (res.items ?? res.results ?? []));
  }, [id]);

  const fetchStats = useCallback(async () => {
    if (!id) return;
    const results = await Promise.all(
      SCAN_TYPES.map(async t => {
        try {
          const s = await getSummary(id, TYPE_LABEL[t.key]);
          return [t.key, {
            total_findings: s.total_findings ?? 0,
            open_findings: s.open_findings ?? 0,
            closed_findings: Math.max(0, (s.total_findings ?? 0) - (s.open_findings ?? 0)),
            critical: s.critical ?? 0,
            high: s.high ?? 0,
            medium: s.medium ?? 0,
            low: s.low ?? 0,
            fixable_packages: s.fixable_packages ?? 0,
            no_fix_packages: s.no_fix_packages ?? 0,
          } as TypeStats] as const;
        } catch {
          return [t.key, null] as const;
        }
      })
    );
    const next: Record<string, TypeStats> = {};
    for (const [k, v] of results) if (v) next[k] = v;
    setStatsByType(next);
  }, [id]);

  useEffect(() => {
    if (!id) return;
    (async () => {
      try {
        const [proj] = await Promise.all([getProject(id), fetchScans(), fetchStats()]);
        setProject(proj);
      } catch { setError('Failed to load project.'); }
      finally { setLoading(false); }
    })();
  }, [id, fetchScans, fetchStats]);

  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running');
    if (!hasActive) return;
    const t = setInterval(() => {
      fetchScans();
      fetchStats();
    }, 5000);
    return () => clearInterval(t);
  }, [scans, fetchScans, fetchStats]);

  const handleDeleteScan = useCallback((e: React.MouseEvent, scan: Scan) => {
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

  const handleRowDownload = useCallback(async (e: React.MouseEvent, scan: Scan) => {
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

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="h-7 w-64 animate-pulse rounded bg-gray-200" />
        <div className="h-64 animate-pulse rounded-lg bg-gray-100" />
      </div>
    );
  }

  if (error || !project) {
    return <div className="rounded-lg bg-red-50 p-4 text-sm text-red-700">{error || 'Project not found.'}</div>;
  }

  const scansFor = (key: string) =>
    scans.filter(s => scanTypeKey(s) === key)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const totalScans = scans.length;
  const totalFindings = scans.reduce((s, x) => s + (x.findings_count || 0), 0);
  const runningCount = scans.filter(s => s.status === 'pending' || s.status === 'running').length;

  return (
    <div className="max-w-6xl mx-auto space-y-5">
      {/* Back link */}
      <button onClick={() => navigate('/projects')}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Projects
      </button>

      {/* Header */}
      <div className="flex items-start justify-between border-b border-gray-200 pb-5">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900">{project.name}</h1>
          {project.description && (
            <p className="mt-1 text-sm text-gray-500">{project.description}</p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-gray-500">
            {project.repository_url && (
              <a href={project.repository_url} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 hover:text-gray-800 hover:underline">
                <ExternalLink className="h-3.5 w-3.5" />
                {project.repository_url.replace(/^https?:\/\//, '')}
              </a>
            )}
            <span>Created {new Date(project.created_at).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })}</span>
          </div>
        </div>
        <a href="/scans"
          className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white hover:bg-black transition-colors">
          <Play className="h-4 w-4" /> Run scan
        </a>
      </div>

      {/* Summary bar */}
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{totalScans}</span> {totalScans === 1 ? 'scan' : 'scans'}
        </span>
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{totalFindings.toLocaleString()}</span> findings
        </span>
        {runningCount > 0 && (
          <span className="inline-flex items-center gap-1 text-amber-600">
            <RefreshCw className="h-3 w-3 animate-spin" />
            {runningCount} running
          </span>
        )}
      </div>

      {/* Scan type blocks */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-gray-900">Scan Types</h2>
        <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
          {SCAN_TYPES.map(type => (
            <ScanTypeBlock
              key={type.key}
              type={type}
              scans={scansFor(type.key)}
              stats={statsByType[type.key]}
              onView={s => {
                const isK8sScan = s.config_json?.scan_subtype === 'k8s' || s.tool_name === 'kubescape';
                if (isK8sScan) navigate(`/projects/${id}/k8s/${s.id}`);
                else navigate(`/projects/${id}/scans/${s.id}`);
              }}
              onDownload={handleRowDownload}
              onDelete={handleDeleteScan}
              onTypeClick={() => navigate(`/projects/${id}/scan-types/${type.key}`)}
              downloadingId={downloadingId}
              deletingId={deletingId}
            />
          ))}
        </div>
      </div>

      {/* SonarQube integration (optional, per-project) */}
      {project && (
        <div>
          <h2 className="mb-3 text-sm font-semibold text-gray-900">Integrations</h2>
          <SonarqubePanel
            project={project as any}
            onUpdated={(p) => setProject(prev => prev ? { ...prev, ...p } as any : prev)}
          />
        </div>
      )}

      {/* Results Drawer */}
      {selectedScan && (
        <ScanResultsDrawer scan={selectedScan} onClose={() => setSelectedScan(null)} />
      )}

      {/* Delete Confirmation Modal */}
      {confirmScan && (
        <ConfirmModal
          title="Delete scan?"
          message={`This will permanently delete the ${scanLabel(confirmScan)} scan for "${targetLabel(confirmScan)}" and all its findings.`}
          onConfirm={confirmDelete}
          onCancel={() => setConfirmScan(null)}
        />
      )}
    </div>
  );
}
