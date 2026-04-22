import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, Filter, ArrowUpDown,
  Shield, Lock, FileText, Code, Globe, Server, RefreshCw,
  CheckCircle, XCircle, Package, ChevronDown, ChevronUp,
} from 'lucide-react';
import { getScan, getScanFindings, getScanSbom, triggerScan, getScans } from '../api/scans';
import SeverityBadge from '../components/common/SeverityBadge';
import StatusBadge from '../components/common/StatusBadge';
import K8sFindingsView from '../components/K8sFindingsView';
import FindingCloseModal from '../components/FindingCloseModal';
import { closeFinding } from '../api/findings';

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
  project_id?: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  tool_name?: string;
  cve_id?: string;
  cvss_score?: number;
  file_path?: string;
  line_number?: number;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
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
  return '';
}

function imageName(scan: Scan): string {
  return scan.config_json?.target ?? '';
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
/* SBOM View                                                              */
/* ------------------------------------------------------------------ */
function SbomView({ sbom }: { sbom: any }) {
  const [search, setSearch] = useState('');
  if (!sbom) return <p className="py-12 text-center text-sm text-gray-400">No SBOM data.</p>;
  const components: any[] = sbom.components ?? sbom.packages ?? [];
  const filtered = search
    ? components.filter(c => JSON.stringify(c).toLowerCase().includes(search.toLowerCase()))
    : components;
  return (
    <div className="space-y-3">
      <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search components..."
        className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-300" />
      <div className="overflow-hidden rounded-xl border border-gray-100">
        <table className="min-w-full divide-y divide-gray-100 text-sm">
          <thead className="bg-gray-50">
            <tr>
              {['Name', 'Version', 'Type', 'License'].map(h => (
                <th key={h} className="px-4 py-2 text-left text-xs font-semibold uppercase tracking-wider text-gray-400">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {filtered.slice(0, 300).map((c: any, i: number) => (
              <tr key={i} className="hover:bg-gray-50">
                <td className="px-4 py-2 font-medium text-gray-800">{c.name ?? c['package-name'] ?? ''}</td>
                <td className="px-4 py-2 font-mono text-xs text-gray-500">{c.version ?? c['package-version'] ?? ''}</td>
                <td className="px-4 py-2 text-xs text-gray-400">{c.type ?? c['package-type'] ?? ''}</td>
                <td className="px-4 py-2 text-xs text-gray-400">
                  {(c.licenses ?? []).map((l: any) => l?.license?.id ?? l?.expression ?? l).join(', ') || ''}
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
/* Image Verify Modal                                                     */
/* ------------------------------------------------------------------ */
interface VerifyResult {
  fixed: string[];
  stillOpen: string[];
  newFindings: Finding[];
  newImage: string;
  newScanId: string;
  newCveSet: Set<string>;
  oldCveSet: Set<string>;
}

function ImageVerifyModal({ scan, findings, onClose, onVerified }: {
  scan: Scan; findings: Finding[];
  onClose: () => void;
  onVerified: (result: VerifyResult) => void;
}) {
  const img = imageName(scan);
  const baseImage = img.split(':')[0] || img;
  const [newTag, setNewTag] = useState('');
  const [regUser, setRegUser] = useState(scan.config_json?.registry_username ?? '');
  const [regPass, setRegPass] = useState('');
  const [step, setStep] = useState<'input' | 'scanning' | 'done'>('input');
  const [progress, setProgress] = useState('');
  const [error, setError] = useState('');

  const fixableCves = [...new Set(
    findings
      .filter(f => f.raw_data?.FixedVersion || f.raw_data?.fixed_version)
      .filter(f => !['resolved', 'accepted', 'false_positive'].includes(f.status))
      .map(f => f.cve_id || f.title)
  )];

  const handleVerify = async () => {
    if (!newTag.trim()) { setError('Enter the fixed image tag'); return; }
    const fullImage = newTag.includes(':') ? newTag : `${baseImage}:${newTag}`;
    setStep('scanning');
    setProgress('Triggering scan...');
    setError('');

    try {
      const cfg: Record<string, any> = { target: fullImage, scan_subtype: 'dependency', scan_type: 'image' };
      if (regUser) cfg.registry_username = regUser;
      if (regPass) cfg.registry_password = regPass;
      const newScan = await triggerScan({
        project_id: scan.project_id || scan.config_json?.project_id || '',
        tool_name: 'trivy',
        config: cfg,
      });
      const newScanId = newScan.id || newScan.scan_id;

      // Poll for completion
      setProgress('Scanning new image...');
      let attempts = 0;
      while (attempts < 120) {
        await new Promise(r => setTimeout(r, 3000));
        attempts++;
        try {
          const s = await getScan(newScanId);
          if (s.status === 'completed') {
            setProgress('Comparing results...');
            const newData = await getScanFindings(newScanId, 1, 1000);
            const newFindingsList: Finding[] = Array.isArray(newData) ? newData : (newData.items ?? newData.results ?? []);
            const newCveSet = new Set(newFindingsList.map(f => f.cve_id || f.title));
            const oldCveSet = new Set(findings.map(f => f.cve_id || f.title));

            const fixed = fixableCves.filter(c => !newCveSet.has(c));
            const stillOpen = fixableCves.filter(c => newCveSet.has(c));

            onVerified({ fixed, stillOpen, newFindings: newFindingsList, newImage: fullImage, newScanId, newCveSet, oldCveSet });
            setStep('done');
            return;
          }
          if (s.status === 'failed') {
            setError(s.error_message || 'Scan failed');
            setStep('input');
            return;
          }
          setProgress(`Scanning... (${Math.round(attempts * 3)}s)`);
        } catch { /* keep polling */ }
      }
      setError('Scan timed out');
      setStep('input');
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to trigger scan');
      setStep('input');
    }
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="border-b px-6 py-4">
          <h2 className="text-base font-bold text-gray-900">Verify Fixed Image</h2>
          <p className="text-xs text-gray-500 mt-1">
            Scan the updated image and compare with {fixableCves.length} fixable CVEs
          </p>
        </div>

        <div className="px-6 py-4 space-y-4">
          <div className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-2">
            <p className="text-[10px] text-gray-400 uppercase font-semibold">Original Image</p>
            <p className="font-mono text-sm text-gray-800">{img}</p>
          </div>

          {step === 'input' && (
            <>
              <div>
                <label className="block text-xs font-semibold text-gray-600 mb-1">Fixed Image Tag</label>
                <input value={newTag} onChange={e => setNewTag(e.target.value)}
                  placeholder={`${baseImage}:latest or full image:tag`}
                  className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-blue-400" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-500 mb-1">Registry Username</label>
                  <input value={regUser} onChange={e => setRegUser(e.target.value)} placeholder="optional"
                    className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 mb-1">Password / Token</label>
                  <input type="password" value={regPass} onChange={e => setRegPass(e.target.value)} placeholder="optional"
                    className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-blue-400" />
                </div>
              </div>
            </>
          )}

          {step === 'scanning' && (
            <div className="flex flex-col items-center py-6 gap-3">
              <RefreshCw className="h-8 w-8 animate-spin text-blue-500" />
              <p className="text-sm font-medium text-gray-600">{progress}</p>
            </div>
          )}

          {error && (
            <div className="rounded-lg bg-red-50 border border-red-200 px-3 py-2 text-xs text-red-700">{error}</div>
          )}
        </div>

        <div className="flex justify-end gap-3 border-t px-6 py-4">
          <button onClick={onClose} className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
          {step === 'input' && (
            <button onClick={handleVerify} disabled={!newTag.trim()}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-50">
              Scan & Compare
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Main Page                                                              */
/* ------------------------------------------------------------------ */
export default function ScanDetail() {
  const { projectId, scanId } = useParams<{ projectId: string; scanId: string }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sbom, setSbom] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'severity' | 'cvss' | 'title'>('severity');
  const [fixableOnly, setFixableOnly] = useState(false);
  const [closingFinding, setClosingFinding] = useState<Finding | null>(null);
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [closingAll, setClosingAll] = useState(false);
  const [compareView, setCompareView] = useState<'old' | 'new' | 'diff'>('diff');

  useEffect(() => {
    if (!scanId) return;
    (async () => {
      setLoading(true);
      try {
        const s: Scan = await getScan(scanId);
        setScan(s);
        const isSbom = s.config_json?.scan_subtype === 'sbom';
        if (isSbom) {
          setSbom(await getScanSbom(scanId));
        } else {
          const data = await getScanFindings(scanId, 1, 1000);
          setFindings(Array.isArray(data) ? data : (data.items ?? data.results ?? []));
        }
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [scanId]);

  if (loading || !scan) {
    return (
      <div className="flex h-full items-center justify-center">
        <RefreshCw className="h-6 w-6 animate-spin text-gray-400" />
      </div>
    );
  }

  const isSbom = scan.config_json?.scan_subtype === 'sbom';
  const isK8s = scan.config_json?.scan_subtype === 'k8s' || scan.tool_name === 'kubescape';
  const isSecrets = scan.config_json?.scan_subtype === 'secrets';
  const isDep = !isSbom && !isK8s && !isSecrets && scan.tool_name === 'trivy';
  const Icon = scanIcon(scan);
  const img = imageName(scan);

  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const openCount = findings.filter(f => !closedStatuses.includes(f.status)).length;
  const closedCount = findings.filter(f => closedStatuses.includes(f.status)).length;
  const fixableCount = findings.filter(f => (f.raw_data?.FixedVersion || f.raw_data?.fixed_version) && !closedStatuses.includes(f.status)).length;
  const noFixCount = findings.filter(f => !(f.raw_data?.FixedVersion || f.raw_data?.fixed_version) && !closedStatuses.includes(f.status)).length;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings.filter(ff => !closedStatuses.includes(ff.status))) {
    const s = f.severity as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  // Use new findings when viewing new image comparison
  const activeFindingsList = (verifyResult && compareView === 'new') ? verifyResult.newFindings : findings;

  const filtered = activeFindingsList
    .filter(f => {
      if (statusFilter === 'open') return !closedStatuses.includes(f.status);
      if (statusFilter === 'closed') return closedStatuses.includes(f.status);
      return true;
    })
    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
    .filter(f => !fixableOnly || (f.raw_data?.FixedVersion || f.raw_data?.fixed_version))
    .sort((a, b) => {
      if (sortBy === 'severity') return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
      if (sortBy === 'cvss') return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
      return a.title.localeCompare(b.title);
    });

  // Group by package
  type Group = { key: string; pkg: string | null; installed: string; items: Finding[] };
  const groups: Group[] = [];
  const idx = new Map<string, number>();
  for (const f of filtered) {
    const pkg = (f.raw_data?.PkgName ?? f.raw_data?.pkg_name) as string | undefined;
    if (!pkg) { groups.push({ key: f.id, pkg: null, installed: '', items: [f] }); continue; }
    const installed = (f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '') as string;
    const key = `${pkg}||${installed}`;
    const pos = idx.get(key);
    if (pos !== undefined) { groups[pos].items.push(f); }
    else { idx.set(key, groups.length); groups.push({ key, pkg, installed, items: [f] }); }
  }

  const handleVerified = async (result: VerifyResult) => {
    setVerifyResult(result);
    setCompareView('diff');
    if (result.fixed.length > 0) {
      setClosingAll(true);
      for (const f of findings) {
        const cve = f.cve_id || f.title;
        if (result.fixed.includes(cve) && !closedStatuses.includes(f.status)) {
          try {
            const updated = await closeFinding(f.id, {
              status: 'resolved',
              close_reason: 'rescan_verified',
              justification: `Verified fixed in new image: ${result.newImage}`,
            });
            setFindings(prev => prev.map(pf => pf.id === f.id ? { ...pf, ...updated } : pf));
          } catch { /* skip */ }
        }
      }
      setClosingAll(false);
    }
  };

  const downloadReport = () => {
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
        'Status': group.items.every(f => closedStatuses.includes(f.status)) ? 'Closed' : 'Open',
        'CVE IDs': [...new Set(group.items.map(f => f.cve_id).filter(Boolean))].join(', '),
        'Fixed Version': fixedVer,
        'Description': topCve.description ?? '',
      });
    }
    const ws = XLSX.utils.json_to_sheet(rows);
    ws['!cols'] = [22, 14, 10, 8, 40, 14, 60].map(w => ({ wch: w }));
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'Findings');
    XLSX.writeFile(wb, `${scanLabel(scan)}-${targetLabel(scan)}-report.xlsx`);
  };

  return (
    <div className="space-y-6">
      {/* Breadcrumb */}
      <button onClick={() => navigate(-1)}
        className="inline-flex items-center gap-1.5 text-sm text-gray-500 hover:text-gray-800">
        <ArrowLeft className="h-4 w-4" /> Back
      </button>

      {/* Image header */}
      <div className="border border-gray-200 bg-white rounded-md p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded border border-gray-200 bg-gray-50">
              <Icon className="h-5 w-5 text-gray-700" />
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">{scanLabel(scan)}</p>
              {img ? (
                <h1 className="mt-0.5 text-sm font-semibold text-gray-900 font-mono break-all">{img}</h1>
              ) : (
                <h1 className="mt-0.5 text-base font-semibold text-gray-900">{targetLabel(scan) || 'Scan Results'}</h1>
              )}
              <p className="mt-1 text-xs text-gray-500 font-mono">
                {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : ''}
              </p>
              {/* Stats row - flat style with vertical bars */}
              <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono">
                <span><span className="font-semibold text-gray-900 tabular-nums">{findings.length}</span> <span className="text-gray-500">total</span></span>
                <span className="border-l-2 border-red-600 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> <span className="text-gray-500">open</span></span>
                <span className="border-l-2 border-green-600 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{closedCount}</span> <span className="text-gray-500">closed</span></span>
                {isDep && (
                  <>
                    <span className="border-l-2 border-emerald-500 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{fixableCount}</span> <span className="text-gray-500">fixable</span></span>
                    <span className="border-l-2 border-gray-300 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{noFixCount}</span> <span className="text-gray-500">no-fix</span></span>
                  </>
                )}
                {sevCounts.critical > 0 && <span className="border-l-2 border-red-600 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{sevCounts.critical}</span> <span className="text-gray-500">Crit</span></span>}
                {sevCounts.high > 0 && <span className="border-l-2 border-orange-500 pl-2"><span className="font-semibold text-gray-900 tabular-nums">{sevCounts.high}</span> <span className="text-gray-500">High</span></span>}
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-wrap items-center gap-2">
            {(isDep || isSecrets) && openCount > 0 && (
              <button onClick={() => setShowVerifyModal(true)}
                className="inline-flex items-center gap-1.5 rounded border border-gray-900 bg-gray-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-gray-800">
                <CheckCircle className="h-3.5 w-3.5" /> Verify Fixed Image
              </button>
            )}
            {openCount === 0 && findings.length > 0 && (
              <span className="inline-flex items-center gap-1.5 rounded border border-green-600 bg-green-50 px-3 py-1.5 text-xs font-semibold text-green-700">
                <CheckCircle className="h-3.5 w-3.5" /> All Closed
              </span>
            )}
            {!isSbom && findings.length > 0 && (
              <button onClick={downloadReport}
                className="inline-flex items-center gap-1.5 rounded-lg border border-gray-200 bg-white px-3 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
                <Download className="h-4 w-4" /> Export
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Comparison panel */}
      {verifyResult && (() => {
        const newOnlyCves = [...verifyResult.newCveSet].filter(c => !verifyResult.oldCveSet.has(c));
        return (
          <div className="space-y-4">
            {/* Summary banner */}
            <div className={`rounded-2xl border p-4 ${verifyResult.stillOpen.length === 0 ? 'border-green-200 bg-green-50' : 'border-amber-200 bg-amber-50'}`}>
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  {verifyResult.stillOpen.length === 0 ? (
                    <CheckCircle className="h-5 w-5 text-green-600 mt-0.5 shrink-0" />
                  ) : (
                    <XCircle className="h-5 w-5 text-amber-600 mt-0.5 shrink-0" />
                  )}
                  <div>
                    <p className="text-sm font-bold text-gray-900">
                      Comparison: {imageName(scan)} vs {verifyResult.newImage}
                    </p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      <span className="rounded-lg bg-green-100 border border-green-200 px-2.5 py-1 text-xs font-bold text-green-700">
                        {verifyResult.fixed.length} Fixed
                      </span>
                      <span className="rounded-lg bg-red-100 border border-red-200 px-2.5 py-1 text-xs font-bold text-red-700">
                        {verifyResult.stillOpen.length} Still Open
                      </span>
                      {newOnlyCves.length > 0 && (
                        <span className="rounded-lg bg-purple-100 border border-purple-200 px-2.5 py-1 text-xs font-bold text-purple-700">
                          {newOnlyCves.length} New in updated image
                        </span>
                      )}
                      <span className="rounded-lg bg-gray-100 border border-gray-200 px-2.5 py-1 text-xs font-bold text-gray-600">
                        {findings.length} Old total / {verifyResult.newFindings.length} New total
                      </span>
                    </div>
                  </div>
                </div>
                <button onClick={() => setVerifyResult(null)}
                  className="text-xs text-gray-400 hover:text-gray-600 shrink-0">Clear</button>
              </div>
            </div>

            {/* View toggle */}
            <div className="flex items-center gap-1 rounded-xl bg-gray-100 p-1 w-fit">
              {([
                { key: 'diff' as const, label: 'Changes' },
                { key: 'old' as const, label: `Old (${imageName(scan).split(':').pop()})` },
                { key: 'new' as const, label: `New (${verifyResult.newImage.split(':').pop()})` },
              ]).map(v => (
                <button key={v.key} onClick={() => setCompareView(v.key)}
                  className={`rounded-lg px-4 py-2 text-xs font-semibold transition-all ${
                    compareView === v.key ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'
                  }`}>
                  {v.label}
                </button>
              ))}
            </div>

            {/* Diff view */}
            {compareView === 'diff' && (
              <div className="space-y-2">
                {verifyResult.fixed.length > 0 && (
                  <div className="rounded-xl border border-green-200 bg-green-50/50 p-4">
                    <p className="text-xs font-bold text-green-700 uppercase tracking-wider mb-2">Fixed ({verifyResult.fixed.length})</p>
                    <div className="space-y-1.5">
                      {verifyResult.fixed.map(cve => {
                        const f = findings.find(ff => (ff.cve_id || ff.title) === cve);
                        return (
                          <div key={cve} className="flex items-center gap-2 text-xs">
                            <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />
                            {f && <SeverityBadge severity={f.severity} />}
                            <span className="font-mono text-gray-600">{cve}</span>
                            {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data.PkgName as string}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {verifyResult.stillOpen.length > 0 && (
                  <div className="rounded-xl border border-red-200 bg-red-50/50 p-4">
                    <p className="text-xs font-bold text-red-700 uppercase tracking-wider mb-2">Still Open ({verifyResult.stillOpen.length})</p>
                    <div className="space-y-1.5">
                      {verifyResult.stillOpen.map(cve => {
                        const f = findings.find(ff => (ff.cve_id || ff.title) === cve);
                        return (
                          <div key={cve} className="flex items-center gap-2 text-xs">
                            <XCircle className="h-3 w-3 text-red-500 shrink-0" />
                            {f && <SeverityBadge severity={f.severity} />}
                            <span className="font-mono text-gray-600">{cve}</span>
                            {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data.PkgName as string}</span>}
                            {f?.raw_data?.FixedVersion && <span className="text-green-600 font-mono">fix: {f.raw_data.FixedVersion as string}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {newOnlyCves.length > 0 && (
                  <div className="rounded-xl border border-purple-200 bg-purple-50/50 p-4">
                    <p className="text-xs font-bold text-purple-700 uppercase tracking-wider mb-2">New in updated image ({newOnlyCves.length})</p>
                    <div className="space-y-1.5">
                      {newOnlyCves.slice(0, 50).map(cve => {
                        const f = verifyResult.newFindings.find(ff => (ff.cve_id || ff.title) === cve);
                        return (
                          <div key={cve} className="flex items-center gap-2 text-xs">
                            <Package className="h-3 w-3 text-purple-500 shrink-0" />
                            {f && <SeverityBadge severity={f.severity} />}
                            <span className="font-mono text-gray-600">{cve}</span>
                            {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data?.PkgName as string}</span>}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })()}

      {/* Filters */}
      {!isSbom && !isK8s && findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-gray-200 bg-white px-4 py-3">
          <Filter className="h-3.5 w-3.5 text-gray-400" />
          {['all', 'open', 'closed'].map(s => (
            <button key={s} onClick={() => setStatusFilter(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                statusFilter === s ? 'bg-gray-800 text-white' : 'bg-white border border-gray-200 text-gray-500 hover:bg-gray-100'
              }`}>
              {s === 'all' ? `All (${findings.length})` : s === 'open' ? `Open (${openCount})` : `Closed (${closedCount})`}
            </button>
          ))}
          <span className="mx-1 text-gray-300">|</span>
          {['all', 'critical', 'high', 'medium', 'low'].map(s => (
            <button key={s} onClick={() => setSeverityFilter(s)}
              className={`rounded-full px-2.5 py-1 text-xs font-medium capitalize transition-colors ${
                severityFilter === s ? 'bg-gray-800 text-white' : 'bg-white border border-gray-200 text-gray-500 hover:bg-gray-100'
              }`}>
              {s === 'all' ? 'All Sev' : s}
            </button>
          ))}
          <div className="ml-auto flex items-center gap-2">
            {isDep && (
              <button onClick={() => setFixableOnly(v => !v)}
                className={`rounded-full border px-2.5 py-1 text-xs font-medium transition-colors ${
                  fixableOnly ? 'bg-green-600 border-green-600 text-white' : 'bg-white border-gray-200 text-gray-500 hover:bg-gray-100'
                }`}>
                {fixableOnly ? 'Fixable only' : 'All packages'}
              </button>
            )}
            <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
              className="rounded-lg border border-gray-200 bg-white px-2 py-1 text-xs text-gray-600 focus:outline-none">
              <option value="severity">Severity</option>
              <option value="cvss">CVSS</option>
              <option value="title">Name</option>
            </select>
          </div>
        </div>
      )}

      {/* Findings - hidden when showing diff comparison */}
      {(!verifyResult || compareView !== 'diff') && <div className="space-y-3">
        {/* Show which image we're viewing */}
        {verifyResult && (
          <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-2 text-sm font-medium text-blue-700">
            Showing: {compareView === 'new' ? verifyResult.newImage : imageName(scan)}
            {compareView === 'new' && ` (${verifyResult.newFindings.length} findings)`}
          </div>
        )}
        {isSbom ? (
          <SbomView sbom={sbom} />
        ) : isK8s ? (
          <K8sFindingsView findings={findings} />
        ) : groups.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-gray-200 py-16 text-center text-sm text-gray-400">
            {findings.length === 0 ? 'No findings.' : 'No findings match filters.'}
          </div>
        ) : (
          groups.map(group => {
            const allFixed = group.items.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version ?? '').filter(Boolean).join(',');
            const fixed = highestVersion(allFixed);
            const worstSev = group.items.reduce((w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w, group.items[0].severity);
            const allClosed = group.items.every(f => closedStatuses.includes(f.status));
            const topCve = group.items.reduce((best, f) => {
              const bs = best.cvss_score ?? 0, fs = f.cvss_score ?? 0;
              return fs > bs ? f : best;
            });
            const refUrl = topCve.raw_data?.PrimaryURL;

            return (
              <div key={group.key} className={`rounded-xl border p-4 transition-colors ${allClosed ? 'border-green-200 bg-green-50/30' : 'border-gray-200 hover:border-gray-300'}`}>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <SeverityBadge severity={worstSev} />
                    {group.pkg ? (
                      <>
                        <span className="font-semibold text-gray-800">{group.pkg}</span>
                        {group.installed && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-500">{group.installed}</span>}
                      </>
                    ) : (
                      <span className="font-semibold text-gray-800">{topCve.title}</span>
                    )}
                    {topCve.cve_id && <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-600">{topCve.cve_id}</span>}
                    {topCve.cvss_score != null && <span className={`rounded px-2 py-0.5 text-xs font-semibold ${cvssColor(topCve.cvss_score)}`}>CVSS {Number(topCve.cvss_score).toFixed(1)}</span>}
                    {refUrl && <a href={refUrl} target="_blank" rel="noopener noreferrer" className="rounded bg-blue-50 px-2 py-0.5 text-xs text-blue-600 hover:underline" onClick={e => e.stopPropagation()}>Ref ↗</a>}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {group.pkg && <span className="text-xs text-gray-400">{group.items.length} CVE{group.items.length !== 1 ? 's' : ''}</span>}
                    {allClosed ? (
                      <button onClick={() => setClosingFinding({ ...group.items[0], tool_name: scan.tool_name })}
                        className="rounded-lg bg-green-100 border border-green-200 px-2.5 py-1 text-xs font-semibold text-green-700 hover:bg-green-200">
                        Closed
                      </button>
                    ) : (
                      <button onClick={() => setClosingFinding({ ...group.items[0], tool_name: scan.tool_name })}
                        className="rounded-lg bg-red-50 border border-red-200 px-2.5 py-1 text-xs font-semibold text-red-600 hover:bg-red-100">
                        Close
                      </button>
                    )}
                  </div>
                </div>

                {topCve.description && (
                  <p className="mt-2 text-xs text-gray-500 line-clamp-2">{topCve.description}</p>
                )}

                {fixed && !allClosed && (
                  <div className="mt-2 flex items-center gap-2 rounded-lg border border-green-200 bg-green-50 px-3 py-1.5">
                    <CheckCircle className="h-3 w-3 text-green-600" />
                    <span className="text-xs font-semibold text-green-700">Fix: upgrade to</span>
                    <span className="rounded bg-green-700 px-2 py-0.5 font-mono text-xs font-bold text-white">{fixed}</span>
                  </div>
                )}

                {allClosed && group.items[0].close_reason && (
                  <p className="mt-1.5 text-xs text-green-600">
                    {group.items[0].close_reason.replace(/_/g, ' ')}
                    {group.items[0].closed_at && ` - ${new Date(group.items[0].closed_at).toLocaleDateString()}`}
                  </p>
                )}
              </div>
            );
          })
        )}
      </div>}

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

      {/* Image verify modal */}
      {showVerifyModal && scan && (
        <ImageVerifyModal
          scan={scan}
          findings={findings}
          onClose={() => setShowVerifyModal(false)}
          onVerified={(result) => { setShowVerifyModal(false); handleVerified(result); }}
        />
      )}
    </div>
  );
}
