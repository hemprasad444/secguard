import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import * as XLSX from 'xlsx';
import {
  ArrowLeft, Download, ArrowUpDown, Search,
  Shield, Lock, FileText, Code, Globe, Server, RefreshCw,
  CheckCircle, XCircle, Package, ChevronRight, ChevronDown,
} from 'lucide-react';
import { getScan, getScanFindings, getScanSbom, triggerScan, getScans } from '../api/scans';
import K8sFindingsView from '../components/K8sFindingsView';
import SastFindingsView from '../components/SastFindingsView';
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
  created_at?: string | null;
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
/* Secrets View                                                           */
/* ------------------------------------------------------------------ */
function SecretsFindingsView({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const closedStatuses = ['resolved', 'accepted', 'false_positive'];

  if (findings.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
        No secrets match filters.
      </div>
    );
  }

  const sevDot = (sev: string) =>
    sev === 'critical' ? 'bg-red-500'
      : sev === 'high' ? 'bg-amber-500'
      : sev === 'medium' ? 'bg-yellow-400'
      : sev === 'low' ? 'bg-blue-400' : 'bg-gray-300';
  const sevText = (sev: string) =>
    sev === 'critical' ? 'text-red-700'
      : sev === 'high' ? 'text-amber-700'
      : sev === 'medium' ? 'text-yellow-700'
      : sev === 'low' ? 'text-blue-700' : 'text-gray-500';

  return (
    <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
      {/* Column headers */}
      <div className="hidden md:grid grid-cols-[110px_160px_minmax(0,1fr)_70px_16px] items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
        <span>Severity</span>
        <span>Rule</span>
        <span>File</span>
        <span className="text-right">Line</span>
        <span />
      </div>

      {findings.map(f => {
        const r = f.raw_data ?? {};
        const isClosed = closedStatuses.includes(f.status);
        const isOpen = expanded[f.id];
        const rule = (r.RuleID as string) ?? '';
        const category = (r.Category as string) ?? '';
        const codeLines = Array.isArray(r.Code?.Lines) ? r.Code.Lines as any[] : [];

        return (
          <div key={f.id} className={`border-b border-gray-100 last:border-b-0 ${isClosed ? 'opacity-60' : ''}`}>
            <button
              onClick={() => setExpanded(p => ({ ...p, [f.id]: !p[f.id] }))}
              className="group grid w-full grid-cols-[110px_160px_minmax(0,1fr)_70px_16px] items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-gray-50/60"
            >
              {/* Severity */}
              <div className="flex items-center gap-2">
                <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${sevDot(f.severity)}`} />
                <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(f.severity)}`}>{f.severity}</span>
              </div>
              {/* Rule */}
              <div className="min-w-0">
                <span className="block font-mono text-[12px] text-gray-800 truncate">{rule || '—'}</span>
                {category && rule !== category && (
                  <span className="block text-[10px] text-gray-400 truncate">{category}</span>
                )}
              </div>
              {/* File */}
              <div className="min-w-0">
                <span className="block font-mono text-[12px] text-gray-700 truncate" title={f.file_path ?? ''}>
                  {f.file_path ?? f.title}
                </span>
                {f.title && f.file_path && f.title !== f.file_path && (
                  <span className="block text-[11px] text-gray-500 truncate">{f.title}</span>
                )}
              </div>
              {/* Line */}
              <div className="text-right">
                {f.line_number != null ? (
                  <span className="font-mono text-[12px] text-gray-600 tabular-nums">{f.line_number}</span>
                ) : <span className="text-[11px] text-gray-300">—</span>}
              </div>
              <span className="shrink-0">
                {isOpen
                  ? <ChevronDown className="h-4 w-4 text-gray-400" />
                  : <ChevronRight className="h-4 w-4 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />}
              </span>
            </button>

            {isOpen && (
              <div className="border-t border-gray-100 bg-gray-50/40 px-4 py-3 space-y-3">
                {f.remediation && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Remediation</p>
                    <p className="text-[13px] text-gray-700 leading-relaxed">{f.remediation}</p>
                  </div>
                )}
                {(f.description || r.Match) && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Match</p>
                    <code className="block whitespace-pre-wrap break-all rounded border border-gray-200 bg-white px-3 py-2 font-mono text-[11px] text-gray-700">
                      {(r.Match as string) || f.description}
                    </code>
                  </div>
                )}
                {codeLines.length > 0 && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Context ({f.file_path}{f.line_number ? `:${f.line_number}` : ''})</p>
                    <div className="rounded border border-gray-200 bg-white overflow-hidden">
                      {codeLines.map((ln: any, i: number) => (
                        <div key={i}
                          className={`grid grid-cols-[56px_1fr] items-start gap-2 px-3 py-1 font-mono text-[11px] ${
                            ln.IsCause ? 'bg-amber-50/60' : ''
                          }`}>
                          <span className="text-right text-gray-400 tabular-nums select-none">{ln.Number}</span>
                          <span className={`whitespace-pre-wrap break-all ${ln.IsCause ? 'text-amber-900 font-medium' : 'text-gray-700'}`}>
                            {ln.Content ?? ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-x-6 gap-y-1 text-[11px]">
                  {rule && (
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">Rule</span>
                      <span className="font-mono text-gray-700">{rule}</span>
                    </div>
                  )}
                  {category && (
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">Category</span>
                      <span className="font-mono text-gray-700">{category}</span>
                    </div>
                  )}
                  {r.StartLine != null && r.EndLine != null && (
                    <div className="flex items-center gap-2">
                      <span className="text-gray-400">Range</span>
                      <span className="font-mono text-gray-700 tabular-nums">{r.StartLine as number}–{r.EndLine as number}</span>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* SBOM View                                                              */
/* ------------------------------------------------------------------ */
function getProp(c: any, name: string): string | null {
  for (const p of c?.properties ?? []) {
    if (p?.name === name) return p?.value ?? null;
  }
  return null;
}
function getPkgManager(c: any): string | null {
  const trivyType = getProp(c, 'aquasecurity:trivy:PkgType');
  if (trivyType) return trivyType;
  const purl: string = c?.purl ?? '';
  const m = purl.match(/^pkg:([^/]+)\//);
  return m ? m[1] : null;
}
function getLicenseList(c: any): string[] {
  const out: string[] = [];
  for (const l of c?.licenses ?? []) {
    const v = l?.license?.id ?? l?.license?.name ?? l?.expression ?? l?.name ?? '';
    if (v) out.push(v);
  }
  return out;
}

function SbomView({ sbom }: { sbom: any }) {
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [pkgMgrFilter, setPkgMgrFilter] = useState('all');
  const [licenseFilter, setLicenseFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'name' | 'type' | 'license'>('name');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showAll, setShowAll] = useState(false);

  if (!sbom) return <p className="py-12 text-center text-sm text-gray-400">No SBOM data.</p>;

  const components: any[] = sbom.components ?? sbom.packages ?? [];
  const meta = sbom.metadata?.component;

  // Aggregate facets
  const types = new Set<string>();
  const pkgMgrs = new Set<string>();
  const licenseCounts = new Map<string, number>();
  const layers = new Set<string>();
  let unlicensed = 0;
  for (const c of components) {
    if (c.type) types.add(c.type);
    const m = getPkgManager(c); if (m) pkgMgrs.add(m);
    const ls = getLicenseList(c);
    if (ls.length === 0) unlicensed++;
    for (const l of ls) licenseCounts.set(l, (licenseCounts.get(l) ?? 0) + 1);
    const ld = getProp(c, 'aquasecurity:trivy:LayerDigest');
    if (ld) layers.add(ld);
  }
  const topLicenses = [...licenseCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 12)
    .map(([l]) => l);

  // Filter + sort
  const q = search.trim().toLowerCase();
  const filtered = components.filter(c => {
    if (typeFilter !== 'all' && c.type !== typeFilter) return false;
    if (pkgMgrFilter !== 'all' && getPkgManager(c) !== pkgMgrFilter) return false;
    if (licenseFilter !== 'all') {
      const ls = getLicenseList(c);
      if (licenseFilter === '__none__') {
        if (ls.length > 0) return false;
      } else {
        if (!ls.includes(licenseFilter)) return false;
      }
    }
    if (q) {
      const name = (c.name ?? '').toLowerCase();
      const ver = (c.version ?? '').toLowerCase();
      const purl = (c.purl ?? '').toLowerCase();
      if (!name.includes(q) && !ver.includes(q) && !purl.includes(q)) return false;
    }
    return true;
  }).sort((a, b) => {
    if (sortBy === 'name') return (a.name ?? '').localeCompare(b.name ?? '');
    if (sortBy === 'type') return (a.type ?? '').localeCompare(b.type ?? '') || (a.name ?? '').localeCompare(b.name ?? '');
    if (sortBy === 'license') return getLicenseList(a).join(',').localeCompare(getLicenseList(b).join(',')) || (a.name ?? '').localeCompare(b.name ?? '');
    return 0;
  });

  const visible = showAll ? filtered : filtered.slice(0, 500);

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(sbom, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const baseName = (meta?.name ?? 'sbom').replace(/[^a-z0-9]+/gi, '_').slice(0, 80);
    a.download = `${baseName}.cdx.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Stats strip + meta */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{components.length.toLocaleString()}</span> components
        </span>
        {types.size > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{types.size}</span> {types.size === 1 ? 'type' : 'types'}
          </span>
        )}
        {pkgMgrs.size > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{pkgMgrs.size}</span> {pkgMgrs.size === 1 ? 'ecosystem' : 'ecosystems'}
          </span>
        )}
        {licenseCounts.size > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{licenseCounts.size}</span> {licenseCounts.size === 1 ? 'license' : 'licenses'}
          </span>
        )}
        {layers.size > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{layers.size}</span> {layers.size === 1 ? 'layer' : 'layers'}
          </span>
        )}
        {unlicensed > 0 && (
          <span className="inline-flex items-center gap-1.5 text-gray-500">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            <span className="font-semibold text-gray-900 tabular-nums">{unlicensed}</span> unlicensed
          </span>
        )}
        <button onClick={downloadJson}
          className="ml-auto inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 transition-colors">
          <Download className="h-3.5 w-3.5" /> Download CycloneDX JSON
        </button>
      </div>

      {/* Image / tool meta */}
      {(meta || sbom.metadata?.tools) && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-2.5 text-[11px]">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
            {meta?.name && (
              <span className="inline-flex items-center gap-1.5 text-gray-500">
                <Package className="h-3 w-3 text-gray-400" />
                <span className="text-gray-400">Subject</span>
                <span className="font-mono text-gray-700 break-all">{meta.name}</span>
              </span>
            )}
            {meta?.type && (
              <span className="inline-flex items-center gap-1.5 text-gray-500">
                <span className="text-gray-400">Type</span>
                <span className="text-gray-700">{meta.type}</span>
              </span>
            )}
            {sbom.bomFormat && (
              <span className="inline-flex items-center gap-1.5 text-gray-500">
                <span className="text-gray-400">Format</span>
                <span className="font-mono text-gray-700">{sbom.bomFormat}{sbom.specVersion ? ` ${sbom.specVersion}` : ''}</span>
              </span>
            )}
            {(() => {
              const tools = sbom.metadata?.tools?.components ?? sbom.metadata?.tools ?? [];
              const tool = Array.isArray(tools) ? tools[0] : null;
              if (!tool) return null;
              return (
                <span className="inline-flex items-center gap-1.5 text-gray-500">
                  <span className="text-gray-400">Generator</span>
                  <span className="font-mono text-gray-700">{tool.name}{tool.version ? ` ${tool.version}` : ''}</span>
                </span>
              );
            })()}
          </div>
        </div>
      )}

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input type="text" value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search by name, version, purl…"
            className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400" />
        </div>
        {types.size > 1 && (
          <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All types</option>
            {[...types].sort().map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        )}
        {pkgMgrs.size > 1 && (
          <select value={pkgMgrFilter} onChange={e => setPkgMgrFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All ecosystems</option>
            {[...pkgMgrs].sort().map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        )}
        {(topLicenses.length > 0 || unlicensed > 0) && (
          <select value={licenseFilter} onChange={e => setLicenseFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All licenses</option>
            {unlicensed > 0 && <option value="__none__">Unlicensed ({unlicensed})</option>}
            {topLicenses.map(l => <option key={l} value={l}>{l} ({licenseCounts.get(l)})</option>)}
          </select>
        )}
        <div className="ml-auto inline-flex items-center gap-1.5">
          <ArrowUpDown className="h-3.5 w-3.5 text-gray-400" />
          <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="name">Name</option>
            <option value="type">Type</option>
            <option value="license">License</option>
          </select>
        </div>
        <span className="text-[11px] text-gray-400 tabular-nums">
          showing <span className="font-semibold text-gray-700">{filtered.length.toLocaleString()}</span> of {components.length.toLocaleString()}
        </span>
      </div>

      {/* Component table */}
      <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
        <div className="hidden md:grid grid-cols-[minmax(0,1.6fr)_140px_120px_minmax(0,1fr)_16px] items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
          <span>Name</span>
          <span>Version</span>
          <span>Ecosystem</span>
          <span>License</span>
          <span />
        </div>

        {visible.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-gray-400">No components match.</p>
        ) : (
          visible.map((c, i) => {
            const id = (c['bom-ref'] as string) ?? (c.purl as string) ?? `${c.name}-${i}`;
            const isOpen = expanded[id];
            const mgr = getPkgManager(c);
            const ls = getLicenseList(c);
            const filePath = getProp(c, 'aquasecurity:trivy:FilePath');
            const layer = getProp(c, 'aquasecurity:trivy:LayerDigest');
            const layerDiff = getProp(c, 'aquasecurity:trivy:LayerDiffID');
            return (
              <div key={id} className="border-b border-gray-100 last:border-b-0">
                <button onClick={() => setExpanded(p => ({ ...p, [id]: !p[id] }))}
                  className="group grid w-full grid-cols-[minmax(0,1.6fr)_140px_120px_minmax(0,1fr)_16px] items-center gap-3 px-4 py-2 text-left transition-colors hover:bg-gray-50/60">
                  <span className="truncate font-mono text-[12px] text-gray-900">{c.name ?? ''}</span>
                  <span className="truncate font-mono text-[11px] text-gray-600">{c.version ?? ''}</span>
                  <span className="truncate text-[11px] text-gray-600">{mgr ?? c.type ?? '—'}</span>
                  <span className="truncate text-[11px]">
                    {ls.length > 0
                      ? <span className="text-gray-700">{ls.join(', ')}</span>
                      : <span className="text-amber-700">unlicensed</span>}
                  </span>
                  <span className="shrink-0">
                    {isOpen
                      ? <ChevronDown className="h-4 w-4 text-gray-400" />
                      : <ChevronRight className="h-4 w-4 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />}
                  </span>
                </button>
                {isOpen && (
                  <div className="border-t border-gray-100 bg-gray-50/40 px-4 py-3 text-[11px] space-y-1.5">
                    {c.purl && (
                      <div className="flex flex-wrap gap-x-2">
                        <span className="text-gray-400 shrink-0">PURL</span>
                        <span className="font-mono text-gray-700 break-all">{c.purl}</span>
                      </div>
                    )}
                    {c.type && (
                      <div className="flex gap-x-2">
                        <span className="text-gray-400 shrink-0">CDX type</span>
                        <span className="text-gray-700">{c.type}</span>
                      </div>
                    )}
                    {filePath && (
                      <div className="flex flex-wrap gap-x-2">
                        <span className="text-gray-400 shrink-0">File</span>
                        <span className="font-mono text-gray-700 break-all">{filePath}</span>
                      </div>
                    )}
                    {layer && (
                      <div className="flex flex-wrap gap-x-2">
                        <span className="text-gray-400 shrink-0">Layer</span>
                        <span className="font-mono text-gray-600 break-all">{layer}</span>
                      </div>
                    )}
                    {layerDiff && layerDiff !== layer && (
                      <div className="flex flex-wrap gap-x-2">
                        <span className="text-gray-400 shrink-0">Diff ID</span>
                        <span className="font-mono text-gray-600 break-all">{layerDiff}</span>
                      </div>
                    )}
                    {(c.hashes ?? []).length > 0 && (
                      <div>
                        <span className="text-gray-400">Hashes</span>
                        <div className="mt-0.5 space-y-0.5">
                          {(c.hashes as any[]).map((h, j) => (
                            <div key={j} className="font-mono text-[10px] text-gray-600 break-all">
                              <span className="text-gray-400">{h?.alg}:</span> {h?.content}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}

        {!showAll && filtered.length > visible.length && (
          <div className="border-t border-gray-100 px-4 py-3 text-center">
            <button onClick={() => setShowAll(true)}
              className="text-[11px] font-medium text-gray-600 hover:text-gray-900 underline">
              Show all {filtered.length.toLocaleString()} components
            </button>
            <span className="ml-2 text-[11px] text-gray-400">
              (showing first {visible.length.toLocaleString()})
            </span>
          </div>
        )}
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
  void fixableCves; // kept for display only; diff uses full CVE sets below

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

            // Full CVE-set diff — works correctly even on re-verify when old scan is mostly closed.
            // "fixed"   = CVEs present in old image but gone from new image
            // "stillOpen" = CVEs present in both images (surface as remaining in updated image)
            const fixed = [...oldCveSet].filter(c => !newCveSet.has(c));
            const stillOpen = [...oldCveSet].filter(c => newCveSet.has(c));

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
  const [showVerifyModal, setShowVerifyModal] = useState(false);
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null);
  const [, setClosingAll] = useState(false);
  const [compareView, setCompareView] = useState<'old' | 'new' | 'diff'>('diff');
  const [showAcceptModal, setShowAcceptModal] = useState(false);
  const [acceptJustification, setAcceptJustification] = useState('');
  const [acceptSubmitting, setAcceptSubmitting] = useState(false);
  const [siblings, setSiblings] = useState<Scan[]>([]);
  const [showHistory, setShowHistory] = useState(false);

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

        // Load siblings: same base image AND same scan type, excluding current scan.
        // Different scan types (dep vs sbom vs secrets) on the same image are NOT siblings.
        const pid = s.project_id || s.config_json?.project_id;
        const target = (s.config_json?.target as string) ?? '';
        const base = target ? (target.split(':')[0] || target).toLowerCase() : '';
        const currentType = scanTypeKey(s);
        if (pid && base) {
          try {
            const res = await getScans({ project_id: pid, page_size: 200 });
            const all: Scan[] = Array.isArray(res) ? res : (res.items ?? res.results ?? []);
            const sameBase = all
              .filter(x => x.id !== s.id)
              .filter(x => scanTypeKey(x) === currentType)
              .filter(x => {
                const t = (x.config_json?.target as string) ?? '';
                return t && (t.split(':')[0] || t).toLowerCase() === base;
              })
              .sort((a, b) => new Date(b.completed_at ?? b.created_at ?? '').getTime() - new Date(a.completed_at ?? a.created_at ?? '').getTime());
            setSiblings(sameBase);
          } catch { /* noop */ }
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
  const isSast = scan.tool_name === 'semgrep' || scan.tool_name === 'sonarqube';
  const isDep = !isSbom && !isK8s && !isSecrets && !isSast && scan.tool_name === 'trivy';
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

  // Package-level counts for filter tabs (unaffected by status filter)
  const buildGroupCounts = () => {
    const map = new Map<string, Finding[]>();
    for (const f of activeFindingsList) {
      const pkg = (f.raw_data?.PkgName ?? f.raw_data?.pkg_name) as string | undefined;
      const installed = (f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '') as string;
      const key = pkg ? `${pkg}||${installed}` : f.id;
      const arr = map.get(key) ?? [];
      arr.push(f);
      map.set(key, arr);
    }
    let total = 0, openG = 0, closedG = 0;
    for (const items of map.values()) {
      total++;
      const allClosed = items.every(x => closedStatuses.includes(x.status));
      if (allClosed) closedG++;
      else openG++;
    }
    return { total, open: openG, closed: closedG };
  };
  const pkgCounts = buildGroupCounts();

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

  const newOnlyCves = verifyResult
    ? [...verifyResult.newCveSet].filter(c => !verifyResult.oldCveSet.has(c))
    : [];

  return (
    <div className="space-y-5">
      {/* Breadcrumb — explicit path, avoids history-loop with Package detail */}
      <button onClick={() => navigate(`/projects/${projectId}/scan-types/${scanTypeKey(scan)}`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to {scanLabel(scan)}
      </button>

      {/* Image header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <Icon className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-gray-400">{scanLabel(scan)}</p>
            {img ? (
              <h1 className="mt-0.5 text-[15px] font-semibold text-gray-900 font-mono break-all">{img}</h1>
            ) : (
              <h1 className="mt-0.5 text-lg font-semibold text-gray-900">{targetLabel(scan) || 'Scan Results'}</h1>
            )}
            <p className="mt-1 text-xs text-gray-500">
              {scan.completed_at ? new Date(scan.completed_at).toLocaleString() : ''}
            </p>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-2">
          {(isDep || isSecrets) && openCount > 0 && (
            <button onClick={() => setShowVerifyModal(true)}
              className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white hover:bg-black transition-colors">
              <CheckCircle className="h-4 w-4" /> Verify fixed image
            </button>
          )}
          {!isSbom && findings.length > 0 && (
            <button onClick={downloadReport}
              className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-2 text-sm text-gray-700 hover:bg-gray-50 transition-colors">
              <Download className="h-4 w-4" /> Export
            </button>
          )}
        </div>
      </div>

      {/* Summary strip — plain text, no colored borders */}
      {findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-sm">
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{findings.length}</span> total
          </span>
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> open
          </span>
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{closedCount}</span> closed
          </span>
          {isDep && (
            <>
              <span className="text-gray-500">
                <span className="font-semibold text-gray-900 tabular-nums">{fixableCount}</span> fixable
              </span>
              <span className="text-gray-500">
                <span className="font-semibold text-gray-900 tabular-nums">{noFixCount}</span> no-fix
              </span>
            </>
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
          {openCount === 0 && findings.length > 0 && (
            <span className="inline-flex items-center gap-1.5 text-emerald-700">
              <CheckCircle className="h-3.5 w-3.5" /> All closed
            </span>
          )}
        </div>
      )}

      {/* Previous versions — other scans for the same base image */}
      {siblings.length > 0 && (
        <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
          <button
            onClick={() => setShowHistory(v => !v)}
            className="flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left hover:bg-gray-50/60 transition-colors"
          >
            <div className="flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wider text-gray-400">Previous versions</span>
              <span className="rounded border border-gray-200 bg-gray-50 px-1.5 py-0.5 text-[10px] font-medium text-gray-600 tabular-nums">
                {siblings.length}
              </span>
            </div>
            <span className="text-[11px] text-gray-500">
              {showHistory ? '− hide' : '+ show history'}
            </span>
          </button>
          {showHistory && (() => {
            const currentTs = new Date(scan.completed_at ?? scan.created_at ?? '').getTime();
            const isViewingLatest = !siblings.some(sib => {
              const t = new Date(sib.completed_at ?? sib.created_at ?? '').getTime();
              return t > currentTs;
            });
            return (
              <div className="border-t border-gray-100 divide-y divide-gray-100">
                {siblings.map(sib => {
                  const sibTag = ((sib.config_json?.target as string) ?? '').split(':').slice(1).join(':') || '—';
                  const sibIsRunning = sib.status === 'pending' || sib.status === 'running';
                  const sibTs = new Date(sib.completed_at ?? sib.created_at ?? '').getTime();
                  const isNewer = sibTs > currentTs;
                  // Only highlight "newer" tags when the viewer is NOT on the latest
                  const highlight = isNewer && !isViewingLatest;
                  return (
                    <button
                      key={sib.id}
                      onClick={() => navigate(`/projects/${projectId}/scans/${sib.id}`)}
                      className={`group grid w-full grid-cols-[auto_minmax(0,1fr)_100px_180px_16px] items-center gap-3 px-4 py-2 text-sm text-left transition-colors ${
                        highlight ? 'bg-emerald-50/40 hover:bg-emerald-50' : 'hover:bg-gray-50/60'
                      }`}
                    >
                      <span className={`inline-flex items-center justify-center rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider font-medium ${
                        highlight
                          ? 'bg-emerald-600 text-white'
                          : isNewer
                            ? 'bg-gray-100 text-gray-500'
                            : 'bg-gray-50 text-gray-400'
                      }`}>
                        {isNewer ? 'Newer' : 'Older'}
                      </span>
                      <span className={`font-mono text-[12px] truncate ${highlight ? 'text-emerald-900 font-medium' : 'text-gray-800'}`}>
                        {sibTag}
                      </span>
                      <span className="text-right text-xs">
                        {sib.status === 'completed' ? <span className="text-emerald-700">Completed</span>
                        : sib.status === 'failed' ? <span className="text-red-600">Failed</span>
                        : sibIsRunning ? <span className="inline-flex items-center gap-1 text-amber-700"><RefreshCw className="h-3 w-3 animate-spin" /> Running</span>
                        : <span className="text-amber-700">Pending</span>}
                      </span>
                      <span className="text-right text-[11px] text-gray-500 font-mono tabular-nums">
                        {sib.completed_at ? new Date(sib.completed_at).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
                      </span>
                      <ChevronRight className={`h-4 w-4 transition-all group-hover:translate-x-0.5 ${highlight ? 'text-emerald-600 group-hover:text-emerald-800' : 'text-gray-300 group-hover:text-gray-600'}`} />
                    </button>
                  );
                })}
              </div>
            );
          })()}
        </div>
      )}

      {/* Verify comparison — one compact panel */}
      {verifyResult && (
        <div className="rounded-md border border-gray-200 bg-white">
          <div className="flex items-start justify-between gap-4 border-b border-gray-100 px-4 py-3">
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-gray-400">Comparison</p>
              <p className="mt-0.5 text-xs font-mono text-gray-700 truncate">
                {imageName(scan)} <span className="text-gray-400">→</span> {verifyResult.newImage}
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
                <span className="inline-flex items-center gap-1.5 text-gray-500">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <span className="font-semibold text-gray-900 tabular-nums">{verifyResult.fixed.length}</span> removed
                </span>
                <span className="inline-flex items-center gap-1.5 text-gray-500">
                  <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                  <span className="font-semibold text-gray-900 tabular-nums">{verifyResult.stillOpen.length}</span> still present
                </span>
                {newOnlyCves.length > 0 && (
                  <span className="inline-flex items-center gap-1.5 text-gray-500">
                    <span className="h-1.5 w-1.5 rounded-full bg-gray-500" />
                    <span className="font-semibold text-gray-900 tabular-nums">{newOnlyCves.length}</span> new in updated
                  </span>
                )}
                <span className="text-gray-400 tabular-nums">
                  {findings.length} old · {verifyResult.newFindings.length} new
                </span>
              </div>
            </div>
            <button onClick={() => setVerifyResult(null)}
              className="text-xs text-gray-400 hover:text-gray-700 shrink-0">Clear</button>
          </div>

          {/* View toggle — simple underline tabs */}
          <div className="flex items-center gap-4 border-b border-gray-100 px-4">
            {([
              { key: 'diff' as const, label: 'Changes' },
              { key: 'old' as const, label: 'Old' },
              { key: 'new' as const, label: 'New' },
            ]).map(v => (
              <button key={v.key} onClick={() => setCompareView(v.key)}
                className={`-mb-px border-b-2 py-2 text-xs font-medium transition-colors ${
                  compareView === v.key
                    ? 'border-gray-900 text-gray-900'
                    : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}>
                {v.label}
              </button>
            ))}
          </div>

          {/* Diff rows — compact monochrome list */}
          {compareView === 'diff' && (
            <div className="divide-y divide-gray-100 max-h-96 overflow-y-auto">
              {verifyResult.fixed.length === 0 && verifyResult.stillOpen.length === 0 && newOnlyCves.length === 0 && (
                <p className="px-4 py-6 text-center text-xs text-gray-400">No changes detected.</p>
              )}
              {verifyResult.fixed.map(cve => {
                const f = findings.find(ff => (ff.cve_id || ff.title) === cve);
                return (
                  <div key={`fixed-${cve}`} className="flex items-center gap-2 px-4 py-1.5 text-xs">
                    <CheckCircle className="h-3 w-3 shrink-0 text-emerald-600" />
                    <span className="w-20 text-[10px] uppercase tracking-wider text-emerald-700">Removed</span>
                    <span className="font-mono text-gray-700">{cve}</span>
                    {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data.PkgName as string}</span>}
                  </div>
                );
              })}
              {verifyResult.stillOpen.map(cve => {
                const f = findings.find(ff => (ff.cve_id || ff.title) === cve);
                return (
                  <div key={`open-${cve}`} className="flex items-center gap-2 px-4 py-1.5 text-xs">
                    <XCircle className="h-3 w-3 shrink-0 text-red-500" />
                    <span className="w-20 text-[10px] uppercase tracking-wider text-red-700">Still present</span>
                    <span className="font-mono text-gray-700">{cve}</span>
                    {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data.PkgName as string}</span>}
                    {f?.raw_data?.FixedVersion ? (
                      <span className="ml-auto font-mono text-[11px] text-gray-500">→ {f.raw_data.FixedVersion as string}</span>
                    ) : null}
                  </div>
                );
              })}
              {newOnlyCves.slice(0, 50).map(cve => {
                const f = verifyResult.newFindings.find(ff => (ff.cve_id || ff.title) === cve);
                return (
                  <div key={`new-${cve}`} className="flex items-center gap-2 px-4 py-1.5 text-xs">
                    <Package className="h-3 w-3 shrink-0 text-gray-500" />
                    <span className="w-16 text-[10px] uppercase tracking-wider text-gray-500">New</span>
                    <span className="font-mono text-gray-700">{cve}</span>
                    {f?.raw_data?.PkgName && <span className="text-gray-400">{f.raw_data?.PkgName as string}</span>}
                  </div>
                );
              })}
            </div>
          )}

          {/* Action bar — bulk-accept remaining open after verify */}
          {compareView === 'diff' && openCount > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-3 border-t border-gray-100 px-4 py-3 bg-gray-50/60">
              <p className="text-[12px] text-gray-600">
                <span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> finding{openCount !== 1 ? 's' : ''} still open in this image.
              </p>
              <button
                onClick={() => setShowAcceptModal(true)}
                className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black transition-colors">
                Accept remaining & close
              </button>
            </div>
          )}
        </div>
      )}

      {/* Toolbar — integrated, minimal */}
      {!isSbom && !isK8s && !isSast && findings.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          {/* Status — segmented (CVE-level counts to match the header) */}
          <div className="inline-flex rounded-md border border-gray-200 bg-white p-0.5">
            {([
              { k: 'all', label: `All ${findings.length}` },
              { k: 'open', label: `Open ${openCount}` },
              { k: 'closed', label: `Closed ${closedCount}` },
            ]).map(s => (
              <button key={s.k} onClick={() => setStatusFilter(s.k)}
                className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                  statusFilter === s.k ? 'bg-gray-900 text-white' : 'text-gray-600 hover:text-gray-900'
                }`}>
                {s.label}
              </button>
            ))}
          </div>
          <span className="text-[11px] text-gray-400">
            showing <span className="font-semibold text-gray-700 tabular-nums">{isSecrets ? filtered.length : groups.length}</span>{' '}
            {isSecrets ? `secret${filtered.length !== 1 ? 's' : ''}` : `package${groups.length !== 1 ? 's' : ''}`}
          </span>

          {/* Severity — dropdown */}
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {isDep && (
            <button onClick={() => setFixableOnly(v => !v)}
              className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-colors ${
                fixableOnly ? 'border-gray-900 bg-gray-900 text-white' : 'border-gray-200 bg-white text-gray-600 hover:bg-gray-50'
              }`}>
              Fixable only
            </button>
          )}

          <div className="ml-auto inline-flex items-center gap-1.5">
            <ArrowUpDown className="h-3.5 w-3.5 text-gray-400" />
            <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
              className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
              <option value="severity">Severity</option>
              <option value="cvss">CVSS</option>
              <option value="title">Name</option>
            </select>
          </div>
        </div>
      )}

      {/* Which image label — only if diff was hidden */}
      {verifyResult && compareView !== 'diff' && (
        <p className="text-xs text-gray-500">
          Viewing <span className="font-mono text-gray-700">{compareView === 'new' ? verifyResult.newImage : imageName(scan)}</span>
          {compareView === 'new' && <span className="text-gray-400"> · {verifyResult.newFindings.length} findings</span>}
        </p>
      )}

      {/* Findings list */}
      {(!verifyResult || compareView !== 'diff') && (
        <div>
          {isSbom ? (
            <SbomView sbom={sbom} />
          ) : isK8s ? (
            <K8sFindingsView findings={findings} projectId={projectId} scanId={scanId} />
          ) : isSecrets ? (
            <SecretsFindingsView findings={filtered} />
          ) : isSast ? (
            <SastFindingsView findings={findings} projectId={projectId} scanId={scanId} />
          ) : groups.length === 0 ? (
            <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
              {findings.length === 0 ? 'No findings.' : 'No findings match filters.'}
            </div>
          ) : (
            <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
              {/* Column headers — grid template shared with rows */}
              <div className="hidden md:grid grid-cols-[minmax(0,1fr)_100px_80px_140px_16px] items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
                <span>Package</span>
                <span className="text-right">Vulnerabilities</span>
                <span className="text-right">Max CVSS</span>
                <span className="text-right">Fix</span>
                <span />
              </div>

              {groups.map(group => {
                const allFixed = group.items.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version ?? '').filter(Boolean).join(',');
                const fixed = highestVersion(allFixed);
                const worstSev = group.items.reduce((w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w, group.items[0].severity);
                const allClosed = group.items.every(f => closedStatuses.includes(f.status));
                const maxCvss = group.items.reduce((m, f) => Math.max(m, f.cvss_score ?? 0), 0);

                // Per-severity breakdown across all CVEs in this package
                const sevBreak = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                for (const f of group.items) {
                  const s = f.severity as keyof typeof sevBreak;
                  if (s in sevBreak) sevBreak[s]++;
                }

                const sevColor =
                  worstSev === 'critical' ? 'bg-red-500' :
                  worstSev === 'high' ? 'bg-amber-500' :
                  worstSev === 'medium' ? 'bg-yellow-400' :
                  worstSev === 'low' ? 'bg-blue-400' : 'bg-gray-300';

                const pkgKey = group.pkg
                  ? encodeURIComponent(`${group.pkg}@@${group.installed}`)
                  : null;

                const handleClick = () => {
                  if (pkgKey) navigate(`/projects/${projectId}/scans/${scanId}/packages/${pkgKey}`);
                };

                return (
                  <button
                    key={group.key}
                    onClick={handleClick}
                    disabled={!pkgKey}
                    className={`group grid w-full grid-cols-[minmax(0,1fr)_16px] md:grid-cols-[minmax(0,1fr)_100px_80px_140px_16px] items-center gap-3 border-b border-gray-100 px-4 py-3 text-left transition-colors last:border-b-0 enabled:hover:bg-gray-50/60 disabled:cursor-default ${
                      allClosed ? 'opacity-60' : ''
                    }`}
                  >
                    {/* Package name + version */}
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
                        {group.pkg ? (
                          <>
                            <span className="text-sm font-medium text-gray-900 font-mono">{group.pkg}</span>
                            {group.installed && (
                              <span className="font-mono text-[11px] text-gray-500">{group.installed}</span>
                            )}
                          </>
                        ) : (
                          <span className="text-sm font-medium text-gray-900">{group.items[0].title}</span>
                        )}
                      </div>
                      {/* Severity breakdown of all CVEs in this package */}
                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[11px]">
                        {sevBreak.critical > 0 && (
                          <span className="inline-flex items-center gap-1 text-gray-500">
                            <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                            <span className="font-semibold text-gray-800 tabular-nums">{sevBreak.critical}</span> crit
                          </span>
                        )}
                        {sevBreak.high > 0 && (
                          <span className="inline-flex items-center gap-1 text-gray-500">
                            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
                            <span className="font-semibold text-gray-800 tabular-nums">{sevBreak.high}</span> high
                          </span>
                        )}
                        {sevBreak.medium > 0 && (
                          <span className="inline-flex items-center gap-1 text-gray-500">
                            <span className="h-1.5 w-1.5 rounded-full bg-yellow-400" />
                            <span className="font-semibold text-gray-700 tabular-nums">{sevBreak.medium}</span> med
                          </span>
                        )}
                        {sevBreak.low > 0 && (
                          <span className="inline-flex items-center gap-1 text-gray-500">
                            <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                            <span className="font-semibold text-gray-700 tabular-nums">{sevBreak.low}</span> low
                          </span>
                        )}
                        {allClosed && group.items[0].close_reason && (
                          <span className="text-emerald-700">
                            · closed · {group.items[0].close_reason.replace(/_/g, ' ')}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* CVE count */}
                    <div className="hidden md:block text-right">
                      <span className="font-mono text-[11px] text-gray-600 tabular-nums">
                        {group.items.length} CVE{group.items.length !== 1 ? 's' : ''}
                      </span>
                    </div>

                    {/* Max CVSS */}
                    <div className="hidden md:block text-right">
                      {maxCvss > 0 ? (
                        <span className="font-mono text-[11px] text-gray-700 tabular-nums">
                          {maxCvss.toFixed(1)}
                        </span>
                      ) : (
                        <span className="text-[11px] text-gray-300">—</span>
                      )}
                    </div>

                    {/* Fix version */}
                    <div className="hidden md:block text-right">
                      {fixed ? (
                        <span className="font-mono text-[11px] text-emerald-700">→ {fixed}</span>
                      ) : (
                        <span className="text-[11px] text-gray-300">no fix</span>
                      )}
                    </div>

                    <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-enabled:group-hover:translate-x-0.5 group-enabled:group-hover:text-gray-600" />
                  </button>
                );
              })}
            </div>
          )}
        </div>
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

      {/* Accept-remaining modal */}
      {showAcceptModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={() => !acceptSubmitting && setShowAcceptModal(false)}>
          <div className="w-full max-w-md rounded-md bg-white shadow-xl" onClick={e => e.stopPropagation()}>
            <div className="border-b border-gray-100 px-5 py-4">
              <p className="text-[11px] uppercase tracking-wider text-gray-400">Accept risk</p>
              <h3 className="mt-0.5 text-base font-semibold text-gray-900">
                Close {openCount} remaining finding{openCount !== 1 ? 's' : ''}
              </h3>
              <p className="mt-1 text-xs text-gray-500">
                These will be marked as <span className="font-medium text-gray-700">accepted</span>. Justification is logged on each finding.
              </p>
            </div>
            <div className="px-5 py-4 space-y-2">
              <label className="block text-[11px] uppercase tracking-wider text-gray-400">Justification</label>
              <textarea
                autoFocus
                value={acceptJustification}
                onChange={e => setAcceptJustification(e.target.value)}
                disabled={acceptSubmitting}
                rows={3}
                placeholder={`e.g. "no fix available, accepted risk after review on ${new Date().toISOString().slice(0, 10)}"`}
                className="w-full rounded-md border border-gray-200 bg-white px-3 py-2 text-sm text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400 disabled:opacity-50"
              />
            </div>
            <div className="flex items-center justify-end gap-2 border-t border-gray-100 px-5 py-3">
              <button
                onClick={() => setShowAcceptModal(false)}
                disabled={acceptSubmitting}
                className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50">
                Cancel
              </button>
              <button
                onClick={async () => {
                  if (!acceptJustification.trim()) return;
                  setAcceptSubmitting(true);
                  const openFindings = findings.filter(f => !closedStatuses.includes(f.status));
                  for (const f of openFindings) {
                    try {
                      const updated = await closeFinding(f.id, {
                        status: 'accepted',
                        close_reason: 'accepted_after_verify',
                        justification: acceptJustification.trim(),
                      });
                      setFindings(prev => prev.map(pf => pf.id === f.id ? { ...pf, ...updated } : pf));
                    } catch { /* skip */ }
                  }
                  setAcceptSubmitting(false);
                  setShowAcceptModal(false);
                  setAcceptJustification('');
                }}
                disabled={acceptSubmitting || !acceptJustification.trim()}
                className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black disabled:opacity-50">
                {acceptSubmitting
                  ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> Closing…</>
                  : `Close ${openCount} finding${openCount !== 1 ? 's' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
