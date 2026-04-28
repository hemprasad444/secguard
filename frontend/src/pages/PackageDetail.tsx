import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, ExternalLink, RefreshCw,
  Package, Database, Layers,
} from 'lucide-react';
import { getScan, getScanFindings } from '../api/scans';

interface Scan {
  id: string;
  tool_name: string;
  status: string;
  config_json?: Record<string, any> | null;
  project_id?: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  cve_id?: string;
  cvss_score?: number;
  description?: string;
  raw_data?: Record<string, any>;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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

function imageName(scan: Scan): string {
  return scan.config_json?.target ?? '';
}

export default function PackageDetail() {
  const { projectId, scanId, pkgKey } = useParams<{
    projectId: string; scanId: string; pkgKey: string;
  }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  const [decodedPkg, decodedVersion] = useMemo(() => {
    if (!pkgKey) return ['', ''];
    const raw = decodeURIComponent(pkgKey);
    const idx = raw.indexOf('@@');
    if (idx === -1) return [raw, ''];
    return [raw.slice(0, idx), raw.slice(idx + 2)];
  }, [pkgKey]);

  useEffect(() => {
    if (!scanId) return;
    (async () => {
      setLoading(true);
      try {
        const s: Scan = await getScan(scanId);
        setScan(s);
        const data = await getScanFindings(scanId, 1, 1000);
        const all: Finding[] = Array.isArray(data) ? data : (data.items ?? data.results ?? []);
        const filtered = all.filter(f => {
          const pkg = f.raw_data?.PkgName ?? f.raw_data?.pkg_name;
          const installed = f.raw_data?.InstalledVersion ?? f.raw_data?.installed_version ?? '';
          return pkg === decodedPkg && installed === decodedVersion;
        });
        filtered.sort((a, b) => {
          const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
          if (sd !== 0) return sd;
          return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
        });
        setFindings(filtered);
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [scanId, decodedPkg, decodedVersion]);

  if (loading) {
    return (
      <div className="flex h-60 items-center justify-center">
        <RefreshCw className="h-5 w-5 animate-spin text-gray-400" />
      </div>
    );
  }

  if (!scan || findings.length === 0) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)}
          className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
          <ArrowLeft className="h-3.5 w-3.5" /> Back
        </button>
        <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
          Package not found in this scan.
        </div>
      </div>
    );
  }

  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const sample = findings[0].raw_data ?? {};
  const allFixedVers = [...new Set(
    findings.map(f => f.raw_data?.FixedVersion ?? f.raw_data?.fixed_version).filter(Boolean)
  )].join(',');
  const fixedHighest = highestVersion(allFixedVers);
  const purl = sample?.PkgIdentifier?.PURL ?? null;
  const pkgPath = sample?.PkgPath ?? null;
  const pkgId = sample?.PkgID ?? null;
  const dataSource = sample?.DataSource ?? null;
  const layer = sample?.Layer ?? null;
  const image = imageName(scan);

  const openCount = findings.filter(f => !closedStatuses.includes(f.status)).length;
  const closedCount = findings.length - openCount;
  const worstSev = findings.reduce(
    (w, f) => (SEV_ORDER[f.severity] ?? 9) < (SEV_ORDER[w] ?? 9) ? f.severity : w,
    findings[0].severity,
  );
  const maxCvss = findings.reduce((m, f) => Math.max(m, f.cvss_score ?? 0), 0);
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = f.severity as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }
  const fixableCount = findings.filter(f =>
    f.raw_data?.FixedVersion || f.raw_data?.fixed_version
  ).length;

  return (
    <div className="space-y-5">
      {/* Back */}
      <button onClick={() => navigate(`/projects/${projectId}/scans/${scanId}`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to scan
      </button>

      {/* Header row — package identity | recommended fix */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto] gap-6 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <Package className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0 flex-1">
            <p className="text-[11px] uppercase tracking-wider text-gray-400">Package</p>
            <h1 className="mt-0.5 text-lg font-semibold text-gray-900 font-mono break-all">
              {decodedPkg}
            </h1>
            <p className="mt-1 text-xs text-gray-500 font-mono">
              Installed <span className="text-gray-800">{decodedVersion || '—'}</span>
              {image && (
                <>
                  <span className="mx-2 text-gray-300">·</span>
                  <span className="text-gray-500">{image}</span>
                </>
              )}
            </p>
          </div>
        </div>

        {/* Recommended fix card */}
        {fixedHighest && (
          <div className="rounded-md border border-gray-200 bg-white px-4 py-3 lg:min-w-[280px]">
            <p className="text-[10px] uppercase tracking-wider text-gray-400">
              Recommended fix
            </p>
            <p className="mt-1 font-mono text-[15px] font-semibold text-emerald-700">
              → {fixedHighest}
            </p>
            <p className="mt-1 text-[11px] text-gray-500">
              Upgrading resolves{' '}
              <span className="font-semibold text-gray-800 tabular-nums">{fixableCount}</span>
              {' '}of{' '}
              <span className="font-semibold text-gray-800 tabular-nums">{findings.length}</span>
              {' '}vulnerabilities
            </p>
          </div>
        )}
      </div>

      {/* Stats + meta — single row */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{findings.length}</span> total
        </span>
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> open
        </span>
        {closedCount > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{closedCount}</span> closed
          </span>
        )}
        <span className="inline-flex items-center gap-1.5 text-gray-500">
          worst <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(worstSev)}`}>{worstSev}</span>
        </span>
        {maxCvss > 0 && (
          <span className="text-gray-500">
            max CVSS <span className="font-semibold text-gray-900 tabular-nums">{maxCvss.toFixed(1)}</span>
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

      {/* Meta strip */}
      {(purl || pkgPath || pkgId || dataSource || layer) && (
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1.5 border-t border-gray-100 pt-3 text-[11px]">
          {purl && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <Package className="h-3 w-3 text-gray-400" />
              <span className="text-gray-400">PURL</span>
              <span className="font-mono text-gray-700 break-all">{purl}</span>
            </span>
          )}
          {pkgId && pkgId !== purl && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <span className="text-gray-400">ID</span>
              <span className="font-mono text-gray-700 break-all">{pkgId}</span>
            </span>
          )}
          {pkgPath && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <span className="text-gray-400">Path</span>
              <span className="font-mono text-gray-700 break-all">{pkgPath}</span>
            </span>
          )}
          {dataSource && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <Database className="h-3 w-3 text-gray-400" />
              <span className="text-gray-400">Source</span>
              {dataSource.URL ? (
                <a href={dataSource.URL} target="_blank" rel="noopener noreferrer"
                  className="text-gray-700 hover:text-gray-900 hover:underline inline-flex items-center gap-1">
                  {dataSource.Name ?? dataSource.ID}
                  <ExternalLink className="h-3 w-3" />
                </a>
              ) : (
                <span className="text-gray-700">{dataSource.Name ?? dataSource.ID}</span>
              )}
            </span>
          )}
          {layer?.DiffID && (
            <span className="inline-flex items-center gap-1.5 text-gray-500">
              <Layers className="h-3 w-3 text-gray-400" />
              <span className="text-gray-400">Layer</span>
              <span className="font-mono text-gray-600 break-all">
                {(layer.DiffID as string).slice(0, 20)}…
              </span>
            </span>
          )}
        </div>
      )}

      {/* CVE table — dense */}
      <div>
        <h2 className="mb-2 text-sm font-semibold text-gray-900">
          Vulnerabilities <span className="text-gray-400 font-normal">({findings.length})</span>
        </h2>

        <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
          {/* Table header */}
          <div className="hidden md:grid grid-cols-[110px_160px_70px_1fr_160px] items-center gap-4 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
            <span>Severity</span>
            <span>CVE</span>
            <span className="text-right">CVSS</span>
            <span>Title</span>
            <span>Fix</span>
          </div>

          {findings.map(f => {
            const r = f.raw_data ?? {};
            const isClosed = closedStatuses.includes(f.status);
            const cvssScore = f.cvss_score ?? r.CVSS?.nvd?.V3Score ?? r.CVSS?.redhat?.V3Score ?? null;
            const fixedVer = r.FixedVersion ?? r.fixed_version ?? '';
            const title = r.Title ?? f.title;
            const refUrl = r.PrimaryURL;

            return (
              <div key={f.id}
                className={`group grid grid-cols-1 md:grid-cols-[110px_160px_70px_1fr_160px] items-center gap-2 md:gap-4 border-b border-gray-100 px-4 py-2 text-sm transition-colors last:border-b-0 hover:bg-gray-50/60 ${
                  isClosed ? 'opacity-60' : ''
                }`}>
                {/* Severity */}
                <div className="flex items-center gap-2">
                  <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${sevDot(f.severity)}`} />
                  <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(f.severity)}`}>
                    {f.severity}
                  </span>
                </div>

                {/* CVE ID — link */}
                <div className="min-w-0">
                  {refUrl && f.cve_id ? (
                    <a href={refUrl} target="_blank" rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 font-mono text-[12px] font-medium text-gray-900 hover:text-gray-700 hover:underline">
                      {f.cve_id}
                      <ExternalLink className="h-3 w-3 text-gray-400" />
                    </a>
                  ) : f.cve_id ? (
                    <span className="font-mono text-[12px] text-gray-900">{f.cve_id}</span>
                  ) : (
                    <span className="text-[11px] text-gray-400">—</span>
                  )}
                </div>

                {/* CVSS */}
                <div className="md:text-right">
                  {cvssScore != null ? (
                    <span className="font-mono text-[12px] text-gray-700 tabular-nums">
                      {Number(cvssScore).toFixed(1)}
                    </span>
                  ) : (
                    <span className="text-[11px] text-gray-300">—</span>
                  )}
                </div>

                {/* Title */}
                <div className="min-w-0">
                  <p className="truncate text-[13px] text-gray-800">{title}</p>
                </div>

                {/* Fix version */}
                <div>
                  {fixedVer ? (
                    <span className="font-mono text-[11px] text-emerald-700 break-all">
                      → {fixedVer}
                    </span>
                  ) : (
                    <span className="text-[11px] text-gray-400">no fix</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
