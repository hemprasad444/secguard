import { useEffect, useState, useCallback } from 'react';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, LineChart, Line,
} from 'recharts';
import {
  Shield, AlertTriangle, AlertCircle, TrendingUp, GitCompare,
  CheckCircle, XCircle, Lock, Key, FileText, Package,
  Server, Layers, Box, Globe,
} from 'lucide-react';
import {
  getSummary, getToolBreakdown, getScanTypeSeverity,
  getImageBreakdown, getCategoryBreakdown,
  getSbomLicenseBreakdown,
  getK8sCategories, getK8sResources, getK8sNamespaces,
} from '../api/dashboard';
import { getProjects } from '../api/projects';

// ── Types ─────────────────────────────────────────────────────────────────────
interface SummaryData {
  total_findings: number; critical: number; high: number;
  medium: number; low: number; info: number;
  open_findings: number; resolved_findings: number;
  total_scans: number; total_projects: number;
  total_packages: number; fixable_packages: number;
  no_fix_packages: number; actionable_packages: number;
  pkg_critical: number; pkg_high: number; pkg_medium: number;
  pkg_low: number; pkg_info: number;
}
interface ToolItem    { tool_name: string; count: number; }
interface ScanTypeSev { scan_type: string; total: number; critical: number; high: number; medium: number; low: number; info: number; total_packages: number; fixable_packages: number; no_fix_packages: number; }
interface ImageItem   { image: string; count: number; fixable_count: number; no_fix_count: number; }
interface ProjectItem { id: string; name: string; }
interface SecretsCategoryItem {
  category: string; total: number;
  critical: number; high: number; medium: number; low: number; info: number;
}
interface SbomLicenseCategoryItem {
  category: string; total_packages: number; actionable: number; not_actionable: number;
}
interface SbomPackageItem {
  name: string; version: string; pkg_type: string; image: string;
  raw_licenses: string[]; effective_license: string; license_category: string; actionable: boolean;
}
interface SbomLicenseData {
  total_packages: number; total_actionable: number; total_not_actionable: number;
  by_category: SbomLicenseCategoryItem[]; actionable_packages: SbomPackageItem[];
}
interface K8sCategoryItem {
  category: string; total: number;
  critical: number; high: number; medium: number; low: number; info: number;
}
interface K8sResourceItem {
  kind: string; name: string; namespace: string;
  total_findings: number; critical: number; high: number; medium: number; low: number;
}
interface K8sNamespaceItem {
  namespace: string; total_findings: number;
  critical: number; high: number; medium: number; low: number;
}

// ── Colors ────────────────────────────────────────────────────────────────────
const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#9ca3af',
};
const SCAN_COLORS: Record<string, string> = {
  Dependency: '#0891b2', Secrets: '#dc2626', SBOM: '#7c3aed',
  SAST: '#d97706', DAST: '#ea580c', K8s: '#059669',
};
const SCAN_LUCIDE_ICONS: Record<string, React.ElementType> = {
  Dependency: Package, Secrets: Key, SBOM: FileText, SAST: Shield, DAST: Globe, K8s: Server,
};
const CMP_A = '#6366f1';
const CMP_B = '#ec4899';

// ── Stat Card (Grafana-style) ─────────────────────────────────────────────────
function StatCard({ label, value, accent, sub }: {
  label: string; value: number; accent: string; icon?: React.ElementType; sub?: string;
}) {
  return (
    <div className="relative overflow-hidden rounded bg-white border border-gray-200 px-4 py-3">
      <p className="text-[10px] font-medium uppercase tracking-wider text-gray-500">{label}</p>
      <p className="mt-1 text-3xl font-semibold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums', color: accent, lineHeight: '1.1' }}>
        {value.toLocaleString()}
      </p>
      {sub && <p className="mt-0.5 text-[10px] text-gray-400 uppercase tracking-wider">{sub}</p>}
      <div className="absolute bottom-0 left-0 right-0 h-0.5" style={{ background: accent }} />
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="animate-pulse rounded bg-white border border-gray-200 p-3">
      <div className="h-2 w-16 bg-gray-100" />
      <div className="mt-2 h-7 w-20 bg-gray-100" />
    </div>
  );
}

function SkeletonChart({ h = 'h-64' }: { h?: string }) {
  return (
    <div className="animate-pulse rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <div className="mb-1 h-4 w-36 rounded-full bg-gray-100" />
      <div className="mb-4 h-3 w-24 rounded-full bg-gray-100" />
      <div className={`${h} rounded-xl bg-gray-50`} />
    </div>
  );
}

// ── Dependency: Severity Donut with Packages / Findings toggle ────────────────
function SeverityDonut({ summary, title = 'Severity Breakdown' }: { summary: SummaryData | null; title?: string }) {
  const [mode, setMode] = useState<'packages' | 'findings'>('packages');

  const pkgData = summary
    ? [
        { name: 'Critical', value: summary.pkg_critical ?? 0, color: SEV_COLORS.critical },
        { name: 'High',     value: summary.pkg_high     ?? 0, color: SEV_COLORS.high },
        { name: 'Medium',   value: summary.pkg_medium   ?? 0, color: SEV_COLORS.medium },
        { name: 'Low',      value: summary.pkg_low      ?? 0, color: SEV_COLORS.low },
        { name: 'Info',     value: summary.pkg_info     ?? 0, color: SEV_COLORS.info },
      ].filter(d => d.value > 0)
    : [];

  const findData = summary
    ? [
        { name: 'Critical', value: summary.critical, color: SEV_COLORS.critical },
        { name: 'High',     value: summary.high,     color: SEV_COLORS.high },
        { name: 'Medium',   value: summary.medium,   color: SEV_COLORS.medium },
        { name: 'Low',      value: summary.low,      color: SEV_COLORS.low },
        { name: 'Info',     value: summary.info,     color: SEV_COLORS.info },
      ].filter(d => d.value > 0)
    : [];

  const data  = mode === 'packages' ? pkgData : findData;
  const total = mode === 'packages'
    ? (summary?.total_packages ?? 0)
    : (summary?.total_findings ?? 0);
  const centreLabel = mode === 'packages' ? 'packages' : 'findings';

  const fixable  = summary?.fixable_packages ?? 0;
  const noFix    = summary?.no_fix_packages  ?? 0;
  const fixPct   = total > 0 ? Math.round((fixable / total) * 100) : 0;
  const noFixPct = total > 0 ? Math.round((noFix   / total) * 100) : 0;

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      {/* Header + toggle */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-sm font-semibold text-gray-800">{title}</h2>
          <p className="mt-0.5 text-xs text-gray-400">
            {mode === 'packages'
              ? 'Unique packages · each counted once at highest CVE severity'
              : 'Raw finding counts by severity'}
          </p>
        </div>
        <div className="flex items-center rounded-xl border border-gray-200 bg-gray-50 p-0.5 text-xs font-medium shrink-0">
          <button onClick={() => setMode('packages')}
            className={`rounded-lg px-3 py-1.5 transition-all ${mode === 'packages' ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}>
            Packages
          </button>
          <button onClick={() => setMode('findings')}
            className={`rounded-lg px-3 py-1.5 transition-all ${mode === 'findings' ? 'bg-white shadow-sm text-gray-900' : 'text-gray-500 hover:text-gray-700'}`}>
            Findings
          </button>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex h-56 items-center justify-center text-sm text-gray-400">No findings yet</div>
      ) : (
        <>
          {/* Fixable / No-fix strip — packages mode only */}
          {mode === 'packages' && (
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div className="rounded-xl bg-green-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-green-600">Fixable</p>
                <p className="mt-1 text-2xl font-bold text-green-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{fixable.toLocaleString()}</p>
                <p className="text-xs text-green-500">{fixPct}% of packages</p>
              </div>
              <div className="rounded-xl bg-red-50 p-3">
                <p className="text-[10px] font-semibold uppercase tracking-widest text-red-500">No Fix Yet</p>
                <p className="mt-1 text-2xl font-bold text-red-600" style={{ fontVariantNumeric: 'tabular-nums' }}>{noFix.toLocaleString()}</p>
                <p className="text-xs text-red-400">{noFixPct}% of packages</p>
              </div>
            </div>
          )}

          {/* Donut + legend */}
          <div className="mt-4 flex flex-col items-center gap-4 sm:flex-row">
            <div className="relative shrink-0">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie data={data} dataKey="value" cx="50%" cy="50%"
                    innerRadius={46} outerRadius={74} paddingAngle={2} startAngle={90} endAngle={-270}>
                    {data.map(d => <Cell key={d.name} fill={d.color} stroke="transparent" />)}
                  </Pie>
                  <Tooltip formatter={(v: number) => [v.toLocaleString(), centreLabel]} />
                </PieChart>
              </ResponsiveContainer>
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-xl font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{total.toLocaleString()}</span>
                <span className="text-[10px] font-medium uppercase tracking-wider text-gray-400">{centreLabel}</span>
              </div>
            </div>
            <div className="flex-1 w-full space-y-2">
              {data.map(d => (
                <div key={d.name} className="flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full shrink-0" style={{ background: d.color }} />
                  <span className="flex-1 text-xs font-medium text-gray-600">{d.name}</span>
                  <span className="text-xs font-semibold text-gray-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{d.value.toLocaleString()}</span>
                  <span className="w-8 text-right text-xs text-gray-400">{total > 0 ? ((d.value / total) * 100).toFixed(0) : 0}%</span>
                  <div className="w-16 overflow-hidden rounded-full bg-gray-100 h-1.5">
                    <div className="h-full rounded-full" style={{ width: `${total > 0 ? (d.value / total) * 100 : 0}%`, background: d.color }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── Findings-based severity donut (used by Secrets + K8s) ─────────────────────
function FindingsSeverityDonut({ summary, subtitle }: { summary: SummaryData | null; subtitle?: string }) {
  const data = summary
    ? [
        { name: 'Critical', value: summary.critical, color: SEV_COLORS.critical },
        { name: 'High',     value: summary.high,     color: SEV_COLORS.high },
        { name: 'Medium',   value: summary.medium,   color: SEV_COLORS.medium },
        { name: 'Low',      value: summary.low,      color: SEV_COLORS.low },
        { name: 'Info',     value: summary.info,     color: SEV_COLORS.info },
      ].filter(d => d.value > 0)
    : [];
  const total = summary?.total_findings ?? 0;

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <h2 className="text-sm font-semibold text-gray-800">Severity Breakdown</h2>
      <p className="mt-0.5 text-xs text-gray-400">{subtitle ?? 'Distribution of findings by severity'}</p>
      {data.length === 0 ? (
        <div className="flex h-56 items-center justify-center text-sm text-gray-400">No secrets found</div>
      ) : (
        <div className="mt-4 flex flex-col items-center gap-4 sm:flex-row">
          <div className="relative shrink-0">
            <ResponsiveContainer width={160} height={160}>
              <PieChart>
                <Pie data={data} dataKey="value" cx="50%" cy="50%"
                  innerRadius={46} outerRadius={74} paddingAngle={2} startAngle={90} endAngle={-270}>
                  {data.map(d => <Cell key={d.name} fill={d.color} stroke="transparent" />)}
                </Pie>
                <Tooltip formatter={(v: number) => [v.toLocaleString(), 'secrets']} />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-xl font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{total.toLocaleString()}</span>
              <span className="text-[10px] font-medium uppercase tracking-wider text-gray-400">secrets</span>
            </div>
          </div>
          <div className="flex-1 w-full space-y-2">
            {data.map(d => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full shrink-0" style={{ background: d.color }} />
                <span className="flex-1 text-xs font-medium text-gray-600">{d.name}</span>
                <span className="text-xs font-semibold text-gray-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{d.value.toLocaleString()}</span>
                <span className="w-8 text-right text-xs text-gray-400">{total > 0 ? ((d.value / total) * 100).toFixed(0) : 0}%</span>
                <div className="w-16 overflow-hidden rounded-full bg-gray-100 h-1.5">
                  <div className="h-full rounded-full" style={{ width: `${total > 0 ? (d.value / total) * 100 : 0}%`, background: d.color }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Secrets: Category breakdown chart ─────────────────────────────────────────
function SecretsCategoryChart({ data }: { data: SecretsCategoryItem[] }) {
  if (data.length === 0) {
    return (
      <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100 flex items-center justify-center h-64 text-sm text-gray-400">
        No category data
      </div>
    );
  }
  const chartData = data.map(d => ({
    name: d.category,
    Critical: d.critical,
    High: d.high,
    Medium: d.medium,
    Low: d.low,
    total: d.total,
  })).reverse(); // highest at top in horizontal chart

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <h2 className="text-sm font-semibold text-gray-800">Secrets by Category</h2>
      <p className="mt-0.5 mb-4 text-xs text-gray-400">Exposed secret types and their severity</p>
      <div className="mb-3 flex flex-wrap gap-3 text-xs">
        {['Critical','High','Medium','Low'].map(s => (
          <span key={s} className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm inline-block" style={{ background: SEV_COLORS[s.toLowerCase()] }} />
            {s}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={Math.max(data.length * 44 + 20, 160)}>
        <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 48, left: 8, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
          <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fontSize: 12, fill: '#374151', fontWeight: 500 }} tickLine={false} axisLine={false} width={150} />
          <Tooltip formatter={(v: number, name: string) => [v, name]} />
          <Bar dataKey="Critical" stackId="a" fill={SEV_COLORS.critical} maxBarSize={24} />
          <Bar dataKey="High"     stackId="a" fill={SEV_COLORS.high}     maxBarSize={24} />
          <Bar dataKey="Medium"   stackId="a" fill={SEV_COLORS.medium}   maxBarSize={24} />
          <Bar dataKey="Low"      stackId="a" fill={SEV_COLORS.low}      radius={[0, 4, 4, 0]} maxBarSize={24} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── SBOM: License category colors ─────────────────────────────────────────────
const LICENSE_COLORS: Record<string, string> = {
  GPL: '#dc2626', AGPL: '#991b1b', LGPL: '#ea580c', MPL: '#d97706',
  EPL: '#ca8a04', Apache: '#16a34a', BSD: '#2563eb', MIT: '#7c3aed',
  ISC: '#8b5cf6', 'Public Domain': '#059669', Other: '#6b7280', Unknown: '#9ca3af',
};
const LICENSE_RISK_ORDER = ['AGPL', 'GPL', 'LGPL', 'MPL', 'EPL', 'Apache', 'BSD', 'MIT', 'ISC', 'Public Domain', 'Other', 'Unknown'];

// ── SBOM: Summary stat cards row ──────────────────────────────────────────────
function SbomStatCards({ data }: { data: SbomLicenseData | null }) {
  const total = data?.total_packages ?? 0;
  const actionable = data?.total_actionable ?? 0;
  const safe = data?.total_not_actionable ?? 0;
  const categories = data?.by_category?.length ?? 0;
  const rawPct = total > 0 ? (safe / total) * 100 : 0;
  const pct = actionable > 0 ? Math.min(Math.floor(rawPct), 99) : (total > 0 ? 100 : 0);

  return (
    <div className="space-y-5">
      {/* Top row: 4 stat cards consistent with Dependency / Secrets tabs */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-5">
        <StatCard label="Total Packages"    value={total}       accent="#6366f1" icon={Package}     sub="unique across all images" />
        <StatCard label="Permissive"        value={safe}        accent="#10b981" icon={CheckCircle} sub={`${pct}% of all packages`} />
        <StatCard label="Action Needed"     value={actionable}  accent="#ef4444" icon={AlertCircle} sub="copyleft app packages" />
        <StatCard label="License Types"     value={categories}  accent="#8b5cf6" icon={FileText}    sub="distinct categories" />
        {/* 5th card: compliance gauge */}
        <div className="relative overflow-hidden rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-100 border-t-4"
          style={{ borderTopColor: actionable === 0 ? '#10b981' : '#f59e0b' }}>
          <div className="flex items-start justify-between">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-widest text-gray-400">Compliance</p>
              <p className="mt-2 text-3xl font-bold tracking-tight" style={{ fontVariantNumeric: 'tabular-nums', color: actionable === 0 ? '#10b981' : '#f59e0b' }}>
                {pct}%
              </p>
              <p className="mt-0.5 text-xs text-gray-400">permissive licensed</p>
            </div>
            <div className="flex h-10 w-10 items-center justify-center rounded-xl"
              style={{ background: actionable === 0 ? '#10b98118' : '#f59e0b18' }}>
              <Shield className="h-5 w-5" style={{ color: actionable === 0 ? '#10b981' : '#f59e0b' }} />
            </div>
          </div>
          {/* Mini progress bar */}
          <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
            <div className="h-full rounded-full transition-all duration-700"
              style={{ width: `${pct}%`, background: actionable === 0 ? '#10b981' : '#f59e0b' }} />
          </div>
        </div>
      </div>
    </div>
  );
}

// ── SBOM: License donut ───────────────────────────────────────────────────────
function LicenseDonut({ data }: { data: SbomLicenseData | null }) {
  if (!data || data.total_packages === 0) {
    return (
      <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100 flex items-center justify-center h-72 text-sm text-gray-400">
        No SBOM data
      </div>
    );
  }

  const chartData = data.by_category
    .filter(c => c.total_packages > 0)
    .sort((a, b) => LICENSE_RISK_ORDER.indexOf(a.category) - LICENSE_RISK_ORDER.indexOf(b.category))
    .map(c => ({ name: c.category, value: c.total_packages, color: LICENSE_COLORS[c.category] ?? '#6b7280' }));

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <h2 className="text-sm font-semibold text-gray-800">License Distribution</h2>
      <p className="mt-0.5 text-xs text-gray-400">Unique packages by effective license category</p>

      <div className="mt-5 flex flex-col items-center gap-5 sm:flex-row">
        <div className="relative shrink-0">
          <ResponsiveContainer width={180} height={180}>
            <PieChart>
              <Pie data={chartData} dataKey="value" cx="50%" cy="50%"
                innerRadius={52} outerRadius={82} paddingAngle={2} startAngle={90} endAngle={-270}>
                {chartData.map(d => <Cell key={d.name} fill={d.color} stroke="transparent" />)}
              </Pie>
              <Tooltip
                contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 24px rgba(0,0,0,0.1)', fontSize: '12px' }}
                formatter={(v: number) => [v.toLocaleString(), 'packages']}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
            <span className="text-2xl font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{data.total_packages.toLocaleString()}</span>
            <span className="text-[10px] font-medium uppercase tracking-wider text-gray-400">packages</span>
          </div>
        </div>
        <div className="flex-1 w-full space-y-2.5">
          {chartData.map(d => {
            const pct = ((d.value / data.total_packages) * 100);
            const isRisky = ['GPL', 'AGPL', 'LGPL'].includes(d.name);
            return (
              <div key={d.name} className={`flex items-center gap-2.5 rounded-lg px-2 py-1 ${isRisky ? 'bg-red-50/50' : ''}`}>
                <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: d.color }} />
                <span className={`flex-1 text-xs font-medium ${isRisky ? 'text-gray-800' : 'text-gray-600'}`}>{d.name}</span>
                <span className="text-xs font-bold text-gray-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{d.value.toLocaleString()}</span>
                <span className="w-10 text-right text-[11px] text-gray-400">{pct.toFixed(1)}%</span>
                <div className="w-20 overflow-hidden rounded-full bg-gray-100 h-1.5">
                  <div className="h-full rounded-full transition-all duration-500" style={{ width: `${pct}%`, background: d.color }} />
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ── SBOM: Actionable vs Permissive split card ─────────────────────────────────
function LicenseRiskSplit({ data }: { data: SbomLicenseData | null }) {
  if (!data || data.total_packages === 0) return null;

  const copyleft = data.by_category.filter(c => ['GPL', 'AGPL', 'LGPL'].includes(c.category));
  const permissive = data.by_category.filter(c => !['GPL', 'AGPL', 'LGPL', 'Unknown'].includes(c.category));

  const copyleftTotal = copyleft.reduce((s, c) => s + c.total_packages, 0);
  const permissiveTotal = permissive.reduce((s, c) => s + c.total_packages, 0);
  const unknownCat = data.by_category.find(c => c.category === 'Unknown');
  const unknownTotal = unknownCat?.total_packages ?? 0;

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <h2 className="text-sm font-semibold text-gray-800">Risk Classification</h2>
      <p className="mt-0.5 mb-5 text-xs text-gray-400">Application-level packages grouped by license risk</p>

      {/* Visual split bar */}
      <div className="mb-5">
        <div className="flex h-3 w-full overflow-hidden rounded-full bg-gray-100">
          {copyleftTotal > 0 && (
            <div className="h-full bg-gradient-to-r from-red-500 to-red-400 transition-all duration-500"
              style={{ width: `${(copyleftTotal / data.total_packages) * 100}%` }} />
          )}
          {permissiveTotal > 0 && (
            <div className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-500"
              style={{ width: `${(permissiveTotal / data.total_packages) * 100}%` }} />
          )}
          {unknownTotal > 0 && (
            <div className="h-full bg-gray-300 transition-all duration-500"
              style={{ width: `${(unknownTotal / data.total_packages) * 100}%` }} />
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {/* Copyleft */}
        <div className="rounded-xl border border-red-100 bg-red-50/50 p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-red-100">
              <AlertCircle className="h-3.5 w-3.5 text-red-600" />
            </div>
            <span className="text-xs font-bold uppercase tracking-wider text-red-700">Copyleft</span>
          </div>
          <p className="text-2xl font-bold text-red-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{copyleftTotal.toLocaleString()}</p>
          <div className="mt-2 space-y-1">
            {copyleft.filter(c => c.total_packages > 0).map(c => (
              <div key={c.category} className="flex items-center justify-between text-xs">
                <span className="font-medium text-red-600">{c.category}</span>
                <div className="flex items-center gap-1.5">
                  <span className="font-bold text-red-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{c.total_packages}</span>
                  {c.actionable > 0 && (
                    <span className="rounded bg-red-200 px-1 py-0.5 text-[10px] font-bold text-red-800">{c.actionable} action</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Permissive */}
        <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-100">
              <CheckCircle className="h-3.5 w-3.5 text-emerald-600" />
            </div>
            <span className="text-xs font-bold uppercase tracking-wider text-emerald-700">Permissive</span>
          </div>
          <p className="text-2xl font-bold text-emerald-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{permissiveTotal.toLocaleString()}</p>
          <div className="mt-2 space-y-1">
            {permissive.filter(c => c.total_packages > 0).sort((a, b) => b.total_packages - a.total_packages).map(c => (
              <div key={c.category} className="flex items-center justify-between text-xs">
                <span className="font-medium text-emerald-600">{c.category}</span>
                <span className="font-bold text-emerald-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{c.total_packages}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Unknown */}
        <div className="rounded-xl border border-gray-200 bg-gray-50/50 p-4">
          <div className="flex items-center gap-2 mb-3">
            <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-gray-200">
              <FileText className="h-3.5 w-3.5 text-gray-500" />
            </div>
            <span className="text-xs font-bold uppercase tracking-wider text-gray-500">Unknown / Other</span>
          </div>
          <p className="text-2xl font-bold text-gray-600" style={{ fontVariantNumeric: 'tabular-nums' }}>
            {(unknownTotal + data.by_category.filter(c => c.category === 'Other').reduce((s, c) => s + c.total_packages, 0)).toLocaleString()}
          </p>
          <p className="mt-2 text-xs text-gray-400">Packages with unrecognized or missing license information</p>
        </div>
      </div>
    </div>
  );
}

// ── SBOM: Actionable packages table ───────────────────────────────────────────
function ActionablePackagesTable({ packages }: { packages: SbomPackageItem[] }) {
  const [search, setSearch] = useState('');
  const [pkgTypeFilter, setPkgTypeFilter] = useState('');
  const [licenseFilter, setLicenseFilter] = useState('');

  const pkgTypes = Array.from(new Set(packages.map(p => p.pkg_type))).sort();
  const licenseCategories = Array.from(new Set(packages.map(p => p.license_category))).sort();
  const filtered = packages.filter(p => {
    if (pkgTypeFilter && p.pkg_type !== pkgTypeFilter) return false;
    if (licenseFilter && p.license_category !== licenseFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      return p.name.toLowerCase().includes(q) || p.effective_license.toLowerCase().includes(q) || p.image.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
      {/* Header */}
      <div className="border-b border-gray-100 bg-gradient-to-r from-red-50 to-orange-50 px-6 py-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-red-100">
              <AlertTriangle className="h-4.5 w-4.5 text-red-600" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-gray-900">Actionable Packages</h2>
              <p className="text-xs text-gray-500">Application packages with copyleft licenses requiring review</p>
            </div>
          </div>
          <span className="inline-flex items-center rounded-full bg-red-100 px-3 py-1 text-xs font-bold text-red-800">
            {packages.length} package{packages.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      <div className="p-6">
        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 mb-4">
          <div className="relative flex-1 min-w-[200px] max-w-xs">
            <input
              value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search package name, license, image…"
              className="w-full rounded-xl border border-gray-200 bg-gray-50 pl-3 pr-3 py-2 text-xs
                         focus:border-violet-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-violet-100
                         transition-all placeholder:text-gray-400"
            />
          </div>
          {pkgTypes.length > 1 && (
            <select value={pkgTypeFilter} onChange={e => setPkgTypeFilter(e.target.value)}
              className="rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 text-xs font-medium text-gray-600
                         focus:outline-none focus:ring-2 focus:ring-violet-100 transition-all">
              <option value="">All types</option>
              {pkgTypes.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          )}
          {licenseCategories.length > 1 && (
            <select value={licenseFilter} onChange={e => setLicenseFilter(e.target.value)}
              className="rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 text-xs font-medium text-gray-600
                         focus:outline-none focus:ring-2 focus:ring-violet-100 transition-all">
              <option value="">All licenses</option>
              {licenseCategories.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          )}
          {(search || pkgTypeFilter || licenseFilter) && (
            <button onClick={() => { setSearch(''); setPkgTypeFilter(''); setLicenseFilter(''); }}
              className="rounded-xl border border-gray-200 px-3 py-2 text-xs font-medium text-gray-500 hover:bg-gray-50 transition-all">
              Clear
            </button>
          )}
          <span className="ml-auto text-xs text-gray-400">{filtered.length} result{filtered.length !== 1 ? 's' : ''}</span>
        </div>

        {filtered.length === 0 ? (
          <div className="flex h-32 flex-col items-center justify-center text-center">
            <CheckCircle className="h-8 w-8 text-emerald-300 mb-2" />
            <p className="text-sm font-medium text-gray-500">
              {packages.length === 0 ? 'No actionable packages found' : 'No matches for current filters'}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-gray-100">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-100">
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Package</th>
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Version</th>
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Type</th>
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Effective License</th>
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Category</th>
                  <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Image</th>
                </tr>
              </thead>
              <tbody>
                {filtered.slice(0, 100).map((p, i) => (
                  <tr key={`${p.name}-${p.version}-${i}`}
                    className={`border-b border-gray-50 transition-colors hover:bg-violet-50/30 ${i % 2 === 0 ? 'bg-white' : 'bg-gray-50/30'}`}>
                    <td className="px-4 py-3">
                      <span className="font-semibold text-gray-900">{p.name}</span>
                    </td>
                    <td className="px-4 py-3">
                      <code className="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[11px] text-gray-600">{p.version}</code>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex rounded-md bg-violet-50 px-2 py-0.5 text-[11px] font-semibold text-violet-700">{p.pkg_type}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-gray-700 font-medium">{p.effective_license}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-bold"
                        style={{ background: (LICENSE_COLORS[p.license_category] ?? '#6b7280') + '15', color: LICENSE_COLORS[p.license_category] ?? '#6b7280' }}>
                        <span className="h-1.5 w-1.5 rounded-full" style={{ background: LICENSE_COLORS[p.license_category] ?? '#6b7280' }} />
                        {p.license_category}
                      </span>
                    </td>
                    <td className="px-4 py-3 max-w-[180px]">
                      <span className="text-gray-400 truncate block" title={p.image}>
                        {p.image?.split('/').pop() ?? p.image}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length > 100 && (
              <div className="border-t border-gray-100 bg-gray-50 px-4 py-2.5 text-center text-xs text-gray-400">
                Showing first 100 of {filtered.length} packages
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// ── Dependency: Scan type severity cards ──────────────────────────────────────
function ScanTypeCards({ data, viewMode }: { data: ScanTypeSev[]; viewMode: 'findings' | 'packages' }) {
  if (data.length === 0) {
    return (
      <div className="rounded-xl bg-white p-8 shadow-sm border border-gray-100 text-center text-sm text-gray-400">
        No scan data yet
      </div>
    );
  }
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {data.map(d => {
        const isDep = d.scan_type === 'Dependency';
        const isPkg = viewMode === 'packages' && isDep;
        const displayTotal = isPkg ? d.total_packages : d.total;
        const bars = [
          { key: 'critical', color: '#ef4444', val: d.critical },
          { key: 'high',     color: '#f97316', val: d.high },
          { key: 'medium',   color: '#eab308', val: d.medium },
          { key: 'low',      color: '#3b82f6', val: d.low },
          { key: 'info',     color: '#9ca3af', val: d.info },
        ].filter(b => b.val > 0);
        const total = d.total || 1;
        const accent = SCAN_COLORS[d.scan_type] ?? '#6366f1';
        return (
          <div key={d.scan_type}
            className="relative overflow-hidden rounded-md border border-gray-200 bg-white p-4">
            <div className="absolute inset-x-0 top-0 h-0.5" style={{ background: accent }} />
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                {(() => {
                  const Ic = SCAN_LUCIDE_ICONS[d.scan_type] ?? Shield;
                  return (
                    <div className="flex h-7 w-7 items-center justify-center rounded" style={{ background: accent + '15' }}>
                      <Ic className="h-3.5 w-3.5" style={{ color: accent }} />
                    </div>
                  );
                })()}
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-600">{d.scan_type}</span>
              </div>
              <div className="text-right">
                <p className="text-2xl font-bold tracking-tight" style={{ color: accent, fontVariantNumeric: 'tabular-nums' }}>
                  {displayTotal.toLocaleString()}
                </p>
                <p className="text-[10px] font-medium uppercase tracking-wider text-gray-400">{isPkg ? 'packages' : 'findings'}</p>
              </div>
            </div>
            {isPkg && d.total_packages > 0 && (
              <div className="mb-3 flex items-center gap-2">
                <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2.5 py-1 text-xs font-semibold text-green-700">
                  <CheckCircle className="h-3 w-3" />{d.fixable_packages.toLocaleString()} fixable
                </span>
                <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-600">
                  <XCircle className="h-3 w-3" />{d.no_fix_packages.toLocaleString()} no fix
                </span>
              </div>
            )}
            <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-gray-100 mb-3">
              {bars.map(b => (
                <div key={b.key} style={{ width: `${(b.val / total) * 100}%`, background: b.color }} />
              ))}
            </div>
            <div className="flex flex-wrap gap-x-3 gap-y-1.5">
              {bars.map(b => (
                <span key={b.key} className="flex items-center gap-1 text-xs">
                  <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: b.color }} />
                  <span className="capitalize text-gray-500">{b.key}</span>
                  <span className="font-semibold text-gray-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{b.val.toLocaleString()}</span>
                </span>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Compare components ────────────────────────────────────────────────────────
const SCAN_ORDER = ['Dependency', 'Secrets', 'SBOM', 'SAST', 'DAST', 'K8s'];

// ── Compare: Side-by-side metric table ────────────────────────────────────────
function CompareMetricsTable({ summaryA, summaryB, nameA, nameB }: {
  summaryA: SummaryData | null; summaryB: SummaryData | null; nameA: string; nameB: string;
}) {
  const metrics = [
    { label: 'Total Findings', a: summaryA?.total_findings ?? 0, b: summaryB?.total_findings ?? 0, icon: Shield, accent: '#6366f1' },
    { label: 'Critical',       a: summaryA?.critical ?? 0,       b: summaryB?.critical ?? 0,       icon: AlertCircle, accent: '#dc2626' },
    { label: 'High',           a: summaryA?.high ?? 0,           b: summaryB?.high ?? 0,           icon: AlertTriangle, accent: '#f97316' },
    { label: 'Medium',         a: summaryA?.medium ?? 0,         b: summaryB?.medium ?? 0,         icon: AlertTriangle, accent: '#eab308' },
    { label: 'Packages',       a: summaryA?.total_packages ?? 0, b: summaryB?.total_packages ?? 0, icon: Package, accent: '#8b5cf6' },
    { label: 'Fixable',        a: summaryA?.fixable_packages ?? 0,  b: summaryB?.fixable_packages ?? 0,  icon: CheckCircle, accent: '#22c55e' },
    { label: 'No Fix',         a: summaryA?.no_fix_packages ?? 0,   b: summaryB?.no_fix_packages ?? 0,   icon: XCircle, accent: '#ef4444' },
    { label: 'Actionable',     a: summaryA?.actionable_packages ?? 0, b: summaryB?.actionable_packages ?? 0, icon: TrendingUp, accent: '#f59e0b' },
  ];

  return (
    <div className="rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
      <div className="border-b border-gray-100 px-6 py-4">
        <h2 className="text-sm font-bold text-gray-900">Key Metrics</h2>
        <p className="mt-0.5 text-xs text-gray-400">Side-by-side comparison of security posture</p>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-gray-100 bg-gray-50">
            <th className="px-6 py-3 text-left font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Metric</th>
            <th className="px-4 py-3 text-right font-semibold uppercase tracking-wider text-[10px]" style={{ color: CMP_A }}>{nameA}</th>
            <th className="px-4 py-3 text-center font-semibold text-gray-400 uppercase tracking-wider text-[10px] w-24">Diff</th>
            <th className="px-4 py-3 text-right font-semibold uppercase tracking-wider text-[10px]" style={{ color: CMP_B }}>{nameB}</th>
            <th className="px-6 py-3 text-left font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Ratio</th>
          </tr>
        </thead>
        <tbody>
          {metrics.map((m, i) => {
            const diff = m.a - m.b;
            const max = Math.max(m.a, m.b) || 1;
            const Icon = m.icon;
            return (
              <tr key={m.label} className={`border-b border-gray-50 ${i % 2 === 0 ? 'bg-white' : 'bg-gray-50/30'}`}>
                <td className="px-6 py-3">
                  <div className="flex items-center gap-2.5">
                    <div className="flex h-6 w-6 items-center justify-center rounded-lg" style={{ background: m.accent + '15' }}>
                      <Icon className="h-3 w-3" style={{ color: m.accent }} />
                    </div>
                    <span className="font-semibold text-gray-700">{m.label}</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-right">
                  <span className="text-sm font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{m.a.toLocaleString()}</span>
                </td>
                <td className="px-4 py-3 text-center">
                  {diff !== 0 ? (
                    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
                      diff > 0 ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600'
                    }`}>
                      {diff > 0 ? '+' : ''}{diff.toLocaleString()}
                    </span>
                  ) : (
                    <span className="text-gray-300">=</span>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  <span className="text-sm font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{m.b.toLocaleString()}</span>
                </td>
                <td className="px-6 py-3">
                  <div className="flex items-center gap-1.5">
                    <div className="flex h-2 w-24 overflow-hidden rounded-full bg-gray-100">
                      <div className="h-full rounded-l-full" style={{ width: `${(m.a / max) * 100}%`, background: CMP_A }} />
                    </div>
                    <div className="flex h-2 w-24 overflow-hidden rounded-full bg-gray-100 flex-row-reverse">
                      <div className="h-full rounded-r-full" style={{ width: `${(m.b / max) * 100}%`, background: CMP_B }} />
                    </div>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ── Compare: Scan-type grouped bar chart ──────────────────────────────────────
function CompareScanChart({ dataA, dataB, nameA, nameB }: {
  dataA: ToolItem[]; dataB: ToolItem[]; nameA: string; nameB: string;
}) {
  const mapA = Object.fromEntries(dataA.map(d => [d.tool_name, d.count]));
  const mapB = Object.fromEntries(dataB.map(d => [d.tool_name, d.count]));
  const keys = Array.from(new Set([...dataA.map(d => d.tool_name), ...dataB.map(d => d.tool_name)]))
    .sort((a, b) => {
      const ia = SCAN_ORDER.indexOf(a), ib = SCAN_ORDER.indexOf(b);
      return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
    });

  if (keys.length === 0) {
    return (
      <div className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-gray-100 text-center text-sm text-gray-400">
        Select both projects to compare
      </div>
    );
  }

  const chartData = keys.map(k => ({
    name: k,
    [nameA]: mapA[k] ?? 0,
    [nameB]: mapB[k] ?? 0,
  }));

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <div className="flex items-start justify-between mb-5">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Findings by Scan Type</h2>
          <p className="mt-0.5 text-xs text-gray-400">Grouped comparison across scan categories</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-medium">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_A }} />
            <span className="text-gray-600">{nameA}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_B }} />
            <span className="text-gray-600">{nameB}</span>
          </span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={Math.max(keys.length * 60 + 20, 200)}>
        <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 24, left: 8, bottom: 0 }} barGap={4}>
          <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
          <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fontSize: 12, fill: '#374151', fontWeight: 600 }} tickLine={false} axisLine={false} width={100} />
          <Tooltip
            contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 24px rgba(0,0,0,0.1)', fontSize: '12px' }}
            formatter={(v: number) => [v.toLocaleString(), 'findings']}
          />
          <Bar dataKey={nameA} fill={CMP_A} radius={[0, 4, 4, 0]} maxBarSize={20} />
          <Bar dataKey={nameB} fill={CMP_B} radius={[0, 4, 4, 0]} maxBarSize={20} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Compare: Severity side-by-side bar chart ──────────────────────────────────
function CompareSeverityChart({ summaryA, summaryB, nameA, nameB }: {
  summaryA: SummaryData | null; summaryB: SummaryData | null; nameA: string; nameB: string;
}) {
  const sevs = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const labels: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  const chartData = sevs.map(s => ({
    name: labels[s],
    [nameA]: (summaryA as any)?.[s] ?? 0,
    [nameB]: (summaryB as any)?.[s] ?? 0,
    color: SEV_COLORS[s],
  }));

  return (
    <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
      <div className="flex items-start justify-between mb-5">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Severity Comparison</h2>
          <p className="mt-0.5 text-xs text-gray-400">Finding counts by severity level</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-medium">
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_A }} />
            <span className="text-gray-600">{nameA}</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_B }} />
            <span className="text-gray-600">{nameB}</span>
          </span>
        </div>
      </div>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart data={chartData} margin={{ top: 4, right: 16, left: 0, bottom: 4 }} barGap={6}>
          <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" vertical={false} />
          <XAxis dataKey="name" tick={{ fontSize: 12, fill: '#374151', fontWeight: 500 }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
          <Tooltip
            contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 24px rgba(0,0,0,0.1)', fontSize: '12px' }}
            formatter={(v: number) => [v.toLocaleString(), 'findings']}
          />
          <Bar dataKey={nameA} fill={CMP_A} radius={[4, 4, 0, 0]} maxBarSize={32} />
          <Bar dataKey={nameB} fill={CMP_B} radius={[4, 4, 0, 0]} maxBarSize={32} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Compare: SBOM License comparison ──────────────────────────────────────────
function CompareLicenseSection({ dataA, dataB, nameA, nameB }: {
  dataA: SbomLicenseData | null; dataB: SbomLicenseData | null; nameA: string; nameB: string;
}) {
  const hasA = dataA && dataA.total_packages > 0;
  const hasB = dataB && dataB.total_packages > 0;
  if (!hasA && !hasB) return null;

  // Merge all categories from both sides
  const allCats = Array.from(new Set([
    ...(dataA?.by_category ?? []).map(c => c.category),
    ...(dataB?.by_category ?? []).map(c => c.category),
  ])).sort((a, b) => LICENSE_RISK_ORDER.indexOf(a) - LICENSE_RISK_ORDER.indexOf(b));

  const mapA = Object.fromEntries((dataA?.by_category ?? []).map(c => [c.category, c]));
  const mapB = Object.fromEntries((dataB?.by_category ?? []).map(c => [c.category, c]));

  const chartData = allCats.filter(cat => (mapA[cat]?.total_packages ?? 0) + (mapB[cat]?.total_packages ?? 0) > 0).map(cat => ({
    name: cat,
    [nameA]: mapA[cat]?.total_packages ?? 0,
    [nameB]: mapB[cat]?.total_packages ?? 0,
  }));

  const totalA = dataA?.total_packages ?? 0;
  const totalB = dataB?.total_packages ?? 0;
  const actionableA = dataA?.total_actionable ?? 0;
  const actionableB = dataB?.total_actionable ?? 0;
  const safeA = dataA?.total_not_actionable ?? 0;
  const safeB = dataB?.total_not_actionable ?? 0;
  const pctA = totalA > 0 ? (actionableA > 0 ? Math.min(Math.floor((safeA / totalA) * 100), 99) : 100) : 0;
  const pctB = totalB > 0 ? (actionableB > 0 ? Math.min(Math.floor((safeB / totalB) * 100), 99) : 100) : 0;

  return (
    <>
      {/* License metrics table */}
      <div className="rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
        <div className="border-b border-gray-100 px-6 py-4">
          <h2 className="text-sm font-bold text-gray-900">SBOM License Comparison</h2>
          <p className="mt-0.5 text-xs text-gray-400">License compliance and package distribution</p>
        </div>
        <table className="w-full text-xs">
          <thead>
            <tr className="border-b border-gray-100 bg-gray-50">
              <th className="px-6 py-3 text-left font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Metric</th>
              <th className="px-4 py-3 text-right font-semibold uppercase tracking-wider text-[10px]" style={{ color: CMP_A }}>{nameA}</th>
              <th className="px-4 py-3 text-center font-semibold text-gray-400 uppercase tracking-wider text-[10px] w-24">Diff</th>
              <th className="px-4 py-3 text-right font-semibold uppercase tracking-wider text-[10px]" style={{ color: CMP_B }}>{nameB}</th>
            </tr>
          </thead>
          <tbody>
            {[
              { label: 'Total Packages', a: totalA, b: totalB, icon: Package, accent: '#8b5cf6' },
              { label: 'Permissive', a: safeA, b: safeB, icon: CheckCircle, accent: '#10b981' },
              { label: 'Actionable (Copyleft)', a: actionableA, b: actionableB, icon: AlertCircle, accent: '#ef4444' },
              { label: 'Compliance', a: pctA, b: pctB, icon: Shield, accent: '#f59e0b', isPct: true },
            ].map((m, i) => {
              const diff = m.a - m.b;
              const Icon = m.icon;
              return (
                <tr key={m.label} className={`border-b border-gray-50 ${i % 2 === 0 ? 'bg-white' : 'bg-gray-50/30'}`}>
                  <td className="px-6 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className="flex h-6 w-6 items-center justify-center rounded-lg" style={{ background: m.accent + '15' }}>
                        <Icon className="h-3 w-3" style={{ color: m.accent }} />
                      </div>
                      <span className="font-semibold text-gray-700">{m.label}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className="text-sm font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {m.a.toLocaleString()}{(m as any).isPct ? '%' : ''}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-center">
                    {diff !== 0 ? (
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-bold ${
                        m.label === 'Compliance'
                          ? (diff > 0 ? 'bg-green-50 text-green-600' : 'bg-red-50 text-red-600')
                          : (diff > 0 ? 'bg-red-50 text-red-600' : 'bg-green-50 text-green-600')
                      }`}>
                        {diff > 0 ? '+' : ''}{diff.toLocaleString()}{(m as any).isPct ? '%' : ''}
                      </span>
                    ) : (
                      <span className="text-gray-300">=</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <span className="text-sm font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>
                      {m.b.toLocaleString()}{(m as any).isPct ? '%' : ''}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* License category grouped bar chart */}
      {chartData.length > 0 && (
        <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
          <div className="flex items-start justify-between mb-5">
            <div>
              <h2 className="text-sm font-bold text-gray-900">License Distribution</h2>
              <p className="mt-0.5 text-xs text-gray-400">Packages by license category per project</p>
            </div>
            <div className="flex items-center gap-4 text-xs font-medium">
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_A }} />
                <span className="text-gray-600">{nameA}</span>
              </span>
              <span className="flex items-center gap-1.5">
                <span className="h-2.5 w-6 rounded-sm" style={{ background: CMP_B }} />
                <span className="text-gray-600">{nameB}</span>
              </span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={Math.max(chartData.length * 56 + 20, 200)}>
            <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 24, left: 8, bottom: 0 }} barGap={4}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
              <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 12, fill: '#374151', fontWeight: 600 }} tickLine={false} axisLine={false} width={110} />
              <Tooltip
                contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 24px rgba(0,0,0,0.1)', fontSize: '12px' }}
                formatter={(v: number) => [v.toLocaleString(), 'packages']}
              />
              <Bar dataKey={nameA} fill={CMP_A} radius={[0, 4, 4, 0]} maxBarSize={20} />
              <Bar dataKey={nameB} fill={CMP_B} radius={[0, 4, 4, 0]} maxBarSize={20} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Side-by-side risk split */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {[{ data: dataA, name: nameA, color: CMP_A }, { data: dataB, name: nameB, color: CMP_B }].map(({ data, name, color }) => {
          const total = data?.total_packages ?? 0;
          const act = data?.total_actionable ?? 0;
          const safe = data?.total_not_actionable ?? 0;
          if (total === 0) return (
            <div key={name} className="rounded-2xl bg-white p-8 shadow-sm ring-1 ring-gray-100 text-center">
              <Package className="mx-auto h-8 w-8 text-gray-200 mb-2" />
              <p className="text-sm font-medium text-gray-400">No SBOM data for {name}</p>
            </div>
          );
          const copyleft = (data?.by_category ?? []).filter(c => ['GPL', 'AGPL', 'LGPL'].includes(c.category));
          const permissive = (data?.by_category ?? []).filter(c => !['GPL', 'AGPL', 'LGPL', 'Unknown', 'Other'].includes(c.category));
          const copyleftTotal = copyleft.reduce((s, c) => s + c.total_packages, 0);
          const permissiveTotal = permissive.reduce((s, c) => s + c.total_packages, 0);
          return (
            <div key={name} className="rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-100 overflow-hidden">
              <div className="flex items-center gap-2.5 mb-4">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: color + '15' }}>
                  <Package className="h-3.5 w-3.5" style={{ color }} />
                </div>
                <h3 className="text-sm font-bold text-gray-900">{name}</h3>
                <span className="ml-auto text-xs font-semibold text-gray-400">{total} packages</span>
              </div>
              {/* Split bar */}
              <div className="flex h-3 w-full overflow-hidden rounded-full bg-gray-100 mb-4">
                {copyleftTotal > 0 && <div className="h-full bg-red-400" style={{ width: `${(copyleftTotal / total) * 100}%` }} />}
                {permissiveTotal > 0 && <div className="h-full bg-emerald-400" style={{ width: `${(permissiveTotal / total) * 100}%` }} />}
                <div className="h-full bg-gray-300 flex-1" />
              </div>
              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl bg-red-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-red-600">Copyleft</p>
                  <p className="mt-1 text-xl font-bold text-red-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{copyleftTotal}</p>
                  <p className="text-[10px] text-red-400">{act} actionable</p>
                </div>
                <div className="rounded-xl bg-emerald-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-emerald-600">Permissive</p>
                  <p className="mt-1 text-xl font-bold text-emerald-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{permissiveTotal}</p>
                  <p className="text-[10px] text-emerald-400">{safe} compliant</p>
                </div>
                <div className="rounded-xl bg-gray-50 p-3">
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-500">Unknown</p>
                  <p className="mt-1 text-xl font-bold text-gray-600" style={{ fontVariantNumeric: 'tabular-nums' }}>{total - copyleftTotal - permissiveTotal}</p>
                  <p className="text-[10px] text-gray-400">unclassified</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </>
  );
}

// ── K8s Dashboard (purpose-built) ─────────────────────────────────────────────
const KIND_ICON_MAP: Record<string, typeof Box> = {
  Deployment: Layers, StatefulSet: Layers, DaemonSet: Layers, ReplicaSet: Layers,
  Pod: Box, ConfigMap: FileText, ClusterRole: Shield, Role: Shield,
  ServiceAccount: Lock, Namespace: Globe, Node: Server,
};

function K8sDashboard({
  summary, toolData, k8sCategories, k8sResources, k8sNamespaces, loading,
  k8sTool, setK8sTool,
}: {
  summary: SummaryData | null; toolData: ToolItem[];
  k8sCategories: K8sCategoryItem[]; k8sResources: K8sResourceItem[];
  k8sNamespaces: K8sNamespaceItem[]; loading: boolean;
  k8sTool: string; setK8sTool: (v: string) => void;
}) {
  /* Derive severity counts from k8sCategories (already filtered by tool) */
  const crit = k8sCategories.reduce((s, c) => s + c.critical, 0);
  const high = k8sCategories.reduce((s, c) => s + c.high, 0);
  const med  = k8sCategories.reduce((s, c) => s + c.medium, 0);
  const low  = k8sCategories.reduce((s, c) => s + c.low, 0);
  const total = k8sCategories.reduce((s, c) => s + c.total, 0);
  const complianceScore = total > 0 ? Math.max(0, Math.round(100 - ((crit * 10 + high * 5 + med * 2 + low * 0.5) / total) * 10)) : 100;

  /* Resource kind aggregation */
  const kindMap = new Map<string, { count: number; critical: number; high: number; findings: number }>();
  for (const r of k8sResources) {
    const prev = kindMap.get(r.kind) ?? { count: 0, critical: 0, high: 0, findings: 0 };
    kindMap.set(r.kind, {
      count: prev.count + 1,
      critical: prev.critical + r.critical,
      high: prev.high + r.high,
      findings: prev.findings + r.total_findings,
    });
  }
  const kindData = [...kindMap.entries()]
    .map(([kind, v]) => ({ kind, ...v }))
    .sort((a, b) => b.findings - a.findings);

  /* Namespace chart data */
  const nsChartData = k8sNamespaces
    .map(d => ({ name: d.namespace || 'cluster-wide', Critical: d.critical, High: d.high, Medium: d.medium, Low: d.low, total: d.total_findings }))
    .sort((a, b) => b.total - a.total)
    .slice(0, 10);

  /* Top risky resources */
  const topResources = [...k8sResources]
    .sort((a, b) => (b.critical * 100 + b.high * 10 + b.medium) - (a.critical * 100 + a.high * 10 + a.medium))
    .slice(0, 8);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="h-32 animate-pulse rounded-2xl bg-gray-100" />
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">{[...Array(4)].map((_, i) => <div key={i} className="h-24 animate-pulse rounded-2xl bg-gray-100" />)}</div>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"><div className="h-64 animate-pulse rounded-2xl bg-gray-100" /><div className="h-64 animate-pulse rounded-2xl bg-gray-100" /></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ── Tool toggle ── */}
      <div className="inline-flex border border-gray-300 rounded-md overflow-hidden w-fit">
        {[
          { key: '', label: 'All Tools' },
          { key: 'trivy', label: 'Trivy' },
          { key: 'kubescape', label: 'Kubescape' },
        ].map((opt, idx) => {
          const active = k8sTool === opt.key;
          return (
            <button key={opt.key} onClick={() => setK8sTool(opt.key)}
              className={`px-4 py-1.5 text-sm font-medium transition-colors ${idx > 0 ? 'border-l border-gray-300' : ''} ${
                active ? 'bg-gray-900 text-white' : 'bg-white text-gray-600 hover:bg-gray-50'
              }`}>
              {opt.label}
            </button>
          );
        })}
      </div>

      {/* ── Cluster health ── */}
      <div className="border border-gray-200 bg-white rounded-md p-5">
        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="flex h-11 w-11 items-center justify-center rounded border border-gray-200 bg-gray-50">
              <Server className="h-5 w-5 text-gray-700" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-gray-900 uppercase tracking-wider">
                {k8sTool ? `${k8sTool.charAt(0).toUpperCase() + k8sTool.slice(1)} ` : ''}Cluster Posture
              </h2>
              <p className="text-xs text-gray-500 font-mono mt-0.5">{k8sNamespaces.length} namespaces · {k8sResources.length} resources</p>
            </div>
          </div>
          <div className="flex items-center gap-6">
            {/* Compliance score ring */}
            <div className="relative flex h-16 w-16 items-center justify-center">
              <svg className="h-16 w-16 -rotate-90" viewBox="0 0 36 36">
                <circle cx="18" cy="18" r="15" fill="none" stroke="#e5e7eb" strokeWidth="2.5" />
                <circle cx="18" cy="18" r="15" fill="none"
                  stroke={complianceScore >= 80 ? '#059669' : complianceScore >= 50 ? '#d97706' : '#dc2626'}
                  strokeWidth="2.5" strokeDasharray={`${complianceScore * 0.942} 100`} strokeLinecap="round" />
              </svg>
              <div className="absolute text-center">
                <span className="text-base font-semibold text-gray-900 tabular-nums">{complianceScore}</span>
                <span className="block text-[8px] text-gray-400 uppercase tracking-wider">Score</span>
              </div>
            </div>
            {/* Severity pills - flat style */}
            <div className="flex items-center gap-1.5 text-xs font-mono">
              {crit > 0 && <span className="border-l-2 border-red-600 pl-2"><span className="font-semibold text-gray-900">{crit}</span> <span className="text-gray-500">Crit</span></span>}
              {high > 0 && <span className="border-l-2 border-orange-500 pl-2"><span className="font-semibold text-gray-900">{high}</span> <span className="text-gray-500">High</span></span>}
              {med > 0 && <span className="border-l-2 border-yellow-500 pl-2"><span className="font-semibold text-gray-900">{med}</span> <span className="text-gray-500">Med</span></span>}
              {low > 0 && <span className="border-l-2 border-blue-500 pl-2"><span className="font-semibold text-gray-900">{low}</span> <span className="text-gray-500">Low</span></span>}
            </div>
          </div>
        </div>
      </div>

      {/* ── Resource kind breakdown ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {kindData.slice(0, 6).map(k => {
          const KIcon = KIND_ICON_MAP[k.kind] ?? Box;
          return (
            <div key={k.kind} className="rounded-2xl bg-white p-4 shadow-sm ring-1 ring-gray-100">
              <div className="flex items-center gap-2 mb-2">
                <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-slate-100">
                  <KIcon className="h-3.5 w-3.5 text-slate-600" />
                </div>
                <span className="text-xs font-bold text-gray-700 truncate">{k.kind}</span>
              </div>
              <p className="text-2xl font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{k.count}</p>
              <div className="mt-1 flex items-center gap-2 text-[10px]">
                <span className="text-gray-400">{k.findings} findings</span>
                {k.critical > 0 && <span className="font-bold text-red-500">{k.critical}C</span>}
                {k.high > 0 && <span className="font-bold text-orange-500">{k.high}H</span>}
              </div>
            </div>
          );
        })}
      </div>

      {/* ── Row 2: Namespace chart + Security categories ── */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Namespace chart */}
        <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
          <h2 className="text-sm font-bold text-gray-800">Namespace Risk Map</h2>
          <p className="mt-0.5 mb-4 text-xs text-gray-400">Top namespaces by finding count</p>
          {nsChartData.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-sm text-gray-400">No data</div>
          ) : (
            <>
              <div className="mb-3 flex flex-wrap gap-3 text-[10px]">
                {['Critical','High','Medium','Low'].map(s => (
                  <span key={s} className="flex items-center gap-1">
                    <span className="h-2 w-2 rounded-sm" style={{ background: SEV_COLORS[s.toLowerCase()] }} />{s}
                  </span>
                ))}
              </div>
              <ResponsiveContainer width="100%" height={Math.max(nsChartData.length * 38 + 10, 140)}>
                <BarChart data={nsChartData} layout="vertical" margin={{ top: 0, right: 40, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#374151', fontWeight: 500 }} tickLine={false} axisLine={false} width={100} />
                  <Tooltip />
                  <Bar dataKey="Critical" stackId="a" fill={SEV_COLORS.critical} maxBarSize={20} />
                  <Bar dataKey="High"     stackId="a" fill={SEV_COLORS.high}     maxBarSize={20} />
                  <Bar dataKey="Medium"   stackId="a" fill={SEV_COLORS.medium}   maxBarSize={20} />
                  <Bar dataKey="Low"      stackId="a" fill={SEV_COLORS.low}      radius={[0, 3, 3, 0]} maxBarSize={20} />
                </BarChart>
              </ResponsiveContainer>
            </>
          )}
        </div>

        {/* Security categories */}
        <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
          <h2 className="text-sm font-bold text-gray-800">Security Categories</h2>
          <p className="mt-0.5 mb-4 text-xs text-gray-400">Finding distribution by compliance area</p>
          {k8sCategories.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-sm text-gray-400">No data</div>
          ) : (
            <div className="space-y-3">
              {k8sCategories.sort((a, b) => b.total - a.total).map(cat => {
                const catTotal = cat.total || 1;
                const bars = [
                  { key: 'critical', color: '#ef4444', val: cat.critical },
                  { key: 'high',     color: '#f97316', val: cat.high },
                  { key: 'medium',   color: '#eab308', val: cat.medium },
                  { key: 'low',      color: '#3b82f6', val: cat.low },
                ].filter(b => b.val > 0);
                return (
                  <div key={cat.category}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-gray-700">{cat.category}</span>
                      <span className="text-xs font-bold text-gray-900" style={{ fontVariantNumeric: 'tabular-nums' }}>{cat.total}</span>
                    </div>
                    <div className="flex h-2 w-full overflow-hidden rounded-full bg-gray-100">
                      {bars.map(b => (
                        <div key={b.key} className="h-full transition-all" style={{ width: `${(b.val / catTotal) * 100}%`, background: b.color }} />
                      ))}
                    </div>
                    <div className="mt-1 flex gap-2 text-[10px]">
                      {bars.map(b => (
                        <span key={b.key} className="flex items-center gap-0.5">
                          <span className="h-1.5 w-1.5 rounded-full" style={{ background: b.color }} />
                          <span className="capitalize text-gray-400">{b.key}</span>
                          <span className="font-semibold text-gray-600">{b.val}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── Row 3: Tool comparison + Top risky resources ── */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Tool comparison */}
        <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
          <h2 className="text-sm font-bold text-gray-800">Scanner Coverage</h2>
          <p className="mt-0.5 mb-4 text-xs text-gray-400">Findings by scanning tool</p>
          {toolData.length === 0 ? (
            <div className="flex h-32 items-center justify-center text-sm text-gray-400">No data</div>
          ) : (
            <div className="space-y-4">
              {toolData.map(t => {
                const toolTotal = toolData.reduce((s, d) => s + d.count, 0) || 1;
                const pct = Math.round((t.count / toolTotal) * 100);
                const isKubescape = t.tool_name.toLowerCase().includes('kubescape');
                const color = isKubescape ? '#10b981' : '#3b82f6';
                return (
                  <div key={t.tool_name}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <div className="flex h-7 w-7 items-center justify-center rounded-lg" style={{ background: color + '15' }}>
                          <Shield className="h-3.5 w-3.5" style={{ color }} />
                        </div>
                        <div>
                          <p className="text-xs font-bold text-gray-800 capitalize">{t.tool_name}</p>
                          <p className="text-[9px] text-gray-400">{isKubescape ? 'Compliance' : 'Misconfig'}</p>
                        </div>
                      </div>
                      <span className="text-lg font-bold" style={{ color, fontVariantNumeric: 'tabular-nums' }}>{t.count}</span>
                    </div>
                    <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: color }} />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Top risky resources */}
        <div className="lg:col-span-2 rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-100">
            <h2 className="text-sm font-bold text-gray-800">Top Risky Resources</h2>
            <p className="text-xs text-gray-400">Resources ranked by severity impact</p>
          </div>
          {topResources.length === 0 ? (
            <div className="flex h-40 items-center justify-center text-sm text-gray-400">No data</div>
          ) : (
            <div className="divide-y divide-gray-50">
              {topResources.map((r, i) => {
                const RIcon = KIND_ICON_MAP[r.kind] ?? Box;
                const riskScore = r.critical * 100 + r.high * 10 + r.medium;
                return (
                  <div key={`${r.kind}-${r.name}-${r.namespace}-${i}`} className="flex items-center gap-3 px-6 py-3 hover:bg-gray-50/50 transition-colors">
                    <span className="w-5 text-right text-xs font-bold text-gray-300">#{i + 1}</span>
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100">
                      <RIcon className="h-4 w-4 text-slate-600" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="rounded bg-slate-200 px-1.5 py-0.5 text-[9px] font-bold uppercase text-slate-600">{r.kind}</span>
                        <span className="text-sm font-semibold text-gray-800 truncate">{r.name}</span>
                      </div>
                      {r.namespace && <span className="text-[10px] text-gray-400">ns: {r.namespace}</span>}
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {r.critical > 0 && <span className="rounded-full bg-red-100 px-2 py-0.5 text-[10px] font-bold text-red-700">{r.critical}</span>}
                      {r.high > 0 && <span className="rounded-full bg-orange-100 px-2 py-0.5 text-[10px] font-bold text-orange-700">{r.high}</span>}
                      {r.medium > 0 && <span className="rounded-full bg-yellow-100 px-2 py-0.5 text-[10px] font-bold text-yellow-700">{r.medium}</span>}
                      {r.low > 0 && <span className="rounded-full bg-blue-100 px-2 py-0.5 text-[10px] font-bold text-blue-700">{r.low}</span>}
                      <span className="ml-1 text-xs font-bold text-gray-400" style={{ fontVariantNumeric: 'tabular-nums' }}>{r.total_findings}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Main ──────────────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [projects, setProjects]           = useState<ProjectItem[]>([]);
  const [selectedId, setSelectedId]       = useState('');
  const [compareMode, setCompareMode]     = useState(false);
  const [pidA, setPidA]                   = useState('');
  const [pidB, setPidB]                   = useState('');

  const [summary, setSummary]             = useState<SummaryData | null>(null);
  const [toolData, setToolData]           = useState<ToolItem[]>([]);
  const [scanTypeSev, setScanTypeSev]     = useState<ScanTypeSev[]>([]);
  const [imageData, setImageData]         = useState<ImageItem[]>([]);
  const [secretsCategories, setSecretsCategories] = useState<SecretsCategoryItem[]>([]);
  const [sbomLicense, setSbomLicense]             = useState<SbomLicenseData | null>(null);

  const [summaryA, setSummaryA]           = useState<SummaryData | null>(null);
  const [summaryB, setSummaryB]           = useState<SummaryData | null>(null);
  const [toolDataA, setToolDataA]         = useState<ToolItem[]>([]);
  const [toolDataB, setToolDataB]         = useState<ToolItem[]>([]);
  const [scanTypeSevA, setScanTypeSevA]   = useState<ScanTypeSev[]>([]);
  const [scanTypeSevB, setScanTypeSevB]   = useState<ScanTypeSev[]>([]);
  const [sbomLicenseA, setSbomLicenseA]   = useState<SbomLicenseData | null>(null);
  const [sbomLicenseB, setSbomLicenseB]   = useState<SbomLicenseData | null>(null);

  const [k8sCategories, setK8sCategories] = useState<K8sCategoryItem[]>([]);
  const [k8sResources, setK8sResources]   = useState<K8sResourceItem[]>([]);
  const [k8sNamespaces, setK8sNamespaces] = useState<K8sNamespaceItem[]>([]);
  const [k8sTool, setK8sTool]             = useState('');  // '' = all, 'trivy', 'kubescape'

  const [loading, setLoading]             = useState(true);
  const [cmpLoading, setCmpLoading]       = useState(false);
  const [availableScanTypes, setAvailableScanTypes] = useState<string[]>([]);
  const [scanTypeFilter, setScanTypeFilter] = useState('');   // set after first load

  // Load projects — start with "All Projects" (empty string)
  useEffect(() => {
    getProjects(1, 500).then(res => {
      const arr: any[] = Array.isArray(res) ? res : (res.items ?? res.results ?? []);
      const mapped = arr.map((p: any) => ({ id: p.id, name: p.name }));
      setProjects(mapped);
    }).catch(() => {});
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch available scan type tabs (unfiltered) whenever project changes
  useEffect(() => {
    getScanTypeSeverity(selectedId || undefined).then(res => {
      const types: string[] = (res.data ?? []).map((d: any) => d.scan_type);
      setAvailableScanTypes(types);
      // Auto-select first type if nothing selected yet
      setScanTypeFilter(prev => (!prev && types.length > 0) ? types[0] : prev);
    }).catch(() => {});
  }, [selectedId]);

  // Load primary data for selected scan type
  const fetchPrimary = useCallback(async (pid?: string, scanType?: string, k8sToolFilter?: string) => {
    setLoading(true);
    try {
      const isSecrets = scanType === 'Secrets';
      const isSbom = scanType === 'SBOM';
      const isK8s = scanType === 'K8s';
      const tn = k8sToolFilter || undefined;
      const [sum, tool, stSev, img, cats, sbom, k8sCats, k8sRes, k8sNs] = await Promise.all([
        getSummary(pid, scanType),
        getToolBreakdown(pid, scanType),
        getScanTypeSeverity(pid, scanType),
        getImageBreakdown(pid, scanType),
        isSecrets ? getCategoryBreakdown(pid, scanType) : Promise.resolve({ data: [] }),
        isSbom ? getSbomLicenseBreakdown(pid) : Promise.resolve(null),
        isK8s ? getK8sCategories(pid, tn) : Promise.resolve({ data: [] }),
        isK8s ? getK8sResources(pid, tn) : Promise.resolve({ data: [] }),
        isK8s ? getK8sNamespaces(pid, tn) : Promise.resolve({ data: [] }),
      ]);
      setSummary(sum);
      setToolData(tool.data ?? []);
      setScanTypeSev(stSev.data ?? []);
      setImageData(img.data ?? []);
      setSecretsCategories(cats.data ?? []);
      setSbomLicense(sbom);
      setK8sCategories(k8sCats.data ?? []);
      setK8sResources(k8sRes.data ?? []);
      setK8sNamespaces(k8sNs.data ?? []);
    } catch { /* noop */ }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (!scanTypeFilter) return;
    fetchPrimary(selectedId || undefined, scanTypeFilter, scanTypeFilter === 'K8s' ? k8sTool : undefined);
  }, [selectedId, scanTypeFilter, k8sTool, fetchPrimary]);

  // Load compare data
  useEffect(() => {
    if (!compareMode || (!pidA && !pidB)) return;
    setCmpLoading(true);
    Promise.all([
      pidA ? Promise.all([getSummary(pidA), getToolBreakdown(pidA), getScanTypeSeverity(pidA), getSbomLicenseBreakdown(pidA)]) : Promise.resolve([null, { data: [] }, { data: [] }, null]),
      pidB ? Promise.all([getSummary(pidB), getToolBreakdown(pidB), getScanTypeSeverity(pidB), getSbomLicenseBreakdown(pidB)]) : Promise.resolve([null, { data: [] }, { data: [] }, null]),
    ]).then(([[sa, ta, sta, sla], [sb, tb, stb, slb]]) => {
      setSummaryA(sa as SummaryData | null);
      setSummaryB(sb as SummaryData | null);
      setToolDataA((ta as any)?.data ?? []);
      setToolDataB((tb as any)?.data ?? []);
      setScanTypeSevA((sta as any)?.data ?? []);
      setScanTypeSevB((stb as any)?.data ?? []);
      setSbomLicenseA(sla as SbomLicenseData | null);
      setSbomLicenseB(slb as SbomLicenseData | null);
    }).catch(() => {}).finally(() => setCmpLoading(false));
  }, [compareMode, pidA, pidB]);

  const nameA = projects.find(p => p.id === pidA)?.name ?? 'Project A';
  const nameB = projects.find(p => p.id === pidB)?.name ?? 'Project B';

  return (
    <div className="space-y-5">

      {/* ── Header bar ── */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-200 pb-4">
        <div>
          <h1 className="text-xl font-semibold text-gray-900">Security Overview</h1>
          <p className="mt-0.5 text-xs text-gray-500 font-mono">
            {selectedId ? `project: ${projects.find(p => p.id === selectedId)?.name ?? 'unknown'}` : 'all projects'}
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <select
            value={selectedId}
            onChange={e => { setSelectedId(e.target.value); setScanTypeFilter(''); }}
            className="rounded border border-gray-300 bg-white px-3 py-1.5 text-sm focus:border-gray-500 focus:outline-none"
          >
            <option value="">All Projects</option>
            {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>

          <button
            onClick={() => setCompareMode(v => !v)}
            className={`inline-flex items-center gap-1.5 rounded border px-3 py-1.5 text-sm font-medium transition-colors ${
              compareMode
                ? 'border-gray-900 bg-gray-900 text-white'
                : 'border-gray-300 bg-white text-gray-700 hover:bg-gray-50'
            }`}
          >
            <GitCompare className="h-3.5 w-3.5" />
            Compare
          </button>
        </div>
      </div>

      {/* ── Scan type tabs ── */}
      {!compareMode && availableScanTypes.length > 0 && (
        <div className="flex items-center gap-4 border-b border-gray-200">
          {availableScanTypes.map(label => {
            const accent = SCAN_COLORS[label] ?? '#6366f1';
            const active = scanTypeFilter === label;
            const Ic = SCAN_LUCIDE_ICONS[label] ?? Shield;
            return (
              <button
                key={label}
                onClick={() => setScanTypeFilter(label)}
                className={`inline-flex items-center gap-2 border-b-2 px-4 py-2 text-sm font-medium transition-colors ${
                  active ? 'text-gray-900' : 'border-transparent text-gray-500 hover:text-gray-700'
                }`}
                style={active ? { borderColor: accent } : undefined}
              >
                <Ic className="h-4 w-4" style={{ color: active ? accent : undefined }} />
                {label}
              </button>
            );
          })}
        </div>
      )}

      {/* ── Compare project pickers ── */}
      {compareMode && (
        <div className="rounded-2xl bg-white p-4 shadow-sm ring-1 ring-gray-100">
          <div className="flex flex-wrap items-center gap-3">
            {/* Project A */}
            <div className="flex items-center gap-2 flex-1 min-w-[200px]">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg" style={{ background: CMP_A + '15' }}>
                <span className="text-xs font-bold" style={{ color: CMP_A }}>A</span>
              </div>
              <select value={pidA} onChange={e => setPidA(e.target.value)}
                className="w-full rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 text-sm font-medium text-gray-700 shadow-sm
                           focus:border-indigo-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-100 transition-all">
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>

            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gray-100">
              <GitCompare className="h-3.5 w-3.5 text-gray-400" />
            </div>

            {/* Project B */}
            <div className="flex items-center gap-2 flex-1 min-w-[200px]">
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg" style={{ background: CMP_B + '15' }}>
                <span className="text-xs font-bold" style={{ color: CMP_B }}>B</span>
              </div>
              <select value={pidB} onChange={e => setPidB(e.target.value)}
                className="w-full rounded-xl border border-gray-200 bg-gray-50 px-3 py-2 text-sm font-medium text-gray-700 shadow-sm
                           focus:border-pink-400 focus:bg-white focus:outline-none focus:ring-2 focus:ring-pink-100 transition-all">
                <option value="">Select project...</option>
                {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            </div>
          </div>
        </div>
      )}

      {/* ── Compare view ── */}
      {compareMode ? (
        <div className="space-y-6">
          {cmpLoading ? (
            <div className="space-y-4">
              <SkeletonChart h="h-48" />
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"><SkeletonChart /><SkeletonChart /></div>
            </div>
          ) : (!pidA && !pidB) ? (
            <div className="rounded-2xl bg-white p-16 shadow-sm ring-1 ring-gray-100 text-center">
              <GitCompare className="mx-auto h-10 w-10 text-gray-200 mb-3" />
              <p className="text-sm font-medium text-gray-400">Select two projects above to compare</p>
            </div>
          ) : (
            <>
              {/* Metrics table */}
              <CompareMetricsTable summaryA={summaryA} summaryB={summaryB} nameA={nameA} nameB={nameB} />

              {/* Charts row: severity + scan type */}
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <CompareSeverityChart summaryA={summaryA} summaryB={summaryB} nameA={nameA} nameB={nameB} />
                <CompareScanChart dataA={toolDataA} dataB={toolDataB} nameA={nameA} nameB={nameB} />
              </div>

              {/* Severity donuts side by side */}
              <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
                <SeverityDonut summary={summaryA} title={`Severity - ${nameA}`} />
                <SeverityDonut summary={summaryB} title={`Severity - ${nameB}`} />
              </div>

              {/* SBOM License comparison */}
              <CompareLicenseSection dataA={sbomLicenseA} dataB={sbomLicenseB} nameA={nameA} nameB={nameB} />
            </>
          )}
        </div>

      /* ── Dependency dashboard ── */
      ) : scanTypeFilter === 'Dependency' ? (
        <>
          {/* ── Row 1: Stat cards + Fix Rate gauge ── */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-6">
            {loading ? (
              <>{[...Array(6)].map((_, i) => <SkeletonCard key={i} />)}</>
            ) : (() => {
              const total = summary?.total_packages ?? 0;
              const fixable = summary?.fixable_packages ?? 0;
              const rawPct = total > 0 ? (fixable / total) * 100 : 0;
              const fixPct = total > 0 ? Math.round(rawPct) : 0;
              const fixColor = fixPct >= 60 ? '#10b981' : fixPct >= 30 ? '#f59e0b' : '#ef4444';
              return (
                <>
                  <StatCard label="Total Packages"   value={total}                                accent="#6366f1" icon={Package}       sub="unique across all scans" />
                  <StatCard label="Fixable"          value={fixable}                              accent="#22c55e" icon={CheckCircle}   sub="patch available" />
                  <StatCard label="No Fix Available" value={summary?.no_fix_packages ?? 0}        accent="#ef4444" icon={XCircle}       sub="no patch yet" />
                  <StatCard label="Actionable"       value={summary?.actionable_packages ?? 0}    accent="#f59e0b" icon={TrendingUp}    sub="fixable + open" />
                  <StatCard label="Critical"         value={summary?.critical ?? 0}               accent="#dc2626" icon={AlertTriangle} sub="critical severity" />
                  {/* Fix Rate gauge card */}
                  <div className="relative overflow-hidden rounded-2xl bg-white p-5 shadow-sm ring-1 ring-gray-100 border-t-4"
                    style={{ borderTopColor: fixColor }}>
                    <div className="flex items-start justify-between">
                      <div>
                        <p className="text-[11px] font-semibold uppercase tracking-widest text-gray-400">Fix Rate</p>
                        <p className="mt-2 text-3xl font-bold tracking-tight" style={{ fontVariantNumeric: 'tabular-nums', color: fixColor }}>
                          {fixPct}%
                        </p>
                        <p className="mt-0.5 text-xs text-gray-400">packages fixable</p>
                      </div>
                      <div className="flex h-10 w-10 items-center justify-center rounded-xl" style={{ background: fixColor + '18' }}>
                        <Shield className="h-5 w-5" style={{ color: fixColor }} />
                      </div>
                    </div>
                    <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-gray-100">
                      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${fixPct}%`, background: fixColor }} />
                    </div>
                  </div>
                </>
              );
            })()}
          </div>

          {/* ── Row 2: Fixable / No-Fix split + Severity donut ── */}
          {loading ? (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"><SkeletonChart /><SkeletonChart /></div>
          ) : (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              {/* Fixable vs No-Fix split card */}
              {(() => {
                const total = summary?.total_packages ?? 0;
                const fixable = summary?.fixable_packages ?? 0;
                const noFix = summary?.no_fix_packages ?? 0;
                const actionable = summary?.actionable_packages ?? 0;
                const fixPct = total > 0 ? Math.round((fixable / total) * 100) : 0;
                const noFixPct = total > 0 ? Math.round((noFix / total) * 100) : 0;
                return (
                  <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
                    <h2 className="text-sm font-semibold text-gray-800">Remediation Status</h2>
                    <p className="mt-0.5 mb-5 text-xs text-gray-400">Package vulnerability fix availability</p>

                    {/* Visual split bar */}
                    <div className="mb-5">
                      <div className="flex h-3 w-full overflow-hidden rounded-full bg-gray-100">
                        {fixable > 0 && (
                          <div className="h-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-500"
                            style={{ width: `${fixPct}%` }} />
                        )}
                        {noFix > 0 && (
                          <div className="h-full bg-gradient-to-r from-red-400 to-red-500 transition-all duration-500"
                            style={{ width: `${noFixPct}%` }} />
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-4">
                      <div className="rounded-xl border border-emerald-100 bg-emerald-50/50 p-4">
                        <div className="flex items-center gap-2 mb-3">
                          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-emerald-100">
                            <CheckCircle className="h-3.5 w-3.5 text-emerald-600" />
                          </div>
                          <span className="text-xs font-bold uppercase tracking-wider text-emerald-700">Fixable</span>
                        </div>
                        <p className="text-2xl font-bold text-emerald-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{fixable.toLocaleString()}</p>
                        <p className="mt-1 text-xs text-emerald-500">{fixPct}% of packages</p>
                      </div>

                      <div className="rounded-xl border border-red-100 bg-red-50/50 p-4">
                        <div className="flex items-center gap-2 mb-3">
                          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-red-100">
                            <XCircle className="h-3.5 w-3.5 text-red-600" />
                          </div>
                          <span className="text-xs font-bold uppercase tracking-wider text-red-700">No Fix</span>
                        </div>
                        <p className="text-2xl font-bold text-red-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{noFix.toLocaleString()}</p>
                        <p className="mt-1 text-xs text-red-500">{noFixPct}% of packages</p>
                      </div>

                      <div className="rounded-xl border border-amber-100 bg-amber-50/50 p-4">
                        <div className="flex items-center gap-2 mb-3">
                          <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-amber-100">
                            <TrendingUp className="h-3.5 w-3.5 text-amber-600" />
                          </div>
                          <span className="text-xs font-bold uppercase tracking-wider text-amber-700">Actionable</span>
                        </div>
                        <p className="text-2xl font-bold text-amber-700" style={{ fontVariantNumeric: 'tabular-nums' }}>{actionable.toLocaleString()}</p>
                        <p className="mt-1 text-xs text-amber-500">fixable + open</p>
                      </div>
                    </div>
                  </div>
                );
              })()}

              {/* Severity donut */}
              <SeverityDonut summary={summary} />
            </div>
          )}

          {/* ── Row 3: Severity stacked bar by image + Top images fix chart ── */}
          {loading ? (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2"><SkeletonChart h="h-72" /><SkeletonChart h="h-72" /></div>
          ) : imageData.length > 0 && (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              {/* Top images - fix status */}
              <div className="rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
                <div className="border-b border-gray-100 px-6 py-4">
                  <h2 className="text-sm font-bold text-gray-900">Top Images by Fix Status</h2>
                  <p className="mt-0.5 text-xs text-gray-400">
                    <span className="text-emerald-600 font-medium">Fixable</span> vs <span className="text-red-500 font-medium">no fix</span> per container image
                  </p>
                </div>
                <div className="p-5">
                  <div className="mb-3 flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-sm bg-emerald-500 inline-block" />
                      <span className="font-medium text-gray-600">Fixable</span>
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span className="h-2.5 w-2.5 rounded-sm bg-red-400 inline-block" />
                      <span className="font-medium text-gray-600">No Fix</span>
                    </span>
                  </div>
                  <ResponsiveContainer width="100%" height={Math.min(imageData.length * 38 + 20, 400)}>
                    <BarChart
                      data={imageData.slice(0, 12).map(d => ({
                        name: d.image?.split('/').pop() ?? d.image,
                        full: d.image,
                        Fixable: d.fixable_count,
                        'No Fix': d.no_fix_count,
                      })).reverse()}
                      layout="vertical" margin={{ top: 0, right: 24, left: 8, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
                      <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                      <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#374151', fontWeight: 500 }} tickLine={false} axisLine={false} width={140} />
                      <Tooltip
                        contentStyle={{ borderRadius: '12px', border: 'none', boxShadow: '0 4px 24px rgba(0,0,0,0.1)', fontSize: '12px' }}
                        formatter={(v: number, name: string, p: any) => [v.toLocaleString(), `${name} — ${p.payload.full}`]}
                      />
                      <Bar dataKey="Fixable" stackId="a" fill="#10b981" maxBarSize={22} />
                      <Bar dataKey="No Fix"  stackId="a" fill="#f87171" radius={[0, 4, 4, 0]} maxBarSize={22} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Top images - severity breakdown */}
              <div className="rounded-2xl bg-white shadow-sm ring-1 ring-gray-100 overflow-hidden">
                <div className="border-b border-gray-100 px-6 py-4">
                  <h2 className="text-sm font-bold text-gray-900">Image Vulnerability Summary</h2>
                  <p className="mt-0.5 text-xs text-gray-400">Total vulnerabilities per container image with fix availability</p>
                </div>
                <div className="p-5">
                  <div className="overflow-x-auto rounded-xl border border-gray-100">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="bg-gray-50 border-b border-gray-100">
                          <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Image</th>
                          <th className="px-3 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px] text-right">Total</th>
                          <th className="px-3 py-3 font-semibold text-emerald-600 uppercase tracking-wider text-[10px] text-right">Fixable</th>
                          <th className="px-3 py-3 font-semibold text-red-500 uppercase tracking-wider text-[10px] text-right">No Fix</th>
                          <th className="px-4 py-3 font-semibold text-gray-500 uppercase tracking-wider text-[10px]">Fix Rate</th>
                        </tr>
                      </thead>
                      <tbody>
                        {imageData.slice(0, 12).map((d, i) => {
                          const imgTotal = d.fixable_count + d.no_fix_count;
                          const imgFixPct = imgTotal > 0 ? Math.round((d.fixable_count / imgTotal) * 100) : 0;
                          const barColor = imgFixPct >= 60 ? '#10b981' : imgFixPct >= 30 ? '#f59e0b' : '#ef4444';
                          return (
                            <tr key={d.image}
                              className={`border-b border-gray-50 transition-colors hover:bg-indigo-50/30 ${i % 2 === 0 ? 'bg-white' : 'bg-gray-50/30'}`}>
                              <td className="px-4 py-3 max-w-[160px]">
                                <span className="font-semibold text-gray-900 truncate block" title={d.image}>
                                  {d.image?.split('/').pop() ?? d.image}
                                </span>
                              </td>
                              <td className="px-3 py-3 text-right">
                                <span className="font-bold text-gray-800" style={{ fontVariantNumeric: 'tabular-nums' }}>{d.count.toLocaleString()}</span>
                              </td>
                              <td className="px-3 py-3 text-right">
                                <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-[11px] font-bold text-emerald-700">
                                  {d.fixable_count.toLocaleString()}
                                </span>
                              </td>
                              <td className="px-3 py-3 text-right">
                                <span className="inline-flex items-center rounded-full bg-red-50 px-2 py-0.5 text-[11px] font-bold text-red-600">
                                  {d.no_fix_count.toLocaleString()}
                                </span>
                              </td>
                              <td className="px-4 py-3">
                                <div className="flex items-center gap-2">
                                  <div className="flex h-2 w-16 overflow-hidden rounded-full bg-gray-100">
                                    <div className="h-full rounded-full transition-all duration-500" style={{ width: `${imgFixPct}%`, background: barColor }} />
                                  </div>
                                  <span className="text-[11px] font-semibold tabular-nums" style={{ color: barColor }}>{imgFixPct}%</span>
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          )}

        </>

      /* ── Secrets dashboard ── */
      ) : scanTypeFilter === 'Secrets' ? (
        <>
          {/* Stat cards */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {loading ? (
              <>{[...Array(4)].map((_, i) => <SkeletonCard key={i} />)}</>
            ) : (
              <>
                <StatCard label="Total Secrets" value={summary?.total_findings ?? 0}  accent="#ef4444" icon={Key}           sub="secrets exposed" />
                <StatCard label="Critical"       value={summary?.critical ?? 0}         accent="#dc2626" icon={AlertCircle}  sub="critical severity" />
                <StatCard label="High"           value={summary?.high ?? 0}             accent="#f97316" icon={AlertTriangle} sub="high severity" />
                <StatCard label="Open"           value={summary?.open_findings ?? 0}    accent="#f59e0b" icon={Lock}          sub="not yet resolved" />
              </>
            )}
          </div>

          {/* Category chart + severity donut */}
          {loading ? (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <SkeletonChart /><SkeletonChart />
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <SecretsCategoryChart data={secretsCategories} />
              <FindingsSeverityDonut summary={summary} subtitle="Distribution of secrets by severity" />
            </div>
          )}

          {/* Top images with secrets */}
          {loading ? <SkeletonChart h="h-48" /> : imageData.length > 0 && (
            <div className="rounded-2xl bg-white p-6 shadow-sm ring-1 ring-gray-100">
              <h2 className="text-sm font-semibold text-gray-800">Top Images with Secrets</h2>
              <p className="mb-4 mt-0.5 text-xs text-gray-400">Container images where secrets were detected</p>
              <ResponsiveContainer width="100%" height={Math.min(imageData.length * 34 + 20, 360)}>
                <BarChart
                  data={imageData.slice(0, 12).map(d => ({
                    name: d.image?.split('/').pop() ?? d.image,
                    full: d.image,
                    Secrets: d.count,
                  })).reverse()}
                  layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#f3f4f6" />
                  <XAxis type="number" tick={{ fontSize: 11, fill: '#9ca3af' }} tickLine={false} axisLine={false} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#374151' }} tickLine={false} axisLine={false} width={160} />
                  <Tooltip formatter={(v: number, _: string, p: any) => [v, `Secrets in ${p.payload.full}`]} />
                  <Bar dataKey="Secrets" fill="#ef4444" radius={[0, 4, 4, 0]} maxBarSize={22} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </>

      /* ── SBOM dashboard ── */
      ) : scanTypeFilter === 'SBOM' ? (
        <>
          {/* Stat cards */}
          {loading ? (
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-5">
              {[...Array(5)].map((_, i) => <SkeletonCard key={i} />)}
            </div>
          ) : (
            <SbomStatCards data={sbomLicense} />
          )}

          {/* License donut + Risk classification */}
          {loading ? (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
              <SkeletonChart h="h-72" /><SkeletonChart h="h-72" />
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
              <div className="xl:col-span-2">
                <LicenseDonut data={sbomLicense} />
              </div>
              <div className="xl:col-span-3">
                <LicenseRiskSplit data={sbomLicense} />
              </div>
            </div>
          )}

          {/* Actionable packages table */}
          {loading ? <SkeletonChart h="h-48" /> : (
            <ActionablePackagesTable packages={sbomLicense?.actionable_packages ?? []} />
          )}

        </>

      /* ── K8s dashboard ── */
      ) : scanTypeFilter === 'K8s' ? (
        <K8sDashboard
          summary={summary} toolData={toolData}
          k8sCategories={k8sCategories} k8sResources={k8sResources}
          k8sNamespaces={k8sNamespaces} loading={loading}
          k8sTool={k8sTool} setK8sTool={setK8sTool}
        />

      /* ── Generic fallback for other scan types (SAST, DAST…) ── */
      ) : scanTypeFilter ? (
        <>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            {loading ? (
              <>{[...Array(4)].map((_, i) => <SkeletonCard key={i} />)}</>
            ) : (
              <>
                <StatCard label="Total Findings" value={summary?.total_findings ?? 0}  accent="#6366f1" icon={Shield}        sub="all findings" />
                <StatCard label="Critical"        value={summary?.critical ?? 0}         accent="#dc2626" icon={AlertCircle}  sub="critical severity" />
                <StatCard label="High"            value={summary?.high ?? 0}             accent="#f97316" icon={AlertTriangle} sub="high severity" />
                <StatCard label="Open"            value={summary?.open_findings ?? 0}    accent="#f59e0b" icon={TrendingUp}    sub="not yet resolved" />
              </>
            )}
          </div>
          {loading ? <SkeletonChart /> : (
            <div>
              <div className="mb-4">
                <h2 className="text-sm font-semibold text-gray-800">Severity by Scan Type</h2>
              </div>
              <ScanTypeCards data={scanTypeSev} viewMode="findings" />
            </div>
          )}
        </>

      ) : (
        <div className="flex h-48 items-center justify-center text-sm text-gray-400">Loading…</div>
      )}
    </div>
  );
}
