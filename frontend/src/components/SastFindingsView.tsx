import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ChevronRight, Search, ArrowUpDown } from 'lucide-react';

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  file_path?: string;
  line_number?: number;
  description?: string;
  raw_data?: Record<string, any>;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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

// Strip the ephemeral upload prefix Semgrep gives us (`/tmp/sast__abc1234/...`)
function cleanPath(p: string | undefined): string {
  if (!p) return '';
  return p.replace(/^\/tmp\/sast__[^/]+\//, '').replace(/^\/tmp\/sast_[^/]+\//, '');
}

// Last dotted segment of a Semgrep check_id is usually the readable rule name.
function ruleShortId(checkId: string): string {
  if (!checkId) return '';
  const parts = checkId.split('.');
  return parts[parts.length - 1] || checkId;
}

function humanMessage(f: Finding): string {
  return (f.raw_data?.extra?.message as string) || f.description || f.title || '';
}

export default function SastFindingsView({ findings, projectId, scanId }: {
  findings: Finding[];
  projectId?: string;
  scanId?: string;
}) {
  const navigate = useNavigate();
  const canNavigate = !!(projectId && scanId);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [techFilter, setTechFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortBy, setSortBy] = useState<'severity' | 'file' | 'rule'>('severity');

  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const openCount = findings.filter(f => !closedStatuses.includes(f.status)).length;
  const closedCount = findings.length - openCount;

  // Build technology facet
  const techSet = new Set<string>();
  for (const f of findings) {
    const tech = f.raw_data?.extra?.metadata?.technology as string[] | undefined;
    if (Array.isArray(tech)) for (const t of tech) techSet.add(t);
  }

  // Severity counts (across all findings, not just filtered)
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = f.severity as keyof typeof sevCounts;
    if (s in sevCounts) sevCounts[s]++;
  }

  const q = search.trim().toLowerCase();
  const filtered = findings
    .filter(f => {
      if (statusFilter === 'open' && closedStatuses.includes(f.status)) return false;
      if (statusFilter === 'closed' && !closedStatuses.includes(f.status)) return false;
      if (sevFilter !== 'all' && f.severity !== sevFilter) return false;
      if (techFilter !== 'all') {
        const tech = (f.raw_data?.extra?.metadata?.technology as string[] | undefined) ?? [];
        if (!tech.includes(techFilter)) return false;
      }
      if (q) {
        const checkId = (f.raw_data?.check_id as string) ?? '';
        const path = cleanPath(f.file_path);
        const msg = humanMessage(f);
        if (
          !checkId.toLowerCase().includes(q) &&
          !path.toLowerCase().includes(q) &&
          !msg.toLowerCase().includes(q)
        ) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'severity') {
        const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
        if (sd !== 0) return sd;
        return cleanPath(a.file_path).localeCompare(cleanPath(b.file_path));
      }
      if (sortBy === 'file') {
        return cleanPath(a.file_path).localeCompare(cleanPath(b.file_path))
          || (a.line_number ?? 0) - (b.line_number ?? 0);
      }
      if (sortBy === 'rule') {
        return ruleShortId((a.raw_data?.check_id as string) ?? a.title).localeCompare(
          ruleShortId((b.raw_data?.check_id as string) ?? b.title));
      }
      return 0;
    });

  if (findings.length === 0) {
    return <p className="py-12 text-center text-sm text-gray-400">No findings for this scan.</p>;
  }

  return (
    <div className="space-y-4">
      {/* Stats strip */}
      <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-sm">
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{findings.length}</span> findings
        </span>
        <span className="text-gray-500">
          <span className="font-semibold text-gray-900 tabular-nums">{openCount}</span> open
        </span>
        {closedCount > 0 && (
          <span className="text-gray-500">
            <span className="font-semibold text-gray-900 tabular-nums">{closedCount}</span> closed
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

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[240px] max-w-md">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search rule, file, message…"
            className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs text-gray-800 placeholder-gray-400 focus:outline-none focus:border-gray-400" />
        </div>
        <div className="inline-flex rounded-md border border-gray-200 bg-white p-0.5">
          {[
            { k: 'all', label: `All ${findings.length}` },
            { k: 'open', label: `Open ${openCount}` },
            { k: 'closed', label: `Closed ${closedCount}` },
          ].map(s => (
            <button key={s.k} onClick={() => setStatusFilter(s.k)}
              className={`rounded px-2.5 py-1 text-xs font-medium transition-colors ${
                statusFilter === s.k ? 'bg-gray-900 text-white' : 'text-gray-600 hover:text-gray-900'
              }`}>
              {s.label}
            </button>
          ))}
        </div>
        <select value={sevFilter} onChange={e => setSevFilter(e.target.value)}
          className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
          <option value="all">All severities</option>
          {(['critical', 'high', 'medium', 'low', 'info'] as const).map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} ({sevCounts[s]})</option>
          ))}
        </select>
        {techSet.size > 1 && (
          <select value={techFilter} onChange={e => setTechFilter(e.target.value)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="all">All languages</option>
            {[...techSet].sort().map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        )}
        <div className="ml-auto inline-flex items-center gap-1.5">
          <ArrowUpDown className="h-3.5 w-3.5 text-gray-400" />
          <select value={sortBy} onChange={e => setSortBy(e.target.value as any)}
            className="rounded-md border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700 focus:outline-none focus:border-gray-400">
            <option value="severity">Severity</option>
            <option value="file">File</option>
            <option value="rule">Rule</option>
          </select>
        </div>
      </div>

      {/* Findings table */}
      {filtered.length === 0 ? (
        <p className="rounded-md border border-dashed border-gray-200 py-12 text-center text-sm text-gray-400">
          No findings match the selected filters.
        </p>
      ) : (
        <div className="rounded-md border border-gray-200 bg-white overflow-hidden">
          {/* Headers */}
          <div className="hidden md:grid grid-cols-[110px_220px_minmax(0,1.2fr)_minmax(0,1.4fr)_16px] items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-4 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
            <span>Severity</span>
            <span>Rule</span>
            <span>File</span>
            <span>Message</span>
            <span />
          </div>

          {filtered.map(f => {
            const checkId = (f.raw_data?.check_id as string) ?? f.title;
            const ruleId = ruleShortId(checkId);
            const path = cleanPath(f.file_path);
            const msg = humanMessage(f);
            const isClosed = closedStatuses.includes(f.status);

            const rowContent = (
              <>
                {/* Severity */}
                <div className="flex items-center gap-2">
                  <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${sevDot(f.severity)}`} />
                  <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(f.severity)}`}>{f.severity}</span>
                </div>
                {/* Rule short-id */}
                <span className="font-mono text-[12px] text-gray-800 truncate" title={checkId}>
                  {ruleId}
                </span>
                {/* File */}
                <span className="font-mono text-[11px] text-gray-700 truncate" title={path}>
                  {path}
                  {f.line_number != null && (
                    <span className="text-gray-500">:{f.line_number}</span>
                  )}
                </span>
                {/* Message */}
                <span className="text-[12px] text-gray-700 truncate" title={msg}>
                  {msg}
                </span>
                <ChevronRight className={`h-4 w-4 shrink-0 ${canNavigate ? 'text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600' : 'text-gray-200'}`} />
              </>
            );

            const baseClass = `group grid w-full grid-cols-[110px_220px_minmax(0,1.2fr)_minmax(0,1.4fr)_16px] items-center gap-3 border-b border-gray-100 px-4 py-2.5 text-left transition-colors last:border-b-0 ${
              canNavigate ? 'hover:bg-gray-50/60' : ''
            } ${isClosed ? 'opacity-60' : ''}`;

            if (canNavigate) {
              return (
                <button key={f.id}
                  onClick={() => navigate(`/projects/${projectId}/scans/${scanId}/sast/${f.id}`)}
                  className={baseClass}>
                  {rowContent}
                </button>
              );
            }
            return <div key={f.id} className={baseClass}>{rowContent}</div>;
          })}
        </div>
      )}
    </div>
  );
}
