import { useEffect, useState } from 'react';
import { X, RefreshCw, Search, AlertTriangle, CheckCircle } from 'lucide-react';
import {
  listSonarqubeProjects,
  importSonarqubeProjects,
  type SonarqubeProjectListItem,
} from '../api/organizations';

export default function SonarqubeImportModal({ onClose, onImported }: {
  onClose: () => void;
  onImported: () => void;
}) {
  const [page, setPage] = useState(1);
  const [pageSize] = useState(100);
  const [q, setQ] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [items, setItems] = useState<SonarqubeProjectListItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [importing, setImporting] = useState(false);
  const [result, setResult] = useState<{ created: number; skipped: number; failed: number } | null>(null);

  const load = async () => {
    setLoading(true); setError('');
    try {
      const r = await listSonarqubeProjects({ page, page_size: pageSize, q: q || undefined });
      setItems(r.items);
      setTotal(r.total);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Failed to load SonarQube projects.');
      setItems([]); setTotal(0);
    }
    setLoading(false);
  };

  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [page, q]);

  const toggle = (key: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };
  const toggleAllVisible = () => {
    setSelected(prev => {
      const next = new Set(prev);
      const allSelected = items.every(i => next.has(i.key));
      if (allSelected) {
        items.forEach(i => next.delete(i.key));
      } else {
        items.forEach(i => next.add(i.key));
      }
      return next;
    });
  };

  const submit = async () => {
    if (selected.size === 0) return;
    setImporting(true); setError('');
    try {
      const payload = items
        .filter(i => selected.has(i.key))
        .map(i => ({ key: i.key, name: i.name }));
      // Include items selected on prior pages too — keep their key with key as fallback name.
      const visibleKeys = new Set(items.map(i => i.key));
      for (const k of selected) {
        if (!visibleKeys.has(k)) payload.push({ key: k, name: k });
      }
      const r = await importSonarqubeProjects({
        projects: payload,
        sync_immediately: true,
      });
      setResult({ created: r.created.length, skipped: r.skipped.length, failed: r.failed.length });
      if (r.created.length > 0) onImported();
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Import failed.');
    }
    setImporting(false);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const allVisibleSelected = items.length > 0 && items.every(i => selected.has(i.key));

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div className="w-full max-w-3xl rounded-md bg-white shadow-2xl flex flex-col max-h-[85vh]" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between border-b border-gray-100 px-5 py-4">
          <div>
            <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Import from SonarQube</p>
            <p className="mt-0.5 text-[12px] text-gray-500">
              Pick the SonarQube projects to track in OpenSentinel. Each becomes a new OpenSentinel project and is queued for an initial sync.
            </p>
          </div>
          <button onClick={onClose} className="rounded p-1 text-gray-400 hover:bg-gray-100">
            <X className="h-4 w-4" />
          </button>
        </div>

        {result ? (
          /* Result view */
          <div className="px-5 py-6 space-y-3 text-sm">
            <div className="inline-flex items-center gap-2 text-emerald-700">
              <CheckCircle className="h-4 w-4" />
              <span className="font-medium">Import complete</span>
            </div>
            <ul className="text-[13px] text-gray-700 space-y-1">
              <li><span className="tabular-nums font-semibold">{result.created}</span> project{result.created !== 1 ? 's' : ''} created and queued for sync</li>
              {result.skipped > 0 && (
                <li><span className="tabular-nums">{result.skipped}</span> skipped (already linked)</li>
              )}
              {result.failed > 0 && (
                <li className="text-red-700"><span className="tabular-nums">{result.failed}</span> failed</li>
              )}
            </ul>
            <p className="text-[11px] text-gray-400">
              The first sync runs in the background — findings will appear on each project's SAST card within a minute or two.
            </p>
            <div className="pt-2">
              <button onClick={onClose}
                className="rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black">
                Done
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Toolbar */}
            <div className="flex flex-wrap items-center gap-2 border-b border-gray-100 px-5 py-3">
              <form onSubmit={(e) => { e.preventDefault(); setPage(1); setQ(searchInput.trim()); }} className="relative flex-1 min-w-[220px] max-w-md">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-400" />
                <input type="text" value={searchInput} onChange={e => setSearchInput(e.target.value)}
                  placeholder="Filter SonarQube projects…"
                  className="w-full rounded-md border border-gray-200 bg-white pl-8 pr-2 py-1.5 text-xs focus:outline-none focus:border-gray-400" />
              </form>
              <span className="text-[11px] text-gray-500 tabular-nums">
                {total.toLocaleString()} total · {selected.size} selected
              </span>
              <div className="ml-auto inline-flex items-center gap-1">
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1 || loading}
                  className="rounded-md border border-gray-200 px-2 py-1 text-xs disabled:opacity-40 hover:bg-gray-50">‹</button>
                <span className="text-[11px] text-gray-500 tabular-nums">{page} / {totalPages}</span>
                <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page >= totalPages || loading}
                  className="rounded-md border border-gray-200 px-2 py-1 text-xs disabled:opacity-40 hover:bg-gray-50">›</button>
              </div>
            </div>

            {/* List */}
            <div className="flex-1 overflow-y-auto">
              {loading ? (
                <div className="flex items-center justify-center py-16 text-sm text-gray-400">
                  <RefreshCw className="h-4 w-4 animate-spin mr-2" /> Loading projects…
                </div>
              ) : error ? (
                <div className="flex items-start gap-2 m-5 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-[12px] text-red-700">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              ) : items.length === 0 ? (
                <p className="py-16 text-center text-sm text-gray-400">No projects found.</p>
              ) : (
                <>
                  <div className="grid grid-cols-[24px_minmax(0,1.2fr)_minmax(0,1fr)_140px] items-center gap-3 border-b border-gray-100 bg-gray-50/60 px-5 py-2 text-[10px] font-medium uppercase tracking-wider text-gray-400">
                    <input type="checkbox" checked={allVisibleSelected} onChange={toggleAllVisible}
                      className="h-3 w-3 rounded border-gray-300 text-gray-900 focus:ring-0" />
                    <span>Name</span>
                    <span>Key</span>
                    <span className="text-right">Last analysis</span>
                  </div>
                  {items.map(it => {
                    const checked = selected.has(it.key);
                    return (
                      <label key={it.key}
                        className={`grid grid-cols-[24px_minmax(0,1.2fr)_minmax(0,1fr)_140px] items-center gap-3 px-5 py-2 text-sm cursor-pointer border-b border-gray-100 last:border-b-0 ${
                          checked ? 'bg-gray-50' : 'hover:bg-gray-50/60'
                        }`}>
                        <input type="checkbox" checked={checked} onChange={() => toggle(it.key)}
                          className="h-3 w-3 rounded border-gray-300 text-gray-900 focus:ring-0" />
                        <span className="text-[13px] text-gray-900 truncate">{it.name}</span>
                        <span className="font-mono text-[11px] text-gray-600 truncate">{it.key}</span>
                        <span className="text-right text-[11px] text-gray-500 tabular-nums">
                          {it.last_analysis_date ? new Date(it.last_analysis_date).toLocaleDateString() : '—'}
                        </span>
                      </label>
                    );
                  })}
                </>
              )}
            </div>

            {/* Footer */}
            <div className="flex items-center justify-between gap-3 border-t border-gray-100 px-5 py-3">
              <button onClick={() => setSelected(new Set())} disabled={selected.size === 0 || importing}
                className="text-[11px] text-gray-500 hover:text-gray-900 disabled:opacity-40">
                Clear selection
              </button>
              <div className="flex items-center gap-2">
                <button onClick={onClose} disabled={importing}
                  className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50 disabled:opacity-50">
                  Cancel
                </button>
                <button onClick={submit} disabled={selected.size === 0 || importing}
                  className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black disabled:opacity-50">
                  {importing ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
                  Import {selected.size || ''} project{selected.size !== 1 ? 's' : ''}
                </button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
