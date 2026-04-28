import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, ExternalLink, RefreshCw, ChevronRight, Code,
} from 'lucide-react';
import { getScan, getScanFindings } from '../api/scans';
import FindingCloseModal from '../components/FindingCloseModal';

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
  tool_name: string;
  file_path?: string;
  line_number?: number;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
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

function cleanPath(p: string | undefined): string {
  if (!p) return '';
  return p.replace(/^\/tmp\/sast__[^/]+\//, '').replace(/^\/tmp\/sast_[^/]+\//, '');
}

function ruleShortId(checkId: string): string {
  if (!checkId) return '';
  const parts = checkId.split('.');
  return parts[parts.length - 1] || checkId;
}

export default function SastFindingDetail() {
  const { projectId, scanId, findingId } = useParams<{
    projectId: string; scanId: string; findingId: string;
  }>();
  const navigate = useNavigate();

  const [scan, setScan] = useState<Scan | null>(null);
  const [finding, setFinding] = useState<Finding | null>(null);
  const [siblings, setSiblings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [closingFinding, setClosingFinding] = useState<Finding | null>(null);

  useEffect(() => {
    if (!scanId || !findingId) return;
    (async () => {
      setLoading(true);
      try {
        const s: Scan = await getScan(scanId);
        setScan(s);
        const data = await getScanFindings(scanId, 1, 1000);
        const items: Finding[] = Array.isArray(data) ? data : (data.items ?? data.results ?? []);
        const f = items.find(x => x.id === findingId) ?? null;
        setFinding(f);
        if (f) {
          // Siblings = other findings in the same source file
          const target = cleanPath(f.file_path);
          const peers = items
            .filter(x => x.id !== f.id)
            .filter(x => cleanPath(x.file_path) === target)
            .sort((a, b) => {
              const sd = (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9);
              if (sd !== 0) return sd;
              return (a.line_number ?? 0) - (b.line_number ?? 0);
            });
          setSiblings(peers);
        } else {
          setSiblings([]);
        }
      } catch { /* noop */ }
      setLoading(false);
    })();
  }, [scanId, findingId]);

  if (loading) {
    return (
      <div className="flex h-64 items-center justify-center">
        <RefreshCw className="h-5 w-5 animate-spin text-gray-400" />
      </div>
    );
  }

  if (!scan || !finding) {
    return (
      <div className="space-y-4">
        <button onClick={() => navigate(-1)}
          className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
          <ArrowLeft className="h-3.5 w-3.5" /> Back
        </button>
        <div className="rounded-md border border-dashed border-gray-200 py-14 text-center text-sm text-gray-400">
          Finding not found in this scan.
        </div>
      </div>
    );
  }

  const r = finding.raw_data ?? {};
  const extra = r.extra ?? {};
  const meta = extra.metadata ?? {};
  const checkId = (r.check_id as string) ?? finding.title;
  const ruleId = ruleShortId(checkId);
  const path = cleanPath(finding.file_path);
  const msg = (extra.message as string) || finding.description || '';
  const startLine = r.start?.line ?? finding.line_number ?? null;
  const endLine = r.end?.line ?? null;
  const startCol = r.start?.col ?? null;
  const endCol = r.end?.col ?? null;
  const lineRange =
    startLine != null && endLine != null && startLine !== endLine
      ? `${startLine}–${endLine}`
      : startLine != null
        ? `${startLine}`
        : null;

  const cwe: string[] = Array.isArray(meta.cwe) ? meta.cwe : meta.cwe ? [meta.cwe] : [];
  const owasp: string[] = Array.isArray(meta.owasp) ? meta.owasp : meta.owasp ? [meta.owasp] : [];
  const technology: string[] = Array.isArray(meta.technology) ? meta.technology : [];
  const vulnClass: string[] = Array.isArray(meta.vulnerability_class) ? meta.vulnerability_class : [];
  const subcategory: string[] = Array.isArray(meta.subcategory) ? meta.subcategory : [];
  const references: string[] = Array.isArray(meta.references) ? meta.references : [];
  const ruleSource: string | undefined = meta.source;
  const shortlink: string | undefined = meta.shortlink;

  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const isClosed = closedStatuses.includes(finding.status);

  return (
    <div className="space-y-5">
      {/* Back */}
      <button onClick={() => navigate(`/projects/${projectId}/scans/${scanId}`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to scan
      </button>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <Code className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0">
            <p className="text-[11px] uppercase tracking-wider text-gray-400">SAST · {finding.tool_name}</p>
            <h1 className="mt-0.5 text-base font-semibold text-gray-900 font-mono break-all">{ruleId}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]">
              <span className="inline-flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${sevDot(finding.severity)}`} />
                <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(finding.severity)}`}>{finding.severity}</span>
              </span>
              {meta.confidence && (
                <span className="text-gray-500">
                  <span className="text-gray-400">confidence</span> {String(meta.confidence).toLowerCase()}
                </span>
              )}
              {meta.likelihood && (
                <span className="text-gray-500">
                  <span className="text-gray-400">likelihood</span> {String(meta.likelihood).toLowerCase()}
                </span>
              )}
              {meta.impact && (
                <span className="text-gray-500">
                  <span className="text-gray-400">impact</span> {String(meta.impact).toLowerCase()}
                </span>
              )}
            </div>
          </div>
        </div>
        <button onClick={() => setClosingFinding(finding)}
          className={`rounded-md border px-3 py-1.5 text-xs font-medium transition-colors ${
            isClosed
              ? 'border-gray-200 bg-white text-emerald-700 hover:bg-gray-50'
              : 'border-gray-200 bg-white text-gray-700 hover:border-gray-900 hover:bg-gray-900 hover:text-white'
          }`}>
          {isClosed
            ? (finding.status === 'resolved' ? 'Closed' : finding.status.replace(/_/g, ' '))
            : 'Close finding'}
        </button>
      </div>

      {/* Source */}
      <div className="rounded-md border border-gray-200 bg-white px-4 py-3 space-y-2">
        <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Source</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-[12px]">
          <div className="flex flex-wrap gap-x-2">
            <span className="text-gray-400 shrink-0">File</span>
            <span className="font-mono text-gray-800 break-all">{path || '—'}</span>
          </div>
          {lineRange && (
            <div className="flex flex-wrap gap-x-2">
              <span className="text-gray-400 shrink-0">Lines</span>
              <span className="font-mono tabular-nums text-gray-800">{lineRange}</span>
            </div>
          )}
          {startCol != null && (
            <div className="flex flex-wrap gap-x-2">
              <span className="text-gray-400 shrink-0">Columns</span>
              <span className="font-mono tabular-nums text-gray-700">
                {startCol}{endCol != null && endCol !== startCol ? `–${endCol}` : ''}
              </span>
            </div>
          )}
          <div className="flex flex-wrap gap-x-2">
            <span className="text-gray-400 shrink-0">Rule ID</span>
            <span className="font-mono text-gray-700 break-all">{checkId}</span>
          </div>
        </div>
      </div>

      {/* Message */}
      {msg && (
        <div className="space-y-2">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Message</p>
          <p className="text-[13px] text-gray-700 leading-relaxed whitespace-pre-wrap">{msg}</p>
        </div>
      )}

      {/* Classification badges */}
      {(cwe.length > 0 || owasp.length > 0 || vulnClass.length > 0 || technology.length > 0 || subcategory.length > 0) && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3 space-y-2 text-[12px]">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Classification</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5">
            {cwe.length > 0 && (
              <div className="flex gap-x-2">
                <span className="text-gray-400 shrink-0">CWE</span>
                <span className="text-gray-700">{cwe.join(', ')}</span>
              </div>
            )}
            {owasp.length > 0 && (
              <div className="flex gap-x-2">
                <span className="text-gray-400 shrink-0">OWASP</span>
                <span className="text-gray-700">{owasp.join(' · ')}</span>
              </div>
            )}
            {vulnClass.length > 0 && (
              <div className="flex gap-x-2">
                <span className="text-gray-400 shrink-0">Class</span>
                <span className="text-gray-700">{vulnClass.join(', ')}</span>
              </div>
            )}
            {technology.length > 0 && (
              <div className="flex gap-x-2">
                <span className="text-gray-400 shrink-0">Tech</span>
                <span className="font-mono text-gray-700">{technology.join(', ')}</span>
              </div>
            )}
            {subcategory.length > 0 && (
              <div className="flex gap-x-2">
                <span className="text-gray-400 shrink-0">Category</span>
                <span className="text-gray-700">{subcategory.join(', ')}</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* References */}
      {(ruleSource || shortlink || references.length > 0) && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700 mb-2">References</p>
          <div className="space-y-1">
            {ruleSource && (
              <a href={ruleSource} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[12px] text-gray-800 hover:text-gray-900 hover:underline break-all">
                <ExternalLink className="h-3 w-3 shrink-0" />
                <span className="font-medium">Semgrep rule</span>
                <span className="text-gray-500">— {ruleSource}</span>
              </a>
            )}
            {shortlink && shortlink !== ruleSource && (
              <a href={shortlink} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-[12px] text-gray-600 hover:text-gray-900 hover:underline break-all">
                <ExternalLink className="h-3 w-3 shrink-0" />
                {shortlink}
              </a>
            )}
            {references.filter(rr => rr !== ruleSource && rr !== shortlink).map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-[12px] text-gray-600 hover:text-gray-900 hover:underline break-all">
                <ExternalLink className="h-3 w-3 shrink-0" />
                {ref}
              </a>
            ))}
          </div>
        </div>
      )}

      {/* Closure metadata */}
      {isClosed && (finding.close_reason || finding.justification || finding.closed_at) && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3 space-y-1 text-[12px]">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-emerald-700">Closure</p>
          {finding.close_reason && (
            <div className="flex gap-x-2">
              <span className="text-gray-400 shrink-0">Reason</span>
              <span className="text-gray-700">{finding.close_reason.replace(/_/g, ' ')}</span>
            </div>
          )}
          {finding.justification && (
            <div className="flex gap-x-2">
              <span className="text-gray-400 shrink-0">Justification</span>
              <span className="text-gray-700">{finding.justification}</span>
            </div>
          )}
          {finding.closed_at && (
            <div className="flex gap-x-2">
              <span className="text-gray-400 shrink-0">Closed at</span>
              <span className="text-gray-700">{new Date(finding.closed_at).toLocaleString()}</span>
            </div>
          )}
        </div>
      )}

      {/* Other findings in same file */}
      {siblings.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-gray-900">
            Other findings in this file
            <span className="ml-2 text-gray-400 font-normal tabular-nums">({siblings.length})</span>
          </h3>
          <div className="rounded-md border border-gray-200 bg-white overflow-hidden divide-y divide-gray-100">
            {siblings.map(p => {
              const pCheckId = (p.raw_data?.check_id as string) ?? p.title;
              const pRuleId = ruleShortId(pCheckId);
              const pIsClosed = closedStatuses.includes(p.status);
              return (
                <button key={p.id}
                  onClick={() => navigate(`/projects/${projectId}/scans/${scanId}/sast/${p.id}`)}
                  className={`group flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-gray-50/60 ${pIsClosed ? 'opacity-60' : ''}`}>
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevDot(p.severity)}`} />
                  <span className={`w-16 text-[10px] uppercase tracking-wider font-medium ${sevText(p.severity)}`}>{p.severity}</span>
                  <span className="shrink-0 font-mono text-[11px] text-gray-700 truncate max-w-[260px]" title={pCheckId}>
                    {pRuleId}
                  </span>
                  {p.line_number != null && (
                    <span className="shrink-0 font-mono text-[11px] text-gray-500 tabular-nums">L{p.line_number}</span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-[12px] text-gray-700">
                    {(p.raw_data?.extra?.message as string) || p.description || p.title}
                  </span>
                  <ChevronRight className="h-4 w-4 shrink-0 text-gray-300 transition-all group-hover:translate-x-0.5 group-hover:text-gray-600" />
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Close modal */}
      {closingFinding && (
        <FindingCloseModal
          finding={closingFinding as any}
          onClose={() => setClosingFinding(null)}
          onUpdated={(updated: any) => {
            setFinding(prev => prev ? { ...prev, ...updated } : prev);
          }}
        />
      )}
    </div>
  );
}
