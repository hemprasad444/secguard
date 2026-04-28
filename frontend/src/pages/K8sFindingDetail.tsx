import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, ExternalLink, RefreshCw, ChevronRight,
  Shield, Lock, FileText, Globe, Server, Box, Layers,
} from 'lucide-react';
import { getScan, getScanFindings } from '../api/scans';
import FindingCloseModal from '../components/FindingCloseModal';

interface Scan {
  id: string;
  tool_name: string;
  status: string;
  config_json?: Record<string, any> | null;
}
interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  tool_name: string;
  description?: string;
  remediation?: string;
  raw_data?: Record<string, any>;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
}

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const KIND_ICONS: Record<string, typeof Box> = {
  Deployment: Layers, StatefulSet: Layers, DaemonSet: Layers, ReplicaSet: Layers,
  Pod: Box, ConfigMap: FileText, ClusterRole: Shield, Role: Shield,
  ServiceAccount: Lock, Namespace: Globe, Node: Server,
};

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

export default function K8sFindingDetail() {
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
          const r = f.raw_data ?? {};
          const peers = items
            .filter(x => x.id !== f.id)
            .filter(x => {
              const rr = x.raw_data ?? {};
              return rr.k8s_resource_kind === r.k8s_resource_kind
                && rr.k8s_resource_name === r.k8s_resource_name
                && (rr.k8s_namespace ?? '') === (r.k8s_namespace ?? '');
            })
            .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
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
  const kind = r.k8s_resource_kind ?? 'Unknown';
  const name = r.k8s_resource_name ?? finding.title;
  const namespace = r.k8s_namespace ?? '';
  const controlId = r.controlID ?? r.ID ?? '';
  const category = r.category ?? r.Type ?? '';
  const message = r.Message ?? '';
  const resolution = finding.remediation ?? r.Resolution ?? '';
  const refUrl: string | undefined = r.PrimaryURL;
  const references: string[] = Array.isArray(r.References) ? r.References : [];
  const causeLines = r.CauseMetadata?.Code?.Lines as Array<{ Number: number; Content: string; IsCause: boolean }> | undefined;
  const causeStartLine = r.CauseMetadata?.StartLine as number | undefined;
  const causeEndLine = r.CauseMetadata?.EndLine as number | undefined;
  const causeProvider = r.CauseMetadata?.Provider as string | undefined;
  const causeService = r.CauseMetadata?.Service as string | undefined;
  const failedPaths: string[] | undefined = r.failedPaths;
  const fixPaths: Array<{ path: string; value: string }> | undefined = r.fixPaths;
  const closedStatuses = ['resolved', 'accepted', 'false_positive'];
  const isClosed = closedStatuses.includes(finding.status);
  const KindIcon = KIND_ICONS[kind] ?? Box;

  // Build kubectl retrieval hint — Trivy/Kubescape both scan the live cluster,
  // so the canonical "source" is the cluster resource itself.
  const kubectlKind = kind.toLowerCase();
  const kubectlNs = namespace ? ` -n ${namespace}` : '';
  const kubectlCmd = `kubectl get ${kubectlKind} ${name}${kubectlNs} -o yaml`;
  const lineRange =
    causeStartLine != null && causeEndLine != null && causeStartLine !== causeEndLine
      ? `${causeStartLine}–${causeEndLine}`
      : causeStartLine != null
        ? `${causeStartLine}`
        : causeLines && causeLines.length > 0
          ? `${causeLines[0]?.Number}–${causeLines[causeLines.length - 1]?.Number}`
          : null;

  return (
    <div className="space-y-5">
      {/* Back */}
      <button onClick={() => navigate(`/projects/${projectId}/k8s/${scanId}`)}
        className="inline-flex items-center gap-1 text-sm text-gray-500 hover:text-gray-800 transition-colors">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to scan
      </button>

      {/* Header — resource identity + finding title */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-gray-200 pb-5">
        <div className="flex items-start gap-3 min-w-0">
          <KindIcon className="h-5 w-5 shrink-0 text-gray-500 mt-0.5" strokeWidth={1.75} />
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
              <span className="text-[10px] uppercase tracking-wider text-gray-400">{kind}</span>
              {namespace && (
                <span className="font-mono text-[11px] text-gray-500">ns: {namespace}</span>
              )}
            </div>
            <h1 className="mt-0.5 text-base font-semibold text-gray-900 font-mono break-all">{name}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12px]">
              <span className="inline-flex items-center gap-1.5">
                <span className={`h-1.5 w-1.5 rounded-full ${sevDot(finding.severity)}`} />
                <span className={`text-[11px] uppercase tracking-wider font-medium ${sevText(finding.severity)}`}>{finding.severity}</span>
              </span>
              {controlId && (
                <span className="font-mono text-gray-700">{controlId}</span>
              )}
              {category && (
                <span className="text-gray-500">{category}</span>
              )}
              <span className="text-gray-400">·</span>
              <span className="font-mono text-[11px] text-gray-500">{scan.tool_name}</span>
            </div>
          </div>
        </div>
        <button
          onClick={() => setClosingFinding(finding)}
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

      {/* Source — points at the live cluster resource */}
      <div className="rounded-md border border-gray-200 bg-white px-4 py-3 space-y-2">
        <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Source</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-[12px]">
          <div className="flex flex-wrap gap-x-2">
            <span className="text-gray-400 shrink-0">Resource</span>
            <span className="font-mono text-gray-800 break-all">
              {kind}/{name}
              {namespace && <span className="text-gray-500"> · ns: {namespace}</span>}
            </span>
          </div>
          {lineRange && (
            <div className="flex flex-wrap gap-x-2">
              <span className="text-gray-400 shrink-0">Lines</span>
              <span className="font-mono tabular-nums text-gray-800">{lineRange}</span>
            </div>
          )}
          {causeProvider && (
            <div className="flex flex-wrap gap-x-2">
              <span className="text-gray-400 shrink-0">Provider</span>
              <span className="text-gray-700">{causeProvider}</span>
            </div>
          )}
          {causeService && (
            <div className="flex flex-wrap gap-x-2">
              <span className="text-gray-400 shrink-0">Service</span>
              <span className="text-gray-700">{causeService}</span>
            </div>
          )}
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-wider text-gray-400 mb-1">Retrieve manifest</p>
          <code className="block font-mono text-[11px] text-gray-700 bg-gray-50 border border-gray-200 rounded px-2.5 py-1.5 break-all">
            {kubectlCmd}
          </code>
        </div>
      </div>

      {/* Title + description */}
      <div className="space-y-3">
        <h2 className="text-[15px] font-semibold text-gray-900 leading-snug">{finding.title}</h2>
        {finding.description && (
          <p className="text-[13px] text-gray-700 leading-relaxed whitespace-pre-wrap">{finding.description}</p>
        )}
      </div>

      {/* Issue detail */}
      {message && message !== finding.description && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Issue detail</p>
          <p className="mt-1.5 text-[13px] text-gray-700 leading-relaxed whitespace-pre-wrap">{message}</p>
        </div>
      )}

      {/* Affected configuration code (Trivy) */}
      {causeLines && causeLines.length > 0 && (
        <div className="rounded-md border border-gray-200 bg-gray-900 overflow-hidden">
          <div className="flex items-center justify-between border-b border-gray-800 px-3 py-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold text-gray-200">Affected configuration</span>
            <span className="text-[10px] text-gray-500 tabular-nums">
              Lines {causeLines[0]?.Number}–{causeLines[causeLines.length - 1]?.Number}
            </span>
          </div>
          <pre className="px-3 py-2 text-[11px] leading-5 overflow-x-auto">
            {causeLines.filter(l => l.Content !== undefined).map((l, i) => (
              <div key={i} className={`flex ${l.IsCause ? 'bg-red-900/30 -mx-3 px-3' : ''}`}>
                <span className="w-10 shrink-0 text-right text-gray-500 select-none pr-3 tabular-nums">{l.Number}</span>
                <span className={l.IsCause ? 'text-red-300' : 'text-gray-400'}>{l.Content}</span>
              </div>
            ))}
          </pre>
        </div>
      )}

      {/* Failed/fix paths (Kubescape) */}
      {!causeLines && ((failedPaths?.length ?? 0) > 0 || (fixPaths?.length ?? 0) > 0) && (
        <div className="rounded-md border border-gray-200 bg-gray-900 overflow-hidden">
          <div className="border-b border-gray-800 px-3 py-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold text-gray-200">Affected paths</span>
          </div>
          <div className="px-3 py-2 space-y-2 text-[11px]">
            {failedPaths && failedPaths.length > 0 && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-red-400">Failed</span>
                {failedPaths.map((p, i) => (
                  <div key={i} className="mt-0.5 font-mono text-red-300 break-all">{p}</div>
                ))}
              </div>
            )}
            {fixPaths && fixPaths.length > 0 && (
              <div>
                <span className="text-[10px] uppercase tracking-wider text-emerald-400">Fix</span>
                {fixPaths.map((fix, i) => (
                  <div key={i} className="mt-0.5 font-mono break-all">
                    <span className="text-emerald-300">{fix.path}</span>
                    {fix.value && <span className="text-gray-500"> = </span>}
                    {fix.value && <span className="text-emerald-200">{fix.value}</span>}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Remediation */}
      {resolution && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-emerald-700">Remediation</p>
          <p className="mt-1.5 text-[13px] text-gray-700 leading-relaxed whitespace-pre-wrap">{resolution}</p>
        </div>
      )}

      {/* References */}
      {(refUrl || references.length > 0) && (
        <div className="rounded-md border border-gray-200 bg-white px-4 py-3">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700 mb-2">References</p>
          <div className="space-y-1">
            {refUrl && (
              <a href={refUrl} target="_blank" rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-[12px] text-gray-800 hover:text-gray-900 hover:underline break-all">
                <ExternalLink className="h-3 w-3 shrink-0" />
                <span className="font-medium">{refUrl}</span>
                <span className="text-[10px] text-gray-400">primary</span>
              </a>
            )}
            {references.filter(rr => rr !== refUrl).map((ref, i) => (
              <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1 text-[12px] text-gray-600 hover:text-gray-900 hover:underline break-all">
                <ExternalLink className="h-3 w-3 shrink-0" />
                <span className="break-all">{ref}</span>
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

      {/* Other findings on this resource */}
      {siblings.length > 0 && (
        <div>
          <h3 className="mb-2 text-sm font-semibold text-gray-900">
            Other findings on this resource
            <span className="ml-2 text-gray-400 font-normal tabular-nums">({siblings.length})</span>
          </h3>
          <div className="rounded-md border border-gray-200 bg-white overflow-hidden divide-y divide-gray-100">
            {siblings.map(p => {
              const pr = p.raw_data ?? {};
              const pcid = pr.controlID ?? pr.ID ?? '';
              const pIsClosed = closedStatuses.includes(p.status);
              return (
                <button
                  key={p.id}
                  onClick={() => navigate(`/projects/${projectId}/k8s/${scanId}/findings/${p.id}`)}
                  className={`group flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-gray-50/60 ${pIsClosed ? 'opacity-60' : ''}`}
                >
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevDot(p.severity)}`} />
                  <span className={`w-16 text-[10px] uppercase tracking-wider font-medium ${sevText(p.severity)}`}>{p.severity}</span>
                  {pcid && (
                    <span className="shrink-0 font-mono text-[11px] text-gray-700">{pcid}</span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-[13px] text-gray-800">{p.title}</span>
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
