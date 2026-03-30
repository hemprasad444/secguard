import { useState, useEffect } from 'react';
import { X, Download, Copy, CheckCircle, RefreshCw, AlertTriangle, Wrench } from 'lucide-react';
import { generateFix } from '../api/findings';
import SeverityBadge from './common/SeverityBadge';

interface Finding {
  id: string;
  title: string;
  severity: string;
  tool_name: string;
  raw_data?: Record<string, any>;
}

interface PatchData {
  control_id: string;
  title: string;
  patch_type: string;
  resource_kind: string;
  resource_name: string;
  namespace: string;
  patch_yaml: string;
  kubectl_command: string;
  notes: string | null;
  risk_level: string;
}

export default function PatchPreviewModal({
  finding,
  onClose,
}: {
  finding: Finding;
  onClose: () => void;
}) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [patch, setPatch] = useState<PatchData | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError('');
      try {
        const data = await generateFix(finding.id);
        setPatch(data);
      } catch (e: any) {
        setError(e.response?.data?.detail || 'Failed to generate fix');
      }
      setLoading(false);
    })();
  }, [finding.id]);

  const handleCopy = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!patch) return;
    const blob = new Blob([patch.patch_yaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `fix-${patch.control_id.toLowerCase()}-${patch.resource_name}.yaml`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const rd = finding.raw_data ?? {};
  const riskColors: Record<string, string> = {
    low: 'bg-green-100 text-green-700 border-green-200',
    medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
    high: 'bg-red-100 text-red-700 border-red-200',
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 px-4" onClick={onClose}>
      <div className="w-full max-w-2xl rounded-2xl bg-white shadow-2xl max-h-[85vh] flex flex-col" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between border-b px-6 py-4 shrink-0">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <Wrench className="h-4 w-4 text-purple-600" />
              <h2 className="text-base font-bold text-gray-900">Generated Fix</h2>
            </div>
            <div className="mt-1.5 flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <span className="rounded bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">{rd.controlID ?? rd.ID}</span>
              <span className="text-xs text-gray-500">{rd.k8s_resource_kind}/{rd.k8s_resource_name}</span>
            </div>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 hover:bg-gray-100 shrink-0 ml-2">
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 gap-3">
              <RefreshCw className="h-6 w-6 animate-spin text-purple-500" />
              <p className="text-sm text-gray-400">Generating fix template...</p>
            </div>
          ) : error ? (
            <div className="flex items-start gap-2 rounded-lg bg-amber-50 border border-amber-200 px-4 py-3">
              <AlertTriangle className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-semibold text-amber-800">No Auto-Fix Available</p>
                <p className="text-xs text-amber-700 mt-1">{error}</p>
                <p className="text-xs text-amber-600 mt-2">Use the remediation guidance from the finding to fix this manually.</p>
              </div>
            </div>
          ) : patch ? (
            <>
              {/* Risk level + patch type */}
              <div className="flex items-center gap-2">
                <span className={`rounded-full border px-2.5 py-0.5 text-[10px] font-bold uppercase ${riskColors[patch.risk_level] || riskColors.low}`}>
                  {patch.risk_level} risk
                </span>
                <span className="rounded bg-purple-50 px-2 py-0.5 text-[10px] font-medium text-purple-600">
                  {patch.patch_type.replace(/_/g, ' ')}
                </span>
                {patch.namespace && (
                  <span className="rounded bg-blue-50 px-2 py-0.5 text-[10px] font-medium text-blue-600">
                    ns: {patch.namespace}
                  </span>
                )}
              </div>

              {/* Patch YAML */}
              <div className="rounded-lg border border-gray-200 bg-gray-900 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800">
                  <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">Patch YAML</span>
                  <div className="flex items-center gap-1.5">
                    <button onClick={() => handleCopy(patch.patch_yaml)}
                      className="inline-flex items-center gap-1 rounded px-2 py-1 text-[10px] text-gray-400 hover:bg-gray-700 hover:text-white transition-colors">
                      {copied ? <CheckCircle className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
                      {copied ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                </div>
                <pre className="px-4 py-3 text-xs leading-6 text-green-300 overflow-x-auto max-h-64 overflow-y-auto">
                  {patch.patch_yaml}
                </pre>
              </div>

              {/* kubectl command */}
              <div className="rounded-lg border border-gray-200 bg-gray-50 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-100">
                  <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">kubectl Command</span>
                  <button onClick={() => handleCopy(patch.kubectl_command)}
                    className="inline-flex items-center gap-1 rounded px-2 py-1 text-[10px] text-gray-500 hover:bg-gray-200 transition-colors">
                    <Copy className="h-3 w-3" /> Copy
                  </button>
                </div>
                <pre className="px-4 py-3 text-xs text-gray-700 font-mono overflow-x-auto whitespace-pre-wrap">
                  {patch.kubectl_command}
                </pre>
              </div>

              {/* Notes */}
              {patch.notes && (
                <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3">
                  <p className="text-[10px] font-bold text-amber-700 uppercase tracking-wider mb-1">Important Notes</p>
                  <p className="text-xs text-amber-700 leading-relaxed">{patch.notes}</p>
                </div>
              )}

              {/* Workflow hint */}
              <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3">
                <p className="text-[10px] font-bold text-blue-700 uppercase tracking-wider mb-1">Next Steps</p>
                <ol className="text-xs text-blue-700 leading-relaxed list-decimal list-inside space-y-1">
                  <li>Review the patch YAML above</li>
                  <li>Download and apply it to your cluster</li>
                  <li>Come back and click <strong>"Verify & Close"</strong> to confirm the fix</li>
                </ol>
              </div>
            </>
          ) : null}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 border-t px-6 py-4 shrink-0">
          <button onClick={onClose} className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
            Close
          </button>
          {patch && (
            <button onClick={handleDownload}
              className="inline-flex items-center gap-1.5 rounded-lg bg-purple-600 px-4 py-2 text-sm font-semibold text-white hover:bg-purple-700">
              <Download className="h-3.5 w-3.5" /> Download YAML
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
