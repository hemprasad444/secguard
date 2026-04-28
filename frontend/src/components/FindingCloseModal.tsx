import { useState, useEffect } from 'react';
import { X, CheckCircle, AlertTriangle, RefreshCw } from 'lucide-react';
import { closeFinding, reopenFinding, verifyK8sFinding } from '../api/findings';
import SeverityBadge from './common/SeverityBadge';

interface Finding {
  id: string;
  title: string;
  severity: string;
  status: string;
  tool_name: string;
  description?: string;
  remediation?: string;
  close_reason?: string | null;
  justification?: string | null;
  closed_at?: string | null;
  raw_data?: Record<string, any>;
}

type CloseReason = 'manual_fix' | 'accepted_risk' | 'false_positive' | 'rescan_verified';

interface CloseOption {
  reason: CloseReason;
  status: 'resolved' | 'accepted' | 'false_positive';
  label: string;
  description: string;
  needsJustification: boolean;
}

function getCloseOptions(f: Finding): CloseOption[] {
  const rd = f.raw_data ?? {};
  const isK8s = rd.k8s_resource_kind || rd.finding_type === 'compliance' || rd.finding_type === 'misconfiguration';
  const isDep = f.tool_name === 'trivy' && !isK8s && !rd.finding_type;
  const isSecret = f.tool_name === 'gitleaks' || rd.finding_type === 'secret';
  const isSbom = rd.license_category || rd.effective_license;

  if (isK8s) {
    return [
      { reason: 'manual_fix', status: 'resolved', label: 'Verify & Close', description: 'Re-scan the cluster to verify this control is now passing -will only close if actually fixed', needsJustification: false },
      { reason: 'accepted_risk', status: 'accepted', label: 'Accept Risk', description: 'Accept this finding as a known risk with justification', needsJustification: true },
      { reason: 'false_positive', status: 'false_positive', label: 'False Positive', description: 'This finding is incorrectly reported', needsJustification: true },
    ];
  }
  if (isDep) {
    const hasFixVersion = rd.FixedVersion || rd.fixed_version;
    return [
      ...(hasFixVersion ? [
        { reason: 'manual_fix' as CloseReason, status: 'resolved' as const, label: 'Fixed (upgraded package)', description: `Upgrade to ${rd.FixedVersion || rd.fixed_version} and rescan to verify`, needsJustification: false },
      ] : []),
      { reason: 'accepted_risk', status: 'accepted', label: 'Accept Risk', description: hasFixVersion ? 'Cannot upgrade now -document the reason' : 'No fix available -document why this risk is acceptable', needsJustification: true },
      { reason: 'false_positive', status: 'false_positive', label: 'False Positive', description: 'This CVE does not affect our usage', needsJustification: true },
    ];
  }
  if (isSecret) {
    return [
      { reason: 'manual_fix', status: 'resolved', label: 'Secret Rotated & Removed', description: 'The secret has been rotated and removed from code', needsJustification: false },
      { reason: 'false_positive', status: 'false_positive', label: 'False Positive', description: 'Not a real secret (test data, example, etc.)', needsJustification: true },
    ];
  }
  if (isSbom) {
    return [
      { reason: 'manual_fix', status: 'resolved', label: 'License Resolved', description: 'Replaced the component or obtained license compliance', needsJustification: false },
      { reason: 'accepted_risk', status: 'accepted', label: 'Accept License Risk', description: 'Usage is compliant -document the reason', needsJustification: true },
    ];
  }
  // Generic (SAST/DAST/other)
  return [
    { reason: 'manual_fix', status: 'resolved', label: 'Fixed', description: 'The issue has been remediated', needsJustification: false },
    { reason: 'accepted_risk', status: 'accepted', label: 'Accept Risk', description: 'Accept with documented justification', needsJustification: true },
    { reason: 'false_positive', status: 'false_positive', label: 'False Positive', description: 'Incorrectly flagged', needsJustification: true },
  ];
}

export default function FindingCloseModal({
  finding,
  onClose,
  onUpdated,
}: {
  finding: Finding;
  onClose: () => void;
  onUpdated: (updated: Finding) => void;
}) {
  const isAlreadyClosed = ['resolved', 'accepted', 'false_positive'].includes(finding.status);
  const [selectedReason, setSelectedReason] = useState<CloseReason | null>(null);
  const [justification, setJustification] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const [verifyMsg, setVerifyMsg] = useState('');
  const [verifyStartedAt, setVerifyStartedAt] = useState<number | null>(null);
  const [elapsedSec, setElapsedSec] = useState(0);

  // Tick elapsed time during verification (no progress signal from backend; UI shows liveness only).
  useEffect(() => {
    if (!verifyStartedAt) return;
    const id = setInterval(() => {
      setElapsedSec(Math.floor((Date.now() - verifyStartedAt) / 1000));
    }, 250);
    return () => clearInterval(id);
  }, [verifyStartedAt]);

  const verifyStage =
    elapsedSec < 4 ? 'Connecting to cluster…'
      : elapsedSec < 18 ? 'Running targeted scan…'
      : elapsedSec < 45 ? 'Analyzing results…'
      : elapsedSec < 90 ? 'Almost there — large clusters take longer…'
      : 'Still working — this may take a few minutes…';

  const isVerifying = !!verifyStartedAt;

  const rd = finding.raw_data ?? {};
  const isK8s = !!(rd.k8s_resource_kind || rd.finding_type === 'compliance' || rd.finding_type === 'misconfiguration');

  const options = getCloseOptions(finding);
  const selected = options.find(o => o.reason === selectedReason);

  const handleClose = async () => {
    if (!selected) return;
    if (selected.needsJustification && !justification.trim()) {
      setError('Justification is required');
      return;
    }
    setSubmitting(true);
    setError('');
    setVerifyMsg('');

    // K8s "Verify & Close" -runs live re-scan
    if (isK8s && selected.reason === 'manual_fix') {
      setVerifyStartedAt(Date.now());
      setElapsedSec(0);
      try {
        const result = await verifyK8sFinding(finding.id);
        if (result.verified) {
          setVerifyMsg(result.message);
          if (result.finding) onUpdated(result.finding);
          setTimeout(onClose, 2000);
        } else {
          setError(result.message);
        }
      } catch (e: any) {
        const detail = e.response?.data?.detail;
        const msg = e.response?.data?.message;
        setError(detail || msg || `Verification scan failed: ${e.message || 'network error or timeout'}`);
      }
      setVerifyStartedAt(null);
      setSubmitting(false);
      return;
    }

    try {
      const updated = await closeFinding(finding.id, {
        status: selected.status,
        close_reason: selected.reason,
        justification: justification.trim() || undefined,
      });
      onUpdated(updated);
      onClose();
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to close finding');
    }
    setSubmitting(false);
  };

  const handleReopen = async () => {
    setSubmitting(true);
    setError('');
    try {
      const updated = await reopenFinding(finding.id);
      onUpdated(updated);
      onClose();
    } catch (e: any) {
      setError(e.response?.data?.detail || 'Failed to reopen finding');
    }
    setSubmitting(false);
  };

  return (
    <div className="fixed inset-0 z-[70] flex items-center justify-center bg-black/50 px-4"
      onClick={isVerifying ? undefined : onClose}>
      <div className="w-full max-w-lg rounded-2xl bg-white shadow-2xl" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between border-b px-6 py-4">
          <div className="flex-1 min-w-0">
            <h2 className="text-base font-bold text-gray-900">
              {isAlreadyClosed ? 'Finding Status' : 'Close Finding'}
            </h2>
            <div className="mt-1.5 flex items-center gap-2 flex-wrap">
              <SeverityBadge severity={finding.severity} />
              <span className="rounded bg-gray-100 px-2 py-0.5 text-[10px] font-medium text-gray-600">{finding.tool_name}</span>
              {rd.controlID && <span className="rounded bg-indigo-50 px-2 py-0.5 text-[10px] font-medium text-indigo-600">{rd.controlID}</span>}
            </div>
            <p className="mt-1.5 text-sm text-gray-700 line-clamp-2">{finding.title}</p>
          </div>
          <button onClick={onClose} className="rounded-lg p-1.5 hover:bg-gray-100 shrink-0 ml-2">
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        <div className="px-6 py-4 space-y-4 max-h-[60vh] overflow-y-auto">
          {/* Verification progress — replaces the form during a K8s verify scan */}
          {isVerifying ? (
            <div className="space-y-3 py-2">
              <div className="flex items-baseline justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">Verifying control</p>
                  <p className="mt-1 text-[13px] font-mono text-gray-800 truncate">
                    {(rd.controlID || rd.ID) ?? finding.title}
                    {rd.k8s_resource_kind && rd.k8s_resource_name && (
                      <span className="text-gray-500"> · {rd.k8s_resource_kind}/{rd.k8s_resource_name}</span>
                    )}
                  </p>
                </div>
                <span className="shrink-0 font-mono text-xs text-gray-500 tabular-nums">{elapsedSec}s</span>
              </div>

              {/* Indeterminate bar — moving segment over a track */}
              <div className="relative h-[3px] w-full overflow-hidden rounded-full bg-gray-100">
                <div
                  className="absolute inset-y-0 -left-1/3 w-1/3 rounded-full bg-gray-900"
                  style={{ animation: 'shimmer 1.4s ease-in-out infinite' }}
                />
                <style>{`
                  @keyframes shimmer {
                    0%   { transform: translateX(0); }
                    100% { transform: translateX(400%); }
                  }
                `}</style>
              </div>

              <p className="text-[12px] text-gray-600">{verifyStage}</p>

              <p className="text-[11px] text-gray-400 leading-relaxed">
                Re-scanning the cluster for this control. The finding will only be closed if the control
                now passes — otherwise you'll see why and can pick another close path.
              </p>
            </div>
          ) : null}

          {/* Already closed -show info */}
          {!isVerifying && isAlreadyClosed ? (
            <div className="space-y-3">
              <div className="rounded-lg border border-green-200 bg-green-50 px-4 py-3">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-600" />
                  <span className="text-sm font-semibold text-green-800 capitalize">{finding.status.replace(/_/g, ' ')}</span>
                </div>
                {finding.close_reason && (
                  <p className="mt-1 text-xs text-green-600">Reason: {finding.close_reason.replace(/_/g, ' ')}</p>
                )}
                {finding.closed_at && (
                  <p className="mt-0.5 text-xs text-green-500">Closed: {new Date(finding.closed_at).toLocaleString()}</p>
                )}
              </div>
              {finding.justification && (
                <div className="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1">Justification</p>
                  <p className="text-sm text-gray-700">{finding.justification}</p>
                </div>
              )}
              {finding.remediation && (
                <div className="rounded-lg border border-blue-200 bg-blue-50 px-4 py-3">
                  <p className="text-xs font-semibold text-blue-500 uppercase tracking-wider mb-1">Remediation</p>
                  <p className="text-sm text-blue-700">{finding.remediation}</p>
                </div>
              )}
            </div>
          ) : !isVerifying ? (
            <>
              {/* Close reason selection */}
              <div className="space-y-2">
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wider">Select Close Reason</p>
                {options.map(opt => (
                  <label key={opt.reason}
                    className={`flex items-start gap-3 rounded-lg border p-3 cursor-pointer transition-colors ${
                      selectedReason === opt.reason
                        ? 'border-green-300 bg-green-50'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}>
                    <input type="radio" name="close_reason" value={opt.reason}
                      checked={selectedReason === opt.reason}
                      onChange={() => { setSelectedReason(opt.reason); setError(''); }}
                      className="mt-0.5 accent-green-600" />
                    <div>
                      <p className="text-sm font-semibold text-gray-800">{opt.label}</p>
                      <p className="text-xs text-gray-500 mt-0.5">{opt.description}</p>
                    </div>
                  </label>
                ))}
              </div>

              {/* Justification textarea */}
              {selected?.needsJustification && (
                <div>
                  <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                    Justification <span className="text-red-500">*</span>
                  </label>
                  <textarea
                    value={justification}
                    onChange={e => { setJustification(e.target.value); setError(''); }}
                    placeholder="Explain why this finding is being closed..."
                    rows={3}
                    className="w-full rounded-lg border border-gray-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-green-400 resize-none"
                  />
                </div>
              )}

            </>
          ) : null}

          {verifyMsg && (
            <div className="flex items-center gap-2 rounded-lg bg-green-50 border border-green-200 px-3 py-2">
              <CheckCircle className="h-3.5 w-3.5 text-green-500 shrink-0" />
              <p className="text-xs text-green-700">{verifyMsg}</p>
            </div>
          )}

          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-red-50 border border-red-200 px-3 py-2">
              <AlertTriangle className="h-3.5 w-3.5 text-red-500 shrink-0" />
              <p className="text-xs text-red-700">{error}</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex justify-end gap-3 border-t px-6 py-4">
          <button onClick={onClose} className="rounded-lg border border-gray-200 px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-50">
            Cancel
          </button>
          {isAlreadyClosed ? (
            <button onClick={handleReopen} disabled={submitting}
              className="inline-flex items-center gap-1.5 rounded-lg bg-amber-600 px-4 py-2 text-sm font-semibold text-white hover:bg-amber-700 disabled:opacity-50">
              {submitting ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
              Reopen Finding
            </button>
          ) : (
            <button onClick={handleClose} disabled={submitting || !selectedReason || !!verifyMsg}
              className="inline-flex items-center gap-1.5 rounded-lg bg-green-600 px-4 py-2 text-sm font-semibold text-white hover:bg-green-700 disabled:opacity-50">
              {submitting ? <><RefreshCw className="h-3.5 w-3.5 animate-spin" /> {isK8s && selectedReason === 'manual_fix' ? 'Scanning cluster…' : 'Closing…'}</> : <><CheckCircle className="h-3.5 w-3.5" /> {isK8s && selectedReason === 'manual_fix' ? 'Verify & Close' : 'Close Finding'}</>}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
