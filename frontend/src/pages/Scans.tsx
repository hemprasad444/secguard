import { useEffect, useRef, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Lock, FileText, Code, Globe, Server,
  Play, RefreshCw, X, FolderOpen, Upload, CheckCircle, AlertCircle,
} from 'lucide-react';
import { getScans, triggerScan, triggerImageUploadScan, triggerCodeUploadScan } from '../api/scans';
import { getProjects, getKubeconfigStatus, uploadKubeconfig } from '../api/projects';
import { useAuthStore } from '../stores/authStore';
import StatusBadge from '../components/common/StatusBadge';

/* ------------------------------------------------------------------ */
/* Types                                                                 */
/* ------------------------------------------------------------------ */
interface Project { id: string; name: string; repo_url?: string; }

interface Scan {
  id: string;
  project_id: string;
  tool_name: string;
  scan_type: string;
  status: string;
  findings_count: number;
  started_at: string | null;
  completed_at: string | null;
  error_message?: string | null;
  created_at: string;
  config_json?: Record<string, string>;
}


/* ------------------------------------------------------------------ */
/* Scan category definitions  (no tool names exposed to user)           */
/* ------------------------------------------------------------------ */
const CATEGORIES = [
  {
    key: 'dependency',
    label: 'Dependency Scan',
    icon: Shield,
    color: 'blue',
    tool: 'trivy',
    description: 'Scan dependencies and container images for known CVEs and vulnerabilities.',
    targetTypes: ['repo', 'image', 'image_upload', 'image_bulk'],
    showCredentials: true,
  },
  {
    key: 'secrets',
    label: 'Secret Detection',
    icon: Lock,
    color: 'red',
    tool: 'trivy',
    description: 'Find hardcoded secrets, tokens, and credentials in source code or images.',
    targetTypes: ['repo', 'image', 'image_bulk'],
    showCredentials: true,
  },
  {
    key: 'sbom',
    label: 'SBOM Generation',
    icon: FileText,
    color: 'purple',
    tool: 'trivy',
    description: 'Generate a Software Bill of Materials (CycloneDX) for an image or repository.',
    targetTypes: ['repo', 'image', 'image_upload', 'image_bulk'],
    showCredentials: true,
  },
  {
    key: 'sast',
    label: 'SAST',
    icon: Code,
    color: 'yellow',
    tool: 'semgrep',
    description: 'Static Application Security Testing - find code-level vulnerabilities.',
    targetTypes: ['repo', 'code_upload'],
    showCredentials: false,
  },
  {
    key: 'dast',
    label: 'DAST',
    icon: Globe,
    color: 'orange',
    tool: 'zap',
    description: 'Dynamic Application Security Testing -scan a running web application.',
    targetTypes: ['url'],
    showCredentials: false,
  },
  {
    key: 'k8s',
    label: 'K8s Security',
    icon: Server,
    color: 'green',
    tool: 'kubescape',
    description: 'Scan a live K8s cluster for misconfigurations, vulnerabilities, and compliance.',
    targetTypes: ['cluster'],
    showCredentials: false,
  },
] as const;

type CategoryKey = typeof CATEGORIES[number]['key'];

const COLOR_CLASSES: Record<string, { bg: string; icon: string; border: string; badge: string }> = {
  blue:   { bg: 'bg-blue-50',   icon: 'text-blue-600',   border: 'border-blue-200',   badge: 'bg-blue-100 text-blue-700' },
  red:    { bg: 'bg-red-50',    icon: 'text-red-600',    border: 'border-red-200',    badge: 'bg-red-100 text-red-700' },
  purple: { bg: 'bg-purple-50', icon: 'text-purple-600', border: 'border-purple-200', badge: 'bg-purple-100 text-purple-700' },
  yellow: { bg: 'bg-yellow-50', icon: 'text-yellow-600', border: 'border-yellow-200', badge: 'bg-yellow-100 text-yellow-700' },
  orange: { bg: 'bg-orange-50', icon: 'text-orange-600', border: 'border-orange-200', badge: 'bg-orange-100 text-orange-700' },
  green:  { bg: 'bg-green-50',  icon: 'text-green-600',  border: 'border-green-200',  badge: 'bg-green-100 text-green-700' },
};

function scanCategory(scan: Scan): CategoryKey {
  if (scan.tool_name === 'trivy') {
    const sub = scan.config_json?.scan_subtype;
    if (sub === 'sbom') return 'sbom';
    if (sub === 'secrets') return 'secrets';
    if (sub === 'k8s') return 'k8s';
    return 'dependency';
  }
  if (scan.tool_name === 'semgrep') return 'sast';
  if (scan.tool_name === 'zap') return 'dast';
  if (scan.tool_name === 'kubescape') return 'k8s';
  return 'dependency';
}

/* ------------------------------------------------------------------ */
/* Trigger Scan Modal                                                     */
/* ------------------------------------------------------------------ */
function TriggerModal({ category, onClose, onSuccess }: {
  category: typeof CATEGORIES[number];
  onClose: () => void;
  onSuccess: (scan: Scan) => void;
}) {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [project, setProject] = useState('');
  const [targetType, setTargetType] = useState<string>(category.targetTypes[0]);
  const [target, setTarget] = useState('');
  const [bulkText, setBulkText] = useState('');
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number } | null>(null);
  const [regUser, setRegUser] = useState('');
  const [regPass, setRegPass] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  // K8s-specific state
  const [k8sTool, setK8sTool] = useState<'kubescape' | 'trivy' | 'both'>('both');
  const [k8sNamespace, setK8sNamespace] = useState('');
  const [kubeconfigStatus, setKubeconfigStatus] = useState<{ configured: boolean; clusters: number } | null>(null);
  const [kubeconfigUploading, setKubeconfigUploading] = useState(false);
  const kubeconfigRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    getProjects().then(res => {
      setProjects(Array.isArray(res) ? res : (res.items ?? res.results ?? []));
    }).catch(() => {}).finally(() => setLoadingProjects(false));
  }, []);

  // Check kubeconfig status when project changes (K8s scans only)
  useEffect(() => {
    if (category.key !== 'k8s' || !project) { setKubeconfigStatus(null); return; }
    getKubeconfigStatus(project).then(setKubeconfigStatus).catch(() => setKubeconfigStatus(null));
  }, [project, category.key]);

  const handleKubeconfigUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (!f || !project) return;
    setKubeconfigUploading(true);
    try {
      await uploadKubeconfig(project, f);
      const status = await getKubeconfigStatus(project);
      setKubeconfigStatus(status);
    } catch {
      setError('Failed to upload kubeconfig. Make sure it is a valid YAML file with a "clusters" key.');
    } finally {
      setKubeconfigUploading(false);
      if (kubeconfigRef.current) kubeconfigRef.current.value = '';
    }
  };

  const showTarget = targetType === 'image' || targetType === 'url' || targetType === 'fs';
  const showCreds = category.showCredentials && (targetType === 'image' || targetType === 'image_upload' || targetType === 'image_bulk');
  // Split on newlines, commas, semicolons, or any whitespace (image names can't contain spaces)
  const bulkImages = bulkText.split(/[\n\r,;|\s]+/).map(l => l.trim()).filter(Boolean);

  const handleBulkPaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text');
    // Normalize any separator (comma, semicolon, single/multiple spaces) → one per line
    const normalized = pasted
      .split(/[\n\r,;|\s]+/)
      .map(s => s.trim())
      .filter(Boolean)
      .join('\n');
    const el = e.currentTarget;
    const start = el.selectionStart;
    const end = el.selectionEnd;
    const next = bulkText.slice(0, start) + normalized + bulkText.slice(end);
    setBulkText(next);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!project) { setError('Select a project.'); return; }
    setSubmitting(true);

    // ── Bulk images mode ──────────────────────────────────────────────
    if (targetType === 'image_bulk') {
      if (bulkImages.length === 0) { setError('Enter at least one image name.'); setSubmitting(false); return; }
      setBulkProgress({ done: 0, total: bulkImages.length });
      let lastScan: Scan | null = null;
      let failed = 0;
      for (let i = 0; i < bulkImages.length; i++) {
        try {
          const config: Record<string, string> = { scan_subtype: category.key, scan_type: 'image', target: bulkImages[i] };
          if (regUser) config.registry_username = regUser;
          if (regPass) config.registry_password = regPass;
          lastScan = await triggerScan({ project_id: project, tool_name: category.tool, config });
        } catch {
          failed++;
        }
        setBulkProgress({ done: i + 1, total: bulkImages.length });
      }
      setSubmitting(false);
      setBulkProgress(null);
      if (lastScan) {
        if (failed > 0) setError(`${failed} of ${bulkImages.length} images failed to queue -the rest are running.`);
        else { onSuccess(lastScan); onClose(); }
      } else {
        setError(`All ${failed} scans failed to trigger. Check the image names and try again.`);
      }
      return;
    }

    // ── K8s scan mode -may trigger two scans ──────────────────────────
    if (category.key === 'k8s') {
      try {
        const tools: string[] = k8sTool === 'both' ? ['kubescape', 'trivy'] : [k8sTool];
        let lastScan: Scan | null = null;
        for (const tool of tools) {
          const config: Record<string, string> = { scan_subtype: 'k8s' };
          if (k8sNamespace) config.namespace = k8sNamespace;
          lastScan = await triggerScan({ project_id: project, tool_name: tool, config });
        }
        if (lastScan) { onSuccess(lastScan); onClose(); }
      } catch {
        setError('Failed to trigger K8s scan. Please try again.');
      } finally {
        setSubmitting(false);
      }
      return;
    }

    // ── Single scan mode ──────────────────────────────────────────────
    try {
      let scan: Scan;
      if (targetType === 'image_upload' || targetType === 'code_upload') {
        if (!file) { setError(`Select a file to upload.`); setSubmitting(false); return; }
        if (targetType === 'code_upload') {
          // Upload file then trigger semgrep scan on it
          scan = await triggerCodeUploadScan(project, file);
        } else {
          scan = await triggerImageUploadScan(project, file, regUser || undefined, regPass || undefined);
        }
      } else {
        const config: Record<string, string> = { scan_subtype: category.key };
        if (category.tool === 'trivy') {
          config.scan_type = targetType === 'image' ? 'image' : targetType === 'fs' ? 'fs' : 'repo';
        }
        if (target) config.target = target;
        if (regUser) config.registry_username = regUser;
        if (regPass) config.registry_password = regPass;
        if (targetType === 'url') config.target_url = target;
        scan = await triggerScan({ project_id: project, tool_name: category.tool, config });
      }
      onSuccess(scan);
      onClose();
    } catch {
      setError('Failed to trigger scan. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  const inputCls = 'mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-primary-500 focus:outline-none focus:ring-1 focus:ring-primary-500';
  const colors = COLOR_CLASSES[category.color];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
      <div className="w-full max-w-lg rounded-2xl bg-white p-6 shadow-2xl">
        <div className="mb-5 flex items-center gap-3">
          <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${colors.bg}`}>
            <category.icon className={`h-5 w-5 ${colors.icon}`} />
          </div>
          <div>
            <h2 className="text-lg font-bold text-gray-900">{category.label}</h2>
            <p className="text-xs text-gray-400">{category.description}</p>
          </div>
          <button onClick={onClose} className="ml-auto rounded-lg p-1.5 hover:bg-gray-100">
            <X className="h-5 w-5 text-gray-400" />
          </button>
        </div>

        {error && <div className="mb-4 rounded-lg bg-red-50 p-3 text-sm text-red-700">{error}</div>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Project <span className="text-red-500">*</span></label>
            <select value={project} onChange={e => setProject(e.target.value)} className={inputCls} disabled={loadingProjects}>
              <option value="">{loadingProjects ? 'Loading…' : projects.length === 0 ? 'No projects -create one first' : 'Select a project…'}</option>
              {projects.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          </div>

          {category.targetTypes.length > 1 && (
            <div>
              <label className="block text-sm font-medium text-gray-700">Scan Target</label>
              <div className="mt-1 flex flex-wrap gap-2">
                {category.targetTypes.map(t => (
                  <button key={t} type="button" onClick={() => setTargetType(t)}
                    className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
                      targetType === t ? `${colors.bg} ${colors.border} ${colors.icon} border` : 'border-gray-200 text-gray-500 hover:bg-gray-50'
                    }`}>
                    {{ repo: 'Git Repository', image: 'Image Name / Registry', image_upload: 'Upload Image File', image_bulk: 'Bulk Images', url: 'Web URL', fs: 'Filesystem', cluster: 'Live Cluster', code_upload: 'Upload Source Code' }[t]}
                  </button>
                ))}
              </div>
              {targetType === 'repo' && <p className="mt-1 text-xs text-gray-400">Uses the repository URL configured on the project.</p>}
            </div>
          )}

          {showTarget && (
            <div>
              <label className="block text-sm font-medium text-gray-700">
                {targetType === 'url' ? 'Target URL' : targetType === 'fs' ? 'Path' : 'Image Name'}
              </label>
              <input type="text" value={target} onChange={e => setTarget(e.target.value)}
                placeholder={{ image: 'e.g. ghcr.io/my-org/api:v2.1  or  nginx:latest  or  registry.host/img:tag', url: 'https://example.com', fs: '/path/to/dir' }[targetType] ?? ''}
                className={inputCls} />
              {targetType === 'image' && (
                <p className="mt-1 text-xs text-gray-400">
                  GHCR: <code className="font-mono">ghcr.io/org/image:tag</code> · Docker Hub: <code className="font-mono">image:tag</code> · Private: <code className="font-mono">registry.host/image:tag</code>
                </p>
              )}
            </div>
          )}

          {targetType === 'image_bulk' && (
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Image Names <span className="text-red-500">*</span>
                <span className="ml-1 text-xs font-normal text-gray-400">— one per line</span>
              </label>
              <textarea
                value={bulkText}
                onChange={e => setBulkText(e.target.value)}
                onPaste={handleBulkPaste}
                rows={8}
                placeholder={[
                  '# GitHub Container Registry (GHCR)',
                  'ghcr.io/my-org/api-service:v2.1.0',
                  'ghcr.io/my-org/frontend:latest',
                  'ghcr.io/my-org/worker:sha-abc1234',
                  '',
                  '# Docker Hub',
                  'nginx:1.25-alpine',
                  'postgres:16',
                  '',
                  '# Private registry',
                  'registry.example.com/app:prod',
                ].join('\n')}
                className={`${inputCls} font-mono resize-y text-xs leading-relaxed`}
              />
              <div className="mt-1.5 flex items-center justify-between">
                <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-gray-400">
                  <span><span className="font-medium text-gray-500">GHCR:</span> ghcr.io/org/image:tag</span>
                  <span><span className="font-medium text-gray-500">Docker Hub:</span> image:tag</span>
                  <span><span className="font-medium text-gray-500">Private:</span> registry.host/image:tag</span>
                </div>
                {bulkImages.length > 0 && (
                  <span className="shrink-0 text-xs font-medium text-gray-600">{bulkImages.length} image{bulkImages.length !== 1 ? 's' : ''}</span>
                )}
              </div>
            </div>
          )}

          {targetType === 'image_upload' && (
            <div>
              <label className="block text-sm font-medium text-gray-700">Image File <span className="text-red-500">*</span></label>
              <input ref={fileRef} type="file" accept=".tar,.tar.gz,.tgz"
                onChange={e => setFile(e.target.files?.[0] ?? null)}
                className="mt-1 block w-full text-sm text-gray-600 file:mr-3 file:rounded-lg file:border-0 file:bg-gray-100 file:px-3 file:py-1.5 file:text-sm file:font-medium hover:file:bg-gray-200" />
              <p className="mt-1 text-xs text-gray-400">.tar, .tar.gz, .tgz -max 2 GB</p>
            </div>
          )}

          {targetType === 'code_upload' && (
            <div>
              <label className="block text-sm font-medium text-gray-700">Source Code Archive <span className="text-red-500">*</span></label>
              <input ref={fileRef} type="file" accept=".zip,.tar,.tar.gz,.tgz"
                onChange={e => setFile(e.target.files?.[0] ?? null)}
                className="mt-1 block w-full text-sm text-gray-600 file:mr-3 file:rounded-lg file:border-0 file:bg-gray-100 file:px-3 file:py-1.5 file:text-sm file:font-medium hover:file:bg-gray-200" />
              <p className="mt-1 text-xs text-gray-400">.zip, .tar, .tar.gz - upload your project source code</p>
            </div>
          )}

          {showCreds && (
            <div className={`rounded-xl border p-4 ${colors.bg} ${colors.border}`}>
              <p className={`mb-3 text-xs font-semibold uppercase tracking-wide ${colors.icon}`}>
                Registry Credentials <span className="font-normal normal-case opacity-60">(optional -private registries only)</span>
              </p>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600">Username</label>
                  <input type="text" value={regUser} onChange={e => setRegUser(e.target.value)} placeholder="username" className={inputCls} />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600">Password / Token</label>
                  <input type="password" value={regPass} onChange={e => setRegPass(e.target.value)} placeholder="••••••••" className={inputCls} />
                </div>
              </div>
            </div>
          )}

          {/* K8s-specific fields */}
          {category.key === 'k8s' && (
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Scanning Tool</label>
                <div className="mt-1 flex flex-wrap gap-2">
                  {([
                    { value: 'both', label: 'Both (Recommended)', desc: 'Kubescape + Trivy' },
                    { value: 'kubescape', label: 'Kubescape', desc: 'Compliance & policy' },
                    { value: 'trivy', label: 'Trivy', desc: 'Misconfigs & vulns' },
                  ] as const).map(opt => (
                    <button key={opt.value} type="button" onClick={() => setK8sTool(opt.value)}
                      className={`rounded-lg border px-3 py-1.5 text-sm font-medium transition-colors ${
                        k8sTool === opt.value
                          ? `${colors.bg} ${colors.border} ${colors.icon} border`
                          : 'border-gray-200 text-gray-500 hover:bg-gray-50'
                      }`}>
                      {opt.label}
                    </button>
                  ))}
                </div>
                <p className="mt-1 text-xs text-gray-400">
                  {k8sTool === 'both' ? 'Triggers two scans: Kubescape (compliance) + Trivy (misconfigs & CVEs)'
                   : k8sTool === 'kubescape' ? 'NSA/MITRE/CIS compliance framework scanning'
                   : 'Misconfiguration detection and vulnerability scanning'}
                </p>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700">
                  Namespace <span className="text-xs font-normal text-gray-400">(optional -leave blank for all namespaces)</span>
                </label>
                <input type="text" value={k8sNamespace} onChange={e => setK8sNamespace(e.target.value)}
                  placeholder="e.g. default, kube-system"
                  className={inputCls} />
              </div>
              {/* Kubeconfig status + upload */}
              {!project ? (
                <p className="rounded-xl bg-gray-50 border border-gray-200 p-3 text-xs text-gray-500">
                  Select a project first to configure kubeconfig.
                </p>
              ) : kubeconfigStatus?.configured ? (
                <div className="rounded-xl bg-green-50 border border-green-200 p-3">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="h-4 w-4 text-green-600 shrink-0" />
                    <div className="flex-1">
                      <p className="text-xs font-semibold text-green-700">Kubeconfig configured</p>
                      <p className="text-[11px] text-green-600">{kubeconfigStatus.clusters} cluster{kubeconfigStatus.clusters !== 1 ? 's' : ''} detected</p>
                    </div>
                    <label className="cursor-pointer rounded-lg border border-green-300 bg-white px-2.5 py-1 text-[11px] font-medium text-green-700 hover:bg-green-50 transition-colors">
                      Replace
                      <input ref={kubeconfigRef} type="file" accept=".yaml,.yml" onChange={handleKubeconfigUpload} className="hidden" />
                    </label>
                  </div>
                </div>
              ) : (
                <div className="rounded-xl bg-amber-50 border border-amber-200 p-3">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="h-4 w-4 text-amber-600 shrink-0" />
                    <div className="flex-1">
                      <p className="text-xs font-semibold text-amber-700">No kubeconfig uploaded</p>
                      <p className="text-[11px] text-amber-600">Upload your cluster's kubeconfig to enable K8s scanning</p>
                    </div>
                  </div>
                  <label className={`mt-2 flex cursor-pointer items-center justify-center gap-2 rounded-lg border border-amber-300 bg-white px-3 py-2 text-xs font-semibold text-amber-700 hover:bg-amber-50 transition-colors ${kubeconfigUploading ? 'opacity-60 pointer-events-none' : ''}`}>
                    {kubeconfigUploading ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
                    {kubeconfigUploading ? 'Uploading...' : 'Upload Kubeconfig (.yaml)'}
                    <input ref={kubeconfigRef} type="file" accept=".yaml,.yml" onChange={handleKubeconfigUpload} className="hidden" disabled={kubeconfigUploading} />
                  </label>
                </div>
              )}
            </div>
          )}

          {bulkProgress && (
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs text-gray-500">
                <span>Triggering scans…</span>
                <span className="font-medium text-gray-700">{bulkProgress.done} / {bulkProgress.total}</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-gray-100">
                <div
                  className="h-2 rounded-full bg-gray-800 transition-all duration-300"
                  style={{ width: `${(bulkProgress.done / bulkProgress.total) * 100}%` }}
                />
              </div>
            </div>
          )}

          <div className="flex justify-end gap-3 pt-1">
            <button type="button" onClick={onClose} disabled={submitting}
              className="rounded-lg border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-40">
              Cancel
            </button>
            <button type="submit" disabled={submitting}
              className="inline-flex items-center gap-2 rounded-lg bg-gray-900 px-4 py-2 text-sm font-semibold text-white hover:bg-gray-800 disabled:opacity-60">
              {submitting && targetType === 'image_bulk'
                ? <><RefreshCw className="h-4 w-4 animate-spin" /> Queueing {bulkProgress?.done ?? 0} / {bulkProgress?.total ?? bulkImages.length}…</>
                : submitting
                  ? <><RefreshCw className="h-4 w-4 animate-spin" /> Starting…</>
                  : targetType === 'image_bulk' && bulkImages.length > 0
                    ? <><Play className="h-4 w-4" /> Start {bulkImages.length} Scans</>
                    : <><Play className="h-4 w-4" /> Start Scan</>
              }
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Category card                                                          */
/* ------------------------------------------------------------------ */
function CategoryCard({ cat, scans, onTrigger, canTrigger }: {
  cat: typeof CATEGORIES[number];
  scans: Scan[];
  onTrigger: () => void;
  canTrigger: boolean;
}) {
  const colors = COLOR_CLASSES[cat.color];
  const Icon = cat.icon;
  const lastScan = scans[0];
  const running = scans.filter(s => s.status === 'running' || s.status === 'pending').length;
  const recentScans = scans.slice(0, 5);

  return (
    <div className={`rounded-2xl border ${colors.border} bg-white shadow-sm`}>
      <div className="p-5">
        <div className="flex items-start justify-between">
          <div className="flex items-center gap-3">
            <div className={`flex h-11 w-11 items-center justify-center rounded-xl ${colors.bg}`}>
              <Icon className={`h-6 w-6 ${colors.icon}`} />
            </div>
            <div>
              <h3 className="font-semibold text-gray-900">{cat.label}</h3>
            </div>
          </div>
          {canTrigger && (
            <button onClick={onTrigger}
              className="inline-flex items-center gap-1.5 rounded-lg bg-gray-900 px-3 py-1.5 text-sm font-semibold text-white shadow-sm hover:bg-gray-800">
              <Play className="h-3.5 w-3.5" /> Scan
            </button>
          )}
        </div>

        <p className="mt-3 text-sm text-gray-500">{cat.description}</p>

        <div className="mt-4 flex items-center gap-4 text-sm text-gray-500">
          <span><span className="font-semibold text-gray-800">{scans.length}</span> scans total</span>
          {running > 0 && (
            <span className="inline-flex items-center gap-1 text-yellow-600 font-medium">
              <RefreshCw className="h-3.5 w-3.5 animate-spin" /> {running} in progress
            </span>
          )}
        </div>

        {/* Recent scan history */}
        {recentScans.length > 0 && (
          <div className="mt-3 space-y-1.5">
            {recentScans.map(s => {
              const time = s.completed_at || s.started_at || s.created_at;
              const ago = time ? _timeAgo(time) : '';
              return (
                <div key={s.id} className={`flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-xs ${
                  s.status === 'failed' ? 'bg-red-50' : s.status === 'running' || s.status === 'pending' ? 'bg-yellow-50' : 'bg-gray-50'
                }`}>
                  <StatusBadge status={s.status} />
                  <span className="flex-1 truncate text-gray-600">
                    {s.tool_name}{s.findings_count > 0 ? ` · ${s.findings_count} findings` : ''}
                  </span>
                  {ago && <span className="shrink-0 text-[10px] text-gray-400">{ago}</span>}
                  {s.status === 'failed' && s.error_message && (
                    <span className="shrink-0 text-[10px] text-red-500 max-w-[120px] truncate" title={s.error_message}>
                      {s.error_message.split('\n')[0].slice(0, 60)}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function _timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

/* ------------------------------------------------------------------ */
/* Main page                                                              */
/* ------------------------------------------------------------------ */
export default function Scans() {
  const hasRole = useAuthStore(s => s.hasRole);
  const canTrigger = hasRole('security_engineer');
  const navigate = useNavigate();

  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [activeModal, setActiveModal] = useState<CategoryKey | null>(null);

  const fetchScans = useCallback(async () => {
    try {
      const res = await getScans({ page_size: 200 });
      setScans(Array.isArray(res) ? res : (res.items ?? res.results ?? []));
    } catch { /* noop */ }
  }, []);

  // Initial load
  useEffect(() => {
    (async () => { setLoading(true); await fetchScans(); setLoading(false); })();
  }, [fetchScans]);

  // Auto-poll every 5s while any scan is pending/running
  useEffect(() => {
    const hasActive = scans.some(s => s.status === 'pending' || s.status === 'running');
    if (!hasActive) return;
    const timer = setInterval(fetchScans, 5000);
    return () => clearInterval(timer);
  }, [scans, fetchScans]);

  const scansFor = (key: CategoryKey) =>
    scans.filter(s => scanCategory(s) === key)
      .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  const modalCat = CATEGORIES.find(c => c.key === activeModal);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Security Scans</h1>
        <span className="text-sm text-gray-400">{scans.length} total scans</span>
      </div>

      {loading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="h-48 animate-pulse rounded-2xl border border-gray-200 bg-gray-50" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {CATEGORIES.map(cat => (
            <CategoryCard
              key={cat.key}
              cat={cat}
              scans={scansFor(cat.key)}
              onTrigger={() => setActiveModal(cat.key)}
              canTrigger={canTrigger}
            />
          ))}
        </div>
      )}

      {/* View history button */}
      <div className="flex justify-center pt-2">
        <button onClick={() => navigate('/projects')}
          className="inline-flex items-center gap-2 rounded-xl border border-gray-200 bg-white px-5 py-2.5 text-sm font-medium text-gray-600 shadow-sm hover:bg-gray-50 hover:border-gray-300 transition-colors">
          <FolderOpen className="h-4 w-4 text-gray-400" />
          View Scan History -go to Projects
        </button>
      </div>

      {modalCat && activeModal && (
        <TriggerModal
          category={modalCat}
          onClose={() => setActiveModal(null)}
          onSuccess={scan => {
            setScans(prev => [scan, ...prev]);
            fetchScans(); // refresh in case bulk triggered many
            setActiveModal(null);
          }}
        />
      )}
    </div>
  );
}
