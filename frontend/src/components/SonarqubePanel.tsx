import { useState } from 'react';
import { ExternalLink, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';
import {
  configureSonarqube,
  removeSonarqube,
  testSonarqube,
  syncSonarqube,
} from '../api/projects';

interface ProjectLike {
  id: string;
  sonarqube_url?: string | null;
  sonarqube_project_key?: string | null;
  sonarqube_token_configured?: boolean;
  sonarqube_last_synced_at?: string | null;
}

export default function SonarqubePanel({ project, onUpdated }: {
  project: ProjectLike;
  onUpdated: (p: ProjectLike) => void;
}) {
  const isConfigured = !!(project.sonarqube_url && project.sonarqube_project_key);
  const [editing, setEditing] = useState(!isConfigured);
  const [url, setUrl] = useState(project.sonarqube_url ?? '');
  const [projectKey, setProjectKey] = useState(project.sonarqube_project_key ?? '');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState<'save' | 'test' | 'sync' | 'remove' | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const save = async () => {
    if (!url.trim() || !projectKey.trim()) {
      setMsg({ kind: 'err', text: 'URL and project key are required.' });
      return;
    }
    setBusy('save'); setMsg(null);
    try {
      const body: { url: string; project_key: string; token?: string } = {
        url: url.trim(),
        project_key: projectKey.trim(),
      };
      if (token.trim()) body.token = token.trim();
      const updated = await configureSonarqube(project.id, body);
      onUpdated(updated);
      setEditing(false);
      setToken('');
      setMsg({ kind: 'ok', text: 'Saved.' });
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Failed to save.' });
    }
    setBusy(null);
  };

  const test = async () => {
    setBusy('test'); setMsg(null);
    try {
      const r = await testSonarqube(project.id);
      setMsg({ kind: r.ok ? 'ok' : 'err', text: r.detail });
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Test failed.' });
    }
    setBusy(null);
  };

  const sync = async () => {
    setBusy('sync'); setMsg(null);
    try {
      await syncSonarqube(project.id);
      setMsg({ kind: 'ok', text: 'Sync queued. Findings will appear when the worker finishes.' });
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Failed to queue sync.' });
    }
    setBusy(null);
  };

  const disconnect = async () => {
    if (!confirm('Disconnect SonarQube? Existing findings will remain in the database.')) return;
    setBusy('remove'); setMsg(null);
    try {
      await removeSonarqube(project.id);
      onUpdated({
        ...project,
        sonarqube_url: null,
        sonarqube_project_key: null,
        sonarqube_token_configured: false,
      });
      setUrl(''); setProjectKey(''); setToken('');
      setEditing(true);
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Failed to disconnect.' });
    }
    setBusy(null);
  };

  return (
    <div className="rounded-md border border-gray-200 bg-white">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-100 px-4 py-3">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">SonarQube integration</p>
          <p className="mt-0.5 text-[12px] text-gray-500">
            Pull SonarQube issues into this project's SAST findings.
            {isConfigured && project.sonarqube_url && (
              <>
                {' '}Linked to <a href={project.sonarqube_url} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-gray-700 hover:text-gray-900 hover:underline inline-flex items-center gap-0.5">
                  {project.sonarqube_url} <ExternalLink className="h-3 w-3" />
                </a>
              </>
            )}
          </p>
          {project.sonarqube_last_synced_at && (
            <p className="mt-0.5 text-[11px] text-gray-400">
              Last synced {new Date(project.sonarqube_last_synced_at).toLocaleString()}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isConfigured && !editing && (
            <>
              <button onClick={test} disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                {busy === 'test' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
                Test connection
              </button>
              <button onClick={sync} disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black disabled:opacity-50">
                {busy === 'sync' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
                Sync now
              </button>
              <button onClick={() => { setEditing(true); setMsg(null); }}
                className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50">
                Edit
              </button>
            </>
          )}
        </div>
      </div>

      {(editing || !isConfigured) && (
        <div className="px-4 py-3 space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[10px] uppercase tracking-wider text-gray-400">SonarQube URL</span>
              <input type="url" value={url} onChange={e => setUrl(e.target.value)}
                placeholder="https://sonar.yourorg.com"
                className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-xs text-gray-800 focus:outline-none focus:border-gray-400" />
            </label>
            <label className="block">
              <span className="text-[10px] uppercase tracking-wider text-gray-400">Project key</span>
              <input type="text" value={projectKey} onChange={e => setProjectKey(e.target.value)}
                placeholder="my-org_my-project"
                className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-xs font-mono text-gray-800 focus:outline-none focus:border-gray-400" />
            </label>
          </div>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">
              Token {project.sonarqube_token_configured && <span className="text-gray-400">— leave blank to keep existing</span>}
            </span>
            <input type="password" value={token} onChange={e => setToken(e.target.value)}
              placeholder={project.sonarqube_token_configured ? '••••••••' : 'sqa_xxxxxxxxxxxx'}
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-xs font-mono text-gray-800 focus:outline-none focus:border-gray-400" />
          </label>
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={save} disabled={busy !== null}
              className="inline-flex items-center gap-1.5 rounded-md bg-gray-900 px-3 py-1.5 text-xs font-medium text-white hover:bg-black disabled:opacity-50">
              {busy === 'save' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
              {isConfigured ? 'Save changes' : 'Connect SonarQube'}
            </button>
            {isConfigured && (
              <>
                <button onClick={() => { setEditing(false); setUrl(project.sonarqube_url ?? ''); setProjectKey(project.sonarqube_project_key ?? ''); setToken(''); setMsg(null); }}
                  className="rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-600 hover:bg-gray-50">
                  Cancel
                </button>
                <button onClick={disconnect} disabled={busy !== null}
                  className="ml-auto rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-500 hover:text-red-700 hover:border-red-200 disabled:opacity-50">
                  Disconnect
                </button>
              </>
            )}
          </div>
        </div>
      )}

      {msg && (
        <div className={`flex items-center gap-2 border-t border-gray-100 px-4 py-2 text-[12px] ${
          msg.kind === 'ok' ? 'text-emerald-700' : 'text-red-700'
        }`}>
          {msg.kind === 'ok'
            ? <CheckCircle className="h-3.5 w-3.5 shrink-0" />
            : <AlertTriangle className="h-3.5 w-3.5 shrink-0" />}
          <span>{msg.text}</span>
        </div>
      )}
    </div>
  );
}
