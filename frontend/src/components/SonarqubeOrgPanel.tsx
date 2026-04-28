import { useEffect, useState } from 'react';
import { ExternalLink, RefreshCw, CheckCircle, AlertTriangle } from 'lucide-react';
import {
  getOrgSonarqube,
  setOrgSonarqube,
  removeOrgSonarqube,
  testOrgSonarqube,
  type SonarqubeOrgStatus,
} from '../api/organizations';

export default function SonarqubeOrgPanel() {
  const [status, setStatus] = useState<SonarqubeOrgStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState(false);
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState<'save' | 'test' | 'remove' | null>(null);
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const s = await getOrgSonarqube();
      setStatus(s);
      setUrl(s.url ?? '');
      setEditing(!s.url);
    } catch {
      setStatus({ url: null, token_configured: false });
      setEditing(true);
    }
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const isConfigured = !!status?.url;

  const save = async () => {
    if (!url.trim()) {
      setMsg({ kind: 'err', text: 'URL is required.' });
      return;
    }
    setBusy('save'); setMsg(null);
    try {
      const body: { url: string; token?: string } = { url: url.trim() };
      if (token.trim()) body.token = token.trim();
      const s = await setOrgSonarqube(body);
      setStatus(s);
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
      const r = await testOrgSonarqube();
      setMsg({ kind: r.ok ? 'ok' : 'err', text: r.detail });
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Test failed.' });
    }
    setBusy(null);
  };

  const disconnect = async () => {
    if (!confirm('Disconnect SonarQube? Existing per-project SonarQube findings stay in the database.')) return;
    setBusy('remove'); setMsg(null);
    try {
      await removeOrgSonarqube();
      setStatus({ url: null, token_configured: false });
      setUrl(''); setToken('');
      setEditing(true);
    } catch (e: any) {
      setMsg({ kind: 'err', text: e?.response?.data?.detail ?? 'Failed to disconnect.' });
    }
    setBusy(null);
  };

  if (loading) {
    return (
      <div className="rounded-md border border-gray-200 bg-white px-4 py-6 text-sm text-gray-400">
        Loading SonarQube settings…
      </div>
    );
  }

  return (
    <div className="rounded-md border border-gray-200 bg-white">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-gray-100 px-4 py-3">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-wider font-semibold text-gray-700">SonarQube — organization defaults</p>
          <p className="mt-0.5 text-[12px] text-gray-500">
            Used by every project in this organization unless overridden.
            {isConfigured && status?.url && (
              <>
                {' '}Connected to <a href={status.url} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-gray-700 hover:text-gray-900 hover:underline inline-flex items-center gap-0.5">
                  {status.url} <ExternalLink className="h-3 w-3" />
                </a>
              </>
            )}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {isConfigured && !editing && (
            <>
              <button onClick={test} disabled={busy !== null}
                className="inline-flex items-center gap-1.5 rounded-md border border-gray-200 px-3 py-1.5 text-xs font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50">
                {busy === 'test' ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : null}
                Test connection
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
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">SonarQube URL</span>
            <input type="url" value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://sonar.yourorg.com"
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-xs text-gray-800 focus:outline-none focus:border-gray-400" />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">
              Token {status?.token_configured && <span className="text-gray-400">— leave blank to keep existing</span>}
            </span>
            <input type="password" value={token} onChange={e => setToken(e.target.value)}
              placeholder={status?.token_configured ? '••••••••' : 'sqa_xxxxxxxxxxxx'}
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
                <button onClick={() => { setEditing(false); setUrl(status?.url ?? ''); setToken(''); setMsg(null); }}
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
