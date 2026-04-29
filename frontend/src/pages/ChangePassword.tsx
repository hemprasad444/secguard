import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Lock, RefreshCw, AlertTriangle } from 'lucide-react';
import { changePassword, getMe } from '../api/auth';
import { useAuthStore } from '../stores/authStore';

export default function ChangePassword() {
  const navigate = useNavigate();
  const setUser = useAuthStore(s => s.setUser);
  const user = useAuthStore(s => s.user);
  const isFirstTime = !!(user as any)?.must_change_password;

  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (next.length < 8) {
      setError('New password must be at least 8 characters.');
      return;
    }
    if (next !== confirm) {
      setError('Passwords do not match.');
      return;
    }
    if (next === current) {
      setError('New password must differ from the current one.');
      return;
    }
    setBusy(true);
    try {
      await changePassword(current, next);
      // refresh /me so the must_change_password flag flips off in store
      try {
        const fresh = await getMe();
        setUser(fresh);
      } catch { /* noop */ }
      setSuccess(true);
      setTimeout(() => navigate('/'), 800);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Password change failed.');
    }
    setBusy(false);
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-sm rounded-md border border-gray-200 bg-white p-6">
        <div className="flex items-center gap-2 mb-4">
          <Lock className="h-5 w-5 text-gray-700" strokeWidth={1.75} />
          <h1 className="text-lg font-semibold text-gray-900">Change password</h1>
        </div>

        {isFirstTime && (
          <div className="mb-4 rounded-md border border-amber-200 bg-amber-50/60 px-3 py-2 text-[12px] text-amber-800">
            An admin set a temporary password for this account. Please change it before continuing.
          </div>
        )}

        <form onSubmit={submit} className="space-y-3">
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Current password</span>
            <input type="password" value={current} onChange={e => setCurrent(e.target.value)} required
              autoComplete="current-password"
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm text-gray-800 focus:outline-none focus:border-gray-400" />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">New password</span>
            <input type="password" value={next} onChange={e => setNext(e.target.value)} required minLength={8}
              autoComplete="new-password"
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm text-gray-800 focus:outline-none focus:border-gray-400" />
          </label>
          <label className="block">
            <span className="text-[10px] uppercase tracking-wider text-gray-400">Confirm new password</span>
            <input type="password" value={confirm} onChange={e => setConfirm(e.target.value)} required minLength={8}
              autoComplete="new-password"
              className="mt-1 w-full rounded-md border border-gray-200 bg-white px-2.5 py-1.5 text-sm text-gray-800 focus:outline-none focus:border-gray-400" />
          </label>

          {error && (
            <div className="flex items-start gap-2 rounded-md border border-red-200 bg-red-50/60 px-3 py-2 text-[12px] text-red-700">
              <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}
          {success && (
            <p className="text-[12px] text-emerald-700">Password updated. Redirecting…</p>
          )}

          <button type="submit" disabled={busy}
            className="w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-gray-900 px-3 py-2 text-sm font-medium text-white hover:bg-black disabled:opacity-50">
            {busy ? <RefreshCw className="h-4 w-4 animate-spin" /> : null}
            Update password
          </button>
        </form>
      </div>
    </div>
  );
}
