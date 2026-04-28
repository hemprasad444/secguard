import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield } from 'lucide-react';
import { login } from '../api/auth';
import { getMe } from '../api/auth';
import { useAuthStore } from '../stores/authStore';

export default function Login() {
  const navigate = useNavigate();
  const setUser = useAuthStore((s) => s.setUser);

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await login(email, password);
      const user = await getMe();
      setUser(user);
      navigate('/');
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } } };
      setError(
        axiosErr.response?.data?.detail || 'Invalid email or password. Please try again.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-primary-600 to-primary-800 px-4">
      <div className="w-full max-w-md rounded-2xl bg-white p-8 shadow-2xl">
        {/* ---- Brand ---- */}
        <div className="mb-8 flex flex-col items-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary-100">
            <Shield className="h-8 w-8 text-primary-600" />
          </div>
          <h1 className="mt-4 text-3xl font-bold text-gray-900">OpenSentinel</h1>
          <p className="mt-1 text-sm text-gray-500">
            Sign in to your security dashboard
          </p>
        </div>

        {/* ---- Error ---- */}
        {error && (
          <div className="mb-4 rounded-lg bg-red-50 p-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {/* ---- Form ---- */}
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-medium text-gray-700"
            >
              Email address
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                         placeholder:text-gray-400 focus:border-primary-500 focus:outline-none
                         focus:ring-1 focus:ring-primary-500"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-gray-700"
            >
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="mt-1 block w-full rounded-lg border border-gray-300 px-3 py-2 shadow-sm
                         placeholder:text-gray-400 focus:border-primary-500 focus:outline-none
                         focus:ring-1 focus:ring-primary-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center rounded-lg bg-primary-600 px-4 py-2.5
                       text-sm font-semibold text-white shadow-sm transition-colors
                       hover:bg-primary-700 focus:outline-none focus:ring-2
                       focus:ring-primary-500 focus:ring-offset-2 disabled:opacity-60"
          >
            {loading ? (
              <svg
                className="h-5 w-5 animate-spin text-white"
                xmlns="http://www.w3.org/2000/svg"
                fill="none"
                viewBox="0 0 24 24"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                />
              </svg>
            ) : (
              'Sign in'
            )}
          </button>
        </form>

        <p className="mt-4 text-center text-sm text-gray-500">
          Don't have an account?{' '}
          <Link to="/signup" className="font-medium text-primary-600 hover:text-primary-700">Sign up</Link>
        </p>
      </div>
    </div>
  );
}
