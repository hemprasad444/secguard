import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowRight, AlertCircle, Loader2 } from 'lucide-react';
import api from '../api/client';
import { useAuthStore } from '../stores/authStore';

/**
 * SignUp screen — first-time org + admin bootstrap.
 *
 * Matches the Login page exactly: octagonal aperture mark, teal→cyan
 * accent, radar-sweep ambient panel on the left. Form on the right is
 * grouped into "Your organization" and "Your account" so the seven
 * fields read as two short forms instead of one long one.
 */
export default function SignUp() {
  const navigate = useNavigate();
  const setUser = useAuthStore((s) => s.setUser);
  const [orgName, setOrgName] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const generateSlug = (value: string) =>
    value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

  const handleOrgNameChange = (value: string) => {
    setOrgName(value);
    setOrgSlug(generateSlug(value));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    setLoading(true);
    try {
      const { data } = await api.post('/onboarding/signup', {
        org_name: orgName,
        org_slug: orgSlug,
        admin_name: name,
        admin_email: email,
        admin_password: password,
      });
      localStorage.setItem('access_token', data.access_token);
      localStorage.setItem('refresh_token', data.refresh_token);
      setUser({
        id: data.user.id,
        email: data.user.email,
        name: data.user.name,
        role: data.user.role,
        is_active: true,
        org_name: data.organization.name,
      });
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Sign up failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const inputCls =
    'mt-1.5 block w-full rounded-md border border-gray-200 bg-white px-3 py-2.5 text-[14px] text-gray-900 placeholder-gray-300 transition-colors focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-100';
  const labelCls =
    'text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-500';

  return (
    <div className="min-h-screen grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] bg-white">
      {/* ============== Left brand panel ============== */}
      <aside className="relative hidden lg:flex flex-col justify-between overflow-hidden bg-[#0c1a3a] text-white">
        {/* Radar-sweep background — identical to /login so the two
            entry points read as one product. */}
        <svg
          aria-hidden
          className="pointer-events-none absolute inset-0 h-full w-full"
          viewBox="0 0 800 900"
          preserveAspectRatio="xMidYMid slice"
        >
          <defs>
            <radialGradient id="su-vignette" cx="38%" cy="32%" r="78%">
              <stop offset="0%" stopColor="white" stopOpacity="0" />
              <stop offset="100%" stopColor="#0c1a3a" stopOpacity="0.96" />
            </radialGradient>
            <linearGradient id="su-sweep" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stopColor="#10b981" stopOpacity="0" />
              <stop offset="55%"  stopColor="#10b981" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.85" />
            </linearGradient>
            <linearGradient id="su-ring" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%"   stopColor="#06b6d4" stopOpacity="0.45" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.05" />
            </linearGradient>
          </defs>

          <g fill="none" stroke="url(#su-ring)" strokeWidth="0.9">
            <circle cx="300" cy="280" r="120" />
            <circle cx="300" cy="280" r="200" />
            <circle cx="300" cy="280" r="290" strokeOpacity="0.85" />
            <circle cx="300" cy="280" r="390" strokeOpacity="0.7" />
            <circle cx="300" cy="280" r="510" strokeOpacity="0.55" />
            <circle cx="300" cy="280" r="650" strokeOpacity="0.35" />
          </g>

          <g transform="translate(300 280)">
            <g>
              <animateTransform
                attributeName="transform" type="rotate"
                from="0" to="360" dur="6.5s" repeatCount="indefinite"
              />
              <line x1="0" y1="0" x2="650" y2="0" stroke="url(#su-sweep)" strokeWidth="2.4" />
              <line x1="0" y1="0" x2="640" y2="0" stroke="#10b981" strokeOpacity="0.18" strokeWidth="8" />
            </g>
          </g>

          <g fill="#7feedb">
            <circle cx="420" cy="280" r="2.4">
              <animate attributeName="opacity" values="0;1;0" dur="3.4s" repeatCount="indefinite" />
            </circle>
            <circle cx="300" cy="480" r="2.4">
              <animate attributeName="opacity" values="0;1;0" dur="4.1s" begin="0.8s" repeatCount="indefinite" />
            </circle>
            <circle cx="120" cy="320" r="2.0">
              <animate attributeName="opacity" values="0;1;0" dur="3.7s" begin="1.6s" repeatCount="indefinite" />
            </circle>
            <circle cx="510" cy="510" r="2.2">
              <animate attributeName="opacity" values="0;1;0" dur="4.6s" begin="2.2s" repeatCount="indefinite" />
            </circle>
            <circle cx="630" cy="180" r="2.0">
              <animate attributeName="opacity" values="0;1;0" dur="3.9s" begin="0.4s" repeatCount="indefinite" />
            </circle>
          </g>

          <g transform="translate(300 280)" fill="none" stroke="#7feedb" strokeWidth="1.6" strokeLinejoin="round">
            <polygon points="0,-14 10,-10 14,0 10,10 0,14 -10,10 -14,0 -10,-10" />
            <circle cx="0" cy="0" r="3" fill="#7feedb" stroke="none">
              <animate attributeName="opacity" values="0.4;1;0.4" dur="2.4s" repeatCount="indefinite" />
            </circle>
          </g>

          <rect width="800" height="900" fill="url(#su-vignette)" />
        </svg>

        {/* Top — wordmark */}
        <div className="relative z-10 px-12 py-10 flex items-center gap-3">
          <span className="inline-flex h-9 w-9 items-center justify-center rounded-md bg-white/8 ring-1 ring-white/15 text-[#7feedb]">
            <Aperture className="h-5 w-5" />
          </span>
          <span className="font-display text-[16px] font-semibold tracking-tight">
            OpenSentinel
          </span>
          <span className="ml-auto font-mono text-[10px] uppercase tracking-[0.22em] text-white/45">
            v1.0
          </span>
        </div>

        {/* Centre — tagline */}
        <div className="relative z-10 px-12">
          <p className="font-display text-[40px] xl:text-[46px] leading-[1.05] tracking-tight font-medium max-w-[15ch] text-white">
            Start watching
            <span className="block text-[#7feedb]">in 30 seconds.</span>
          </p>
          <p className="mt-6 max-w-md text-[13.5px] leading-relaxed text-white/65">
            Spin up your organization and you'll land directly in the
            dashboard — no waitlist, no demo call. Add teammates from
            Settings whenever you're ready.
          </p>

          {/* Three-step hint row — sets expectations for the form fields. */}
          <ol className="mt-10 space-y-2.5 text-[12px] text-white/60">
            {[
              ['1', 'Name your organization'],
              ['2', 'Create the first admin account'],
              ['3', 'Invite the rest of the team later'],
            ].map(([n, label]) => (
              <li key={n} className="flex items-center gap-3">
                <span className="inline-flex h-5 w-5 items-center justify-center rounded-full bg-white/8 ring-1 ring-white/15 text-[10px] font-semibold text-[#7feedb]">
                  {n}
                </span>
                {label}
              </li>
            ))}
          </ol>
        </div>

        {/* Bottom — status row */}
        <div className="relative z-10 px-12 py-10 flex items-center justify-between text-[11px] text-white/55">
          <div className="inline-flex items-center gap-2.5">
            <span className="relative inline-flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400/70 animate-ping" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
            </span>
            <span className="uppercase tracking-[0.2em] font-medium">Ready to onboard</span>
          </div>
          <span className="font-mono text-white/40">opensentinel</span>
        </div>
      </aside>

      {/* ============== Right form panel ============== */}
      <main className="flex items-center justify-center px-6 sm:px-10 py-10 sm:py-14">
        <div className="w-full max-w-[440px]">
          {/* Mobile brand chip — shown only on narrow viewports where
              the aside panel is hidden. */}
          <div className="lg:hidden mb-8 flex items-center gap-2.5">
            <span className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-[#0c1a3a] text-[#7feedb]">
              <Aperture className="h-4 w-4" />
            </span>
            <span className="font-display text-[15px] font-semibold tracking-tight text-gray-900">
              OpenSentinel
            </span>
          </div>

          <header className="mb-7">
            <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-teal-600">
              Create account
            </p>
            <h1 className="mt-2 font-display text-[28px] font-semibold tracking-tight text-gray-900">
              Set up your organization.
            </h1>
            <p className="mt-1.5 text-[13px] text-gray-500">
              You'll be the first admin and can invite teammates from
              Settings.
            </p>
          </header>

          {error && (
            <div
              role="alert"
              className="mb-5 flex items-start gap-2 border-l-2 border-rose-500 bg-rose-50/70 px-3 py-2 text-[12.5px] text-rose-800"
            >
              <AlertCircle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* ── Group 1: Organization ── */}
            <fieldset className="space-y-4">
              <legend className="text-[10px] font-semibold uppercase tracking-[0.22em] text-gray-400 mb-2">
                Your organization
              </legend>

              <div>
                <label htmlFor="orgName" className={labelCls}>Organization name</label>
                <input
                  id="orgName" type="text" required
                  value={orgName}
                  onChange={(e) => handleOrgNameChange(e.target.value)}
                  placeholder="Acme Security"
                  className={inputCls}
                />
              </div>

              <div>
                <label htmlFor="orgSlug" className={labelCls}>Slug</label>
                <input
                  id="orgSlug" type="text" required
                  value={orgSlug}
                  onChange={(e) => setOrgSlug(e.target.value)}
                  placeholder="acme-security"
                  className={`${inputCls} font-mono`}
                />
                <p className="mt-1 text-[11px] text-gray-400">
                  Lowercase letters, numbers, hyphens. Auto-filled from
                  the name — edit if you need.
                </p>
              </div>
            </fieldset>

            {/* ── Group 2: Admin account ── */}
            <fieldset className="space-y-4">
              <legend className="text-[10px] font-semibold uppercase tracking-[0.22em] text-gray-400 mb-2">
                Your account
              </legend>

              <div>
                <label htmlFor="name" className={labelCls}>Full name</label>
                <input
                  id="name" type="text" required autoComplete="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Jane Doe"
                  className={inputCls}
                />
              </div>

              <div>
                <label htmlFor="email" className={labelCls}>Work email</label>
                <input
                  id="email" type="email" required autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="jane@company.com"
                  className={inputCls}
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="password" className={labelCls}>Password</label>
                  <input
                    id="password" type="password" required
                    autoComplete="new-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Min 8 chars"
                    className={inputCls}
                  />
                </div>

                <div>
                  <label htmlFor="confirm" className={labelCls}>Confirm</label>
                  <input
                    id="confirm" type="password" required
                    autoComplete="new-password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Repeat"
                    className={inputCls}
                  />
                </div>
              </div>
            </fieldset>

            <button
              type="submit"
              disabled={loading}
              className="group inline-flex w-full items-center justify-center gap-2 rounded-md bg-gradient-to-r from-teal-600 to-cyan-600 px-4 py-2.5 text-[13px] font-semibold tracking-wide text-white transition-all hover:from-teal-700 hover:to-cyan-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating organization
                </>
              ) : (
                <>
                  Create organization
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-7 pt-5 border-t border-gray-100 flex items-center justify-between text-[12px] text-gray-500">
            <span>Already have an account?</span>
            <Link
              to="/login"
              className="inline-flex items-center gap-1 font-medium text-teal-600 hover:text-teal-700"
            >
              Sign in
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <p className="mt-10 font-mono text-[10px] uppercase tracking-[0.22em] text-gray-300">
            Open-source security tooling
          </p>
        </div>
      </main>
    </div>
  );
}

/**
 * Octagonal aperture mark — concentric octagons + centre pulse. Kept
 * inline so the shape lives with the product rather than as a stock
 * icon. Tints via currentColor.
 */
function Aperture({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      stroke="currentColor"
      strokeWidth="3"
      strokeLinejoin="round"
      className={className}
      aria-hidden
    >
      <polygon points="32,8 49,16 57,32 49,48 32,56 15,48 7,32 15,16" />
      <polygon points="32,20 42,25 47,32 42,39 32,44 22,39 17,32 22,25" opacity="0.55" />
      <circle cx="32" cy="32" r="3" fill="currentColor" stroke="none" />
    </svg>
  );
}
