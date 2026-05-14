import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ArrowRight, AlertCircle, Loader2 } from 'lucide-react';
import { login, getMe } from '../api/auth';
import { useAuthStore } from '../stores/authStore';

/**
 * Login screen.
 *
 * Visual direction is deliberately distinct from any commercial security
 * dashboard the team may have worked with previously: octagonal aperture
 * mark (no diamond / no V-chevron), teal→cyan accent (no warm gradient),
 * radar-sweep ambient background (no network-mesh / no Plinko cascade).
 * The shape vocabulary stays orthogonal — circles, octagons, scan lines —
 * so the page reads as its own product at a glance.
 */
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
      setError(axiosErr.response?.data?.detail || 'Invalid email or password.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen grid grid-cols-1 lg:grid-cols-[1.05fr_1fr] bg-white">
      {/* ============== Left brand panel ============== */}
      <aside className="relative hidden lg:flex flex-col justify-between overflow-hidden bg-[#0c1a3a] text-white">
        {/* Radar-sweep background. Concentric range rings + a slowly
            rotating sweep line — reads as "active observability" without
            looking like any specific tool. All decorative; no semantic
            content. Coordinates centred on a focal point near top-left
            so the sweep sits behind the wordmark area. */}
        <svg
          aria-hidden
          className="pointer-events-none absolute inset-0 h-full w-full"
          viewBox="0 0 800 900"
          preserveAspectRatio="xMidYMid slice"
        >
          <defs>
            <radialGradient id="vignette" cx="38%" cy="32%" r="78%">
              <stop offset="0%" stopColor="white" stopOpacity="0" />
              <stop offset="100%" stopColor="#0c1a3a" stopOpacity="0.96" />
            </radialGradient>
            <linearGradient id="sweep" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stopColor="#10b981" stopOpacity="0" />
              <stop offset="55%"  stopColor="#10b981" stopOpacity="0.55" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.85" />
            </linearGradient>
            <linearGradient id="ring" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%"   stopColor="#06b6d4" stopOpacity="0.45" />
              <stop offset="100%" stopColor="#06b6d4" stopOpacity="0.05" />
            </linearGradient>
          </defs>

          {/* Range rings — six concentric circles around the focal point.
              Stroked, increasing radii, lower opacity each ring out so
              the eye reads them as receding into the distance. */}
          <g fill="none" stroke="url(#ring)" strokeWidth="0.9">
            <circle cx="300" cy="280" r="120" />
            <circle cx="300" cy="280" r="200" />
            <circle cx="300" cy="280" r="290" strokeOpacity="0.85" />
            <circle cx="300" cy="280" r="390" strokeOpacity="0.7" />
            <circle cx="300" cy="280" r="510" strokeOpacity="0.55" />
            <circle cx="300" cy="280" r="650" strokeOpacity="0.35" />
          </g>

          {/* Sweep line — rotates clockwise around the focal point. Two
              segments (a brighter inner stroke + a softer trailing edge)
              to suggest motion blur. */}
          <g transform="translate(300 280)">
            <g>
              <animateTransform
                attributeName="transform" type="rotate"
                from="0" to="360" dur="6.5s" repeatCount="indefinite"
              />
              <line x1="0" y1="0" x2="650" y2="0" stroke="url(#sweep)" strokeWidth="2.4" />
              <line x1="0" y1="0" x2="640" y2="0" stroke="#10b981" strokeOpacity="0.18" strokeWidth="8" />
            </g>
          </g>

          {/* Sparse "pings" along a couple of rings — small dots that
              fade in and out, suggesting telemetry events. Random
              phases so they don't pulse in lockstep. */}
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

          {/* Focal point — small octagonal aperture matching the brand
              mark. Sits at the centre of the radar rings. */}
          <g transform="translate(300 280)" fill="none" stroke="#7feedb" strokeWidth="1.6" strokeLinejoin="round">
            <polygon points="0,-14 10,-10 14,0 10,10 0,14 -10,10 -14,0 -10,-10" />
            <circle cx="0" cy="0" r="3" fill="#7feedb" stroke="none">
              <animate attributeName="opacity" values="0.4;1;0.4" dur="2.4s" repeatCount="indefinite" />
            </circle>
          </g>

          <rect width="800" height="900" fill="url(#vignette)" />
        </svg>

        {/* Top — wordmark. Octagonal aperture mark + product name. */}
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
            Open-source security
            <span className="block text-[#7feedb]">observability.</span>
          </p>
          <p className="mt-6 max-w-md text-[13.5px] leading-relaxed text-white/65">
            One pane of glass for every container image, every Kubernetes
            workload, every finding — owned and remediated by the right
            person on your team.
          </p>
        </div>

        {/* Bottom — status row */}
        <div className="relative z-10 px-12 py-10 flex items-center justify-between text-[11px] text-white/55">
          <div className="inline-flex items-center gap-2.5">
            <span className="relative inline-flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400/70 animate-ping" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
            </span>
            <span className="uppercase tracking-[0.2em] font-medium">All systems operational</span>
          </div>
          <span className="font-mono text-white/40">opensentinel</span>
        </div>
      </aside>

      {/* ============== Right form panel ============== */}
      <main className="flex items-center justify-center px-6 sm:px-10 py-12 sm:py-16">
        <div className="w-full max-w-[400px]">
          <div className="lg:hidden mb-10 flex items-center gap-2.5">
            <span className="inline-flex h-8 w-8 items-center justify-center rounded-md bg-[#0c1a3a] text-[#7feedb]">
              <Aperture className="h-4 w-4" />
            </span>
            <span className="font-display text-[15px] font-semibold tracking-tight text-gray-900">
              OpenSentinel
            </span>
          </div>

          <header className="mb-8">
            <p className="text-[10px] font-semibold uppercase tracking-[0.22em] text-teal-600">
              Sign in
            </p>
            <h1 className="mt-2 font-display text-[30px] font-semibold tracking-tight text-gray-900">
              Welcome back.
            </h1>
            <p className="mt-2 text-[13px] text-gray-500">
              Continue to your security dashboard.
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

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label
                htmlFor="email"
                className="text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-500"
              >
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@example.com"
                className="mt-1.5 block w-full rounded-md border border-gray-200 bg-white px-3 py-2.5 text-[14px] text-gray-900 placeholder-gray-300 transition-colors focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-100"
              />
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label
                  htmlFor="password"
                  className="text-[10px] font-semibold uppercase tracking-[0.18em] text-gray-500"
                >
                  Password
                </label>
                <span className="text-[11px] text-gray-400">Ask an admin to reset</span>
              </div>
              <input
                id="password"
                type="password"
                required
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••"
                className="mt-1.5 block w-full rounded-md border border-gray-200 bg-white px-3 py-2.5 text-[14px] text-gray-900 placeholder-gray-300 transition-colors focus:border-teal-500 focus:outline-none focus:ring-2 focus:ring-teal-100"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="group inline-flex w-full items-center justify-center gap-2 rounded-md bg-gradient-to-r from-teal-600 to-cyan-600 px-4 py-2.5 text-[13px] font-semibold tracking-wide text-white transition-all hover:from-teal-700 hover:to-cyan-700 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:ring-offset-2 disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Signing in
                </>
              ) : (
                <>
                  Sign in
                  <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-5 border-t border-gray-100 flex items-center justify-between text-[12px] text-gray-500">
            <span>Don't have an account?</span>
            <Link
              to="/signup"
              className="inline-flex items-center gap-1 font-medium text-teal-600 hover:text-teal-700"
            >
              Create one
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>

          <p className="mt-12 font-mono text-[10px] uppercase tracking-[0.22em] text-gray-300">
            Open-source security tooling
          </p>
        </div>
      </main>
    </div>
  );
}

/**
 * Inline aperture mark — concentric octagons + centre pulse. Defined
 * here (rather than as a Lucide import) so the shape is a property of
 * this product, not a stock icon. Uses currentColor so callers can
 * tint via the surrounding text colour.
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
