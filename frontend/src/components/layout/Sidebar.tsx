import { NavLink } from 'react-router-dom';
import {
  BarChart3,
  FolderGit2,
  Scan,
  Bug,
  FileText,
  Settings,
  LogOut,
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

/**
 * Octagonal aperture mark — concentric octagons + centre pulse. Matches
 * the brand mark on the login page; kept inline so the shape lives with
 * the product rather than a stock icon library. Tints via currentColor.
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

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { to: '/',           label: 'Analytics',  icon: BarChart3 },
  { to: '/projects',   label: 'Projects',   icon: FolderGit2 },
  { to: '/scans',      label: 'Scans',      icon: Scan },
  { to: '/findings',   label: 'Findings',   icon: Bug },
  { to: '/reports',    label: 'Reports',    icon: FileText },
  { to: '/settings',   label: 'Settings',   icon: Settings },
];

export default function Sidebar() {
  const { user, logout } = useAuthStore();

  return (
    <aside className="flex w-64 flex-col bg-[#0c1a3a] text-white">
      {/* Brand. Octagonal aperture mark + wordmark; matches the login. */}
      <div className="flex h-16 items-center gap-2.5 px-6">
        <Aperture className="h-7 w-7 text-[#7feedb]" />
        <span className="text-xl font-bold tracking-tight">OpenSentinel</span>
      </div>

      {/* Navigation links */}
      <nav className="mt-2 flex-1 space-y-1 px-3">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-white/10 text-white ring-1 ring-[#7feedb]/30'
                  : 'text-white/65 hover:bg-white/5 hover:text-white'
              }`
            }
          >
            <Icon className="h-5 w-5 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User info + logout */}
      <div className="border-t border-white/10 p-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-teal-500 to-cyan-600 text-sm font-semibold uppercase">
            {user?.name
              ? user.name
                  .split(' ')
                  .map((n: string) => n[0])
                  .join('')
                  .slice(0, 2)
              : '??'}
          </div>

          <div className="flex-1 truncate">
            <p className="truncate text-sm font-medium text-white">
              {user?.name ?? 'User'}
            </p>
            <p className="truncate text-xs text-white/55">
              {user?.role ?? 'member'}
            </p>
          </div>

          <button
            onClick={logout}
            className="rounded-md p-1.5 text-white/55 hover:bg-white/10 hover:text-white"
            title="Log out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
