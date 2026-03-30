import { NavLink } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  FolderGit2,
  Scan,
  Bug,
  FileText,
  Settings,
  LogOut,
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const navItems: NavItem[] = [
  { to: '/',         label: 'Dashboard', icon: LayoutDashboard },
  { to: '/projects', label: 'Projects',  icon: FolderGit2 },
  { to: '/scans',    label: 'Scans',     icon: Scan },
  { to: '/findings', label: 'Findings',  icon: Bug },
  { to: '/reports',  label: 'Reports',   icon: FileText },
  { to: '/settings', label: 'Settings',  icon: Settings },
];

export default function Sidebar() {
  const { user, logout } = useAuthStore();

  return (
    <aside className="flex w-64 flex-col bg-gray-900 text-white">
      {/* Logo / Title */}
      <div className="flex h-16 items-center gap-2 px-6">
        <Shield className="h-7 w-7 text-primary-400" />
        <span className="text-xl font-bold tracking-tight">SecGuard</span>
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
                  ? 'bg-primary-600 text-white'
                  : 'text-gray-300 hover:bg-gray-800 hover:text-white'
              }`
            }
          >
            <Icon className="h-5 w-5 flex-shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* User info + logout */}
      <div className="border-t border-gray-700 p-4">
        <div className="flex items-center gap-3">
          {/* User avatar placeholder */}
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-primary-600 text-sm font-semibold uppercase">
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
            <p className="truncate text-xs text-gray-400">
              {user?.role ?? 'member'}
            </p>
          </div>

          <button
            onClick={logout}
            className="rounded-md p-1.5 text-gray-400 hover:bg-gray-800 hover:text-white"
            title="Log out"
          >
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );
}
