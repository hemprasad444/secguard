import { Bell } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

export default function Header() {
  const user = useAuthStore((s) => s.user);

  return (
    <header className="flex h-16 items-center justify-between border-b border-gray-200 bg-white px-6">
      {/* Left side: page title / breadcrumb */}
      <div className="flex items-center">
        <h1 className="text-lg font-semibold text-gray-800">OpenSentinel</h1>
        {user?.org_name && (
          <span className="ml-2 rounded-md bg-gray-100 px-2 py-0.5 text-sm text-gray-600">{user.org_name}</span>
        )}
      </div>

      {/* Right side: notifications + user badge */}
      <div className="flex items-center gap-4">
        {/* Notification bell (placeholder) */}
        <button
          className="relative rounded-md p-2 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
          title="Notifications"
        >
          <Bell className="h-5 w-5" />
          {/* Unread dot indicator */}
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-red-500" />
        </button>

        {/* User name & role badge */}
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-gray-700">
            {user?.name ?? 'User'}
          </span>
          <span className="inline-flex items-center rounded-full bg-primary-100 px-2 py-0.5 text-xs font-medium capitalize text-primary-700">
            {user?.role ?? 'member'}
          </span>
        </div>
      </div>
    </header>
  );
}
