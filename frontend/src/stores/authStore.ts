import { create } from 'zustand';

interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  org_name?: string;
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  setUser: (user: User | null) => void;
  logout: () => void;
  hasRole: (minRole: string) => boolean;
}

const ROLE_HIERARCHY: Record<string, number> = {
  admin: 4, security_engineer: 3, developer: 2, viewer: 1,
};

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  isAuthenticated: !!localStorage.getItem('access_token'),
  setUser: (user) => set({ user, isAuthenticated: !!user }),
  logout: () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    set({ user: null, isAuthenticated: false });
  },
  hasRole: (minRole: string) => {
    const user = get().user;
    if (!user) return false;
    return (ROLE_HIERARCHY[user.role] || 0) >= (ROLE_HIERARCHY[minRole] || 0);
  },
}));
