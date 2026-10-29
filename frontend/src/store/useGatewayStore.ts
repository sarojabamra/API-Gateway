import { create } from 'zustand';
import { AlertItem, TrafficLogItem, UserProfile, UserRole } from '../types/api';

interface ToastNotification {
  id: string;
  title: string;
  message: string;
  severity: 'critical' | 'high' | 'medium' | 'info';
}

interface GatewayState {
  token: string | null;
  user: UserProfile | null;
  gatewayEnabled: boolean;
  timeRange: '15m' | '1h' | '24h' | '7d';
  globalSearch: string;
  selectedRequestId: number | null;
  liveStreamPaused: boolean;
  liveTraffic: TrafficLogItem[];
  trafficTick: number;
  liveAlerts: AlertItem[];
  toasts: ToastNotification[];
  selectedProjectId: number | null;
  selectedProjectName: string;
  selectedProjectSlug: string;

  setAuth: (token: string, user: UserProfile) => void;
  logout: () => void;
  setGatewayEnabled: (enabled: boolean) => void;
  setTimeRange: (range: '15m' | '1h' | '24h' | '7d') => void;
  setGlobalSearch: (q: string) => void;
  openRequestDrawer: (logId: number) => void;
  closeRequestDrawer: () => void;
  setLiveStreamPaused: (paused: boolean) => void;
  pushLiveTraffic: (item: TrafficLogItem) => void;
  pushLiveAlert: (alert: AlertItem) => void;
  addToast: (toast: Omit<ToastNotification, 'id'>) => void;
  dismissToast: (id: string) => void;
  setSelectedProject: (id: number, name: string, slug: string) => void;
  canMutate: (allowedRoles?: UserRole[]) => boolean;
}

const DEFAULT_USER: UserProfile = {
  id: 1,
  email: 'admin@sentinel.local',
  full_name: 'Elena Rostova (Platform Admin)',
  role: 'admin',
  is_active: true,
};

export const useGatewayStore = create<GatewayState>((set, get) => ({
  token: localStorage.getItem('sentinel_token'),
  user: JSON.parse(localStorage.getItem('sentinel_user') || JSON.stringify(DEFAULT_USER)),
  gatewayEnabled: true,
  timeRange: '24h',
  globalSearch: '',
  selectedRequestId: null,
  liveStreamPaused: false,
  liveTraffic: [],
  trafficTick: 0,
  liveAlerts: [],
  toasts: [],
  selectedProjectId: Number(localStorage.getItem('sentinel_project_id')) || null,
  selectedProjectName: localStorage.getItem('sentinel_project_name') || '',
  selectedProjectSlug: localStorage.getItem('sentinel_project_slug') || '',

  setAuth: (token, user) => {
    localStorage.setItem('sentinel_token', token);
    localStorage.setItem('sentinel_user', JSON.stringify(user));
    set({ token, user });
  },

  logout: () => {
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_user');
    set({ token: null, user: null });
  },

  setGatewayEnabled: (gatewayEnabled) => set({ gatewayEnabled }),
  setTimeRange: (timeRange) => set({ timeRange }),
  setGlobalSearch: (globalSearch) => set({ globalSearch }),
  openRequestDrawer: (selectedRequestId) => set({ selectedRequestId }),
  closeRequestDrawer: () => set({ selectedRequestId: null }),
  setLiveStreamPaused: (liveStreamPaused) => set({ liveStreamPaused }),

  pushLiveTraffic: (item) => {
    if (get().liveStreamPaused) return;
    set((state) => ({
      trafficTick: state.trafficTick + 1,
      liveTraffic: [item, ...state.liveTraffic.filter((x) => x.request_id !== item.request_id)].slice(0, 120),
    }));
  },

  pushLiveAlert: (alert) => {
    set((state) => ({
      liveAlerts: [alert, ...state.liveAlerts.filter((a) => a.id !== alert.id)].slice(0, 50),
    }));
    if (alert.upstream_id && alert.upstream_id !== get().selectedProjectId) return;
    get().addToast({
      title: `[${alert.owasp_id}] ${alert.severity.toUpperCase()} ALERT`,
      message: `${alert.title} (${alert.client_ip})`,
      severity: alert.severity === 'critical' ? 'critical' : alert.severity === 'high' ? 'high' : 'medium',
    });
  },

  addToast: (toast) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    set((state) => ({ toasts: [...state.toasts.slice(-3), { ...toast, id }] }));
    setTimeout(() => {
      get().dismissToast(id);
    }, 5500);
  },

  dismissToast: (id) =>
    set((state) => ({ toasts: state.toasts.filter((t) => t.id !== id) })),

  setSelectedProject: (selectedProjectId, selectedProjectName, selectedProjectSlug) => {
    localStorage.setItem('sentinel_project_id', String(selectedProjectId));
    localStorage.setItem('sentinel_project_name', selectedProjectName);
    localStorage.setItem('sentinel_project_slug', selectedProjectSlug);
    set({ selectedProjectId, selectedProjectName, selectedProjectSlug });
  },

  canMutate: (allowedRoles = ['admin', 'analyst', 'developer']) => {
    const role = get().user?.role || 'viewer';
    return allowedRoles.includes(role);
  },
}));
