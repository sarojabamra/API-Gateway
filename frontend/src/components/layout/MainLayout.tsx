import React, { useEffect } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Activity,
  Bell,
  Sliders,
  Gauge,
  FolderGit2,
  KeyRound,
  Ban,
  BarChart3,
  Zap,
  FileSpreadsheet,
  Settings,
  LogOut,
  Power,
  Search,
  Server,
  Menu,
  X,
} from 'lucide-react';
import { apiFetch } from '../../lib/api';
import { useGatewayStore } from '../../store/useGatewayStore';
import { RequestDetailDrawer } from '../shared/RequestDetailDrawer';

export const MainLayout: React.FC = () => {
  const {
    user,
    logout,
    gatewayEnabled,
    setGatewayEnabled,
    timeRange,
    setTimeRange,
    globalSearch,
    setGlobalSearch,
    pushLiveTraffic,
    pushLiveAlert,
    toasts,
    dismissToast,
    addToast,
    selectedProjectId,
    setSelectedProject,
  } = useGatewayStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [projects, setProjects] = React.useState<any[]>([]);
  const [sidebarOpen, setSidebarOpen] = React.useState(false);

  useEffect(() => {
    setSidebarOpen(false);
  }, [location.pathname]);

  useEffect(() => {
    const closeOnDesktop = () => {
      if (window.innerWidth >= 1024) setSidebarOpen(false);
    };
    window.addEventListener('resize', closeOnDesktop);
    return () => window.removeEventListener('resize', closeOnDesktop);
  }, []);

  useEffect(() => {
    if (!sidebarOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setSidebarOpen(false);
    };
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', onKey);
    return () => {
      document.body.style.overflow = prevOverflow;
      window.removeEventListener('keydown', onKey);
    };
  }, [sidebarOpen]);

  useEffect(() => {
    const loadProjects = async () => {
      try {
        const res = await apiFetch('/inventory');
        const items = res.upstreams || [];
        setProjects(items);
        if (items.length && !items.some((p: any) => p.id === selectedProjectId)) {
          const active = items.find((p: any) => p.enabled) || items[0];
          setSelectedProject(active.id, active.name, active.slug);
        }
      } catch {
        // Project picker remains hidden until the API is available.
      }
    };
    loadProjects();
  }, [selectedProjectId, setSelectedProject]);

  // Connect WebSocket for live traffic and alerts with automatic reconnect
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${window.location.host}/ws/live`;
    let ws: WebSocket | null = null;
    let pingTimer: any = null;
    let reconnectTimer: any = null;
    let unmounted = false;

    const connect = () => {
      if (unmounted) return;
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          pingTimer = setInterval(() => {
            if (ws?.readyState === WebSocket.OPEN) ws.send('ping');
          }, 15000);
        };
        ws.onmessage = (evt) => {
          try {
            const msg = JSON.parse(evt.data);
            if (msg.event === 'traffic' && msg.data) {
              pushLiveTraffic(msg.data);
            } else if (msg.event === 'alert' && msg.data) {
              pushLiveAlert(msg.data);
            }
          } catch {
            // ignore
          }
        };
        ws.onclose = () => {
          if (pingTimer) clearInterval(pingTimer);
          if (!unmounted) {
            reconnectTimer = setTimeout(connect, 2500);
          }
        };
      } catch {
        if (!unmounted) {
          reconnectTimer = setTimeout(connect, 2500);
        }
      }
    };
    connect();
    return () => {
      unmounted = true;
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [pushLiveTraffic, pushLiveAlert]);

  const handleToggleGateway = async () => {
    try {
      const res = await apiFetch('/simulator/gateway-toggle', {
        method: 'POST',
        body: JSON.stringify({ gateway_enabled: !gatewayEnabled }),
      });
      setGatewayEnabled(res.gateway_enabled);
      addToast({
        title: res.gateway_enabled ? 'Protection Turned ON' : 'Protection Turned OFF',
        message: res.status_text,
        severity: res.gateway_enabled ? 'info' : 'critical',
      });
    } catch (err: any) {
      addToast({ title: 'Permission Denied', message: err.message, severity: 'high' });
    }
  };

  const navGroups = [
    {
      title: 'Monitoring',
      items: [
        { to: '/', label: 'Overview', icon: LayoutDashboard },
        { to: '/traffic', label: 'Live Traffic', icon: Activity },
        { to: '/alerts', label: 'Security Alerts', icon: Bell },
        { to: '/analytics', label: 'Analytics', icon: BarChart3 },
      ],
    },
    {
      title: 'Gateway & Policies',
      items: [
        { to: '/inventory', label: 'API Inventory', icon: FolderGit2 },
        { to: '/policies', label: 'Security Policies', icon: Sliders },
        { to: '/rate-limits', label: 'Rate Limits', icon: Gauge },
        { to: '/auth-settings', label: 'Auth & JWT', icon: KeyRound },
        { to: '/blocklist', label: 'Blocklist', icon: Ban },
      ],
    },
    {
      title: 'Operations',
      items: [
        { to: '/simulator', label: 'Attack Simulator', icon: Zap },
        { to: '/reports', label: 'Reports', icon: FileSpreadsheet },
        { to: '/settings', label: 'Users & Access', icon: Settings },
      ],
    },
  ];

  const renderSearchField = () => (
    <div className="relative w-full min-w-0 md:max-w-xs lg:max-w-sm">
      <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
      <input
        type="text"
        value={globalSearch}
        onChange={(e) => setGlobalSearch(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Enter' && globalSearch.trim()) {
            navigate('/traffic');
          }
        }}
        placeholder="Search IP, path, or request ID..."
        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50"
      />
    </div>
  );

  return (
    <div className="min-h-screen flex bg-slate-950 text-slate-100 overflow-x-hidden">
      {sidebarOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Left Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-64 max-w-[85vw] bg-slate-900/95 border-r border-slate-800 flex flex-col justify-between transform transition-transform duration-200 lg:static lg:translate-x-0 lg:max-w-none lg:shrink-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="min-h-0 flex-1 flex flex-col">
          <div className="h-16 px-5 flex items-center justify-between gap-3 border-b border-slate-800 shrink-0">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-cyan-400 shrink-0">
                <Shield className="w-5 h-5" />
              </div>
              <div className="min-w-0">
                <div className="font-bold text-white tracking-tight flex items-center gap-1.5">
                  SentinelGW
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300">
                    v1.0
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">API Security Gateway</div>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setSidebarOpen(false)}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 lg:hidden"
              aria-label="Close menu"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <nav className="p-3 space-y-5 overflow-y-auto flex-1">
            {navGroups.map((group) => (
              <div key={group.title}>
                <div className="px-3 mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  {group.title}
                </div>
                <div className="space-y-0.5">
                  {group.items.map((item) => {
                    const Icon = item.icon;
                    return (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        end={item.to === '/'}
                        onClick={() => setSidebarOpen(false)}
                        className={({ isActive }) =>
                          `flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium transition ${
                            isActive
                              ? 'bg-cyan-500/15 text-cyan-300 border border-cyan-500/30'
                              : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                          }`
                        }
                      >
                        <Icon className="w-4 h-4 shrink-0" />
                        <span>{item.label}</span>
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
        </div>

        {/* User Card */}
        <div className="p-3 border-t border-slate-800 shrink-0">
          <div className="flex items-center justify-between px-2.5 py-2 rounded-lg bg-slate-950 border border-slate-800">
            <div className="truncate pr-2">
              <div className="text-xs font-semibold text-white truncate">
                {user?.full_name || 'Admin'}
              </div>
              <div className="text-[11px] font-mono text-slate-400 uppercase truncate">
                {user?.role || 'admin'}
                {user?.organization_name ? ` · ${user.organization_name}` : ''}
              </div>
            </div>
            <button
              onClick={() => {
                logout();
                navigate('/login');
              }}
              title="Sign Out"
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-rose-400"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 w-full">
        {/* Topbar */}
        <header className="sticky top-0 z-30 bg-slate-900/75 border-b border-slate-800 backdrop-blur-md">
          <div className="px-3 sm:px-4 lg:px-6 py-2 min-h-16 flex flex-wrap items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 hover:text-white lg:hidden"
              aria-label="Open navigation"
            >
              <Menu className="w-4 h-4" />
            </button>

            <div className="hidden md:block flex-1 min-w-0 max-w-sm">{renderSearchField()}</div>

            <div className="flex items-center gap-2 sm:gap-3 ml-auto flex-wrap justify-end">
              {projects.length > 0 && (
                <div className="flex items-center gap-1.5 sm:gap-2 bg-slate-950 border border-slate-800 rounded-lg px-2 sm:px-2.5 py-1 max-w-[min(100%,16rem)]">
                  <Server className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span className="hidden xl:inline text-[10px] font-mono uppercase text-slate-500">
                    Monitoring:
                  </span>
                  <select
                    value={selectedProjectId || ''}
                    onChange={(e) => {
                      const project = projects.find((p: any) => p.id === Number(e.target.value));
                      if (project) setSelectedProject(project.id, project.name, project.slug);
                    }}
                    className="min-w-0 max-w-[9rem] sm:max-w-52 bg-slate-950 text-xs font-medium text-slate-200 focus:outline-none"
                  >
                    {projects.map((project: any) => (
                      <option key={project.id} value={project.id}>
                        {project.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <button
                onClick={handleToggleGateway}
                className={`flex items-center gap-1.5 sm:gap-2 px-2 sm:px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition ${
                  gatewayEnabled
                    ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40 hover:bg-emerald-500/25'
                    : 'bg-rose-500/20 text-rose-300 border-rose-500/50'
                }`}
                title="Turn Gateway ON or OFF"
              >
                <Power className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">{gatewayEnabled ? 'GATEWAY: ON' : 'GATEWAY: OFF'}</span>
                <span className="sm:hidden">{gatewayEnabled ? 'ON' : 'OFF'}</span>
              </button>

              <div className="flex items-center bg-slate-950 border border-slate-800 rounded-lg p-0.5 text-xs font-mono">
                {(['15m', '1h', '24h', '7d'] as const).map((tr) => (
                  <button
                    key={tr}
                    onClick={() => setTimeRange(tr)}
                    className={`px-1.5 sm:px-2.5 py-1 rounded-md transition ${
                      timeRange === tr
                        ? 'bg-cyan-500/20 text-cyan-300 font-semibold'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {tr}
                  </button>
                ))}
              </div>

              <div className="flex items-center gap-1.5 sm:gap-2 bg-slate-950 border border-slate-800 rounded-lg px-2 sm:px-2.5 py-1">
                <span className="hidden sm:inline text-[10px] font-mono uppercase text-slate-500">Role:</span>
                <span className="text-[11px] font-mono font-semibold uppercase text-cyan-300">
                  {user?.role || 'viewer'}
                </span>
              </div>
            </div>

            <div className="w-full md:hidden">{renderSearchField()}</div>
          </div>
        </header>

        {/* Toast Notifications */}
        <div className="fixed bottom-4 inset-x-4 sm:inset-x-auto sm:right-5 sm:bottom-5 z-50 space-y-2 sm:max-w-md no-print">
          {toasts.map((t) => (
            <div
              key={t.id}
              onClick={() => dismissToast(t.id)}
              className={`cursor-pointer p-3.5 rounded-xl border shadow-xl backdrop-blur-md transition ${
                t.severity === 'critical'
                  ? 'bg-rose-950/90 border-rose-500/60 text-rose-100'
                  : t.severity === 'high'
                  ? 'bg-orange-950/90 border-orange-500/60 text-orange-100'
                  : 'bg-slate-900/95 border-cyan-500/40 text-slate-100'
              }`}
            >
              <div className="text-xs font-bold font-mono uppercase tracking-wider">{t.title}</div>
              <div className="text-xs mt-0.5 text-slate-200 break-anywhere">{t.message}</div>
            </div>
          ))}
        </div>

        {/* Page Outlet */}
        <main className="flex-1 p-3 sm:p-4 lg:p-6 overflow-x-hidden min-w-0">
          <Outlet />
        </main>
      </div>

      {/* Global Slide-over Request Inspector */}
      <RequestDetailDrawer />
    </div>
  );
};
