import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, Mail, ArrowRight, Terminal, Wrench, Eye } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { UserRole } from '../types/api';

export const LoginPage: React.FC = () => {
  const [email, setEmail] = useState('admin@sentinel.local');
  const [password, setPassword] = useState('sentinel123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { setAuth, addToast } = useGatewayStore();
  const navigate = useNavigate();

  const redirectByRole = (role: UserRole) => {
    if (role === 'analyst') navigate('/alerts');
    else if (role === 'developer') navigate('/inventory');
    else navigate('/');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await apiFetch('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      setAuth(res.access_token, res.user);
      addToast({
        title: 'Authenticated',
        message: `Welcome back, ${res.user.full_name}`,
        severity: 'info',
      });
      redirectByRole(res.user.role);
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoRole = async (role: UserRole) => {
    setError('');
    setLoading(true);
    try {
      const res = await apiFetch(`/auth/quick-role-switch/${role}`, { method: 'POST' });
      setAuth(res.access_token, res.user);
      addToast({
        title: `Signed in as ${res.user.role.toUpperCase()}`,
        message: `${res.user.full_name} (${res.user.email})`,
        severity: 'info',
      });
      redirectByRole(res.user.role);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const demoPersonas = [
    {
      role: 'admin' as UserRole,
      title: 'Platform Admin',
      email: 'admin@sentinel.local',
      desc: 'Full control over policies, users, JWT secrets & gateway master switch',
      icon: Shield,
      badge: 'Full Access',
    },
    {
      role: 'analyst' as UserRole,
      title: 'SOC Security Analyst',
      email: 'analyst@sentinel.local',
      desc: 'Triage alerts, inspect request forensics, block IPs/tokens & run simulations',
      icon: Terminal,
      badge: 'SOC Ops',
    },
    {
      role: 'developer' as UserRole,
      title: 'API Owner / Developer',
      email: 'dev@sentinel.local',
      desc: 'Register APIs, import OpenAPI specs, resolve shadow routes & test JWTs',
      icon: Wrench,
      badge: 'API Inventory',
    },
    {
      role: 'viewer' as UserRole,
      title: 'Compliance Auditor',
      email: 'viewer@sentinel.local',
      desc: 'Read-only OWASP coverage verification, analytics & CSV/PDF report export',
      icon: Eye,
      badge: 'Read-Only',
    },
  ];

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Left: Login Form */}
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-7 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">SentinelGW Control Plane</h1>
              <p className="text-xs text-slate-400">API Security Gateway & OWASP Threat Monitoring</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                Password <span className="text-slate-500 font-mono text-[11px]">(default: sentinel123)</span>
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {error && (
              <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-xs text-rose-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition"
            >
              <span>Sign In to Control Plane</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        </div>

        {/* Right: Role Presets */}
        <div className="lg:col-span-7 space-y-4">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Role-Based Access Control
            </span>
            <h2 className="text-2xl font-bold text-white mt-1">
              Quick Sign-In by Role
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Select a role profile to sign in with its assigned permissions and default workspace.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            {demoPersonas.map((p) => {
              const Icon = p.icon;
              return (
                <button
                  key={p.role}
                  onClick={() => handleQuickDemoRole(p.role)}
                  className="text-left p-4 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-cyan-500/40 transition group"
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-cyan-400 group-hover:border-cyan-500/40">
                      <Icon className="w-4 h-4" />
                    </div>
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {p.badge}
                    </span>
                  </div>
                  <div className="font-semibold text-sm text-white group-hover:text-cyan-300 transition">
                    {p.title}
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 mt-0.5">{p.email}</div>
                  <p className="text-xs text-slate-400 mt-2 leading-relaxed">{p.desc}</p>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
