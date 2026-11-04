import React, { useEffect, useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import {
  Shield,
  Lock,
  Mail,
  ArrowRight,
  UserRound,
  Terminal,
  Wrench,
  Eye,
  Building2,
} from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OrganizationSummary, UserRole } from '../types/api';

const seededAccounts = [
  {
    role: 'admin' as UserRole,
    title: 'Platform Admin',
    email: 'admin@sentinel.local',
    desc: 'Policies, users, JWT secrets, and the gateway master switch',
    icon: Shield,
    badge: 'Full Access',
  },
  {
    role: 'analyst' as UserRole,
    title: 'SOC Security Analyst',
    email: 'analyst@sentinel.local',
    desc: 'Triage alerts, inspect forensics, and block IPs or tokens',
    icon: Terminal,
    badge: 'SOC Ops',
  },
  {
    role: 'developer' as UserRole,
    title: 'API Owner / Developer',
    email: 'dev@sentinel.local',
    desc: 'Register APIs, import OpenAPI specs, and test JWTs',
    icon: Wrench,
    badge: 'API Inventory',
  },
  {
    role: 'viewer' as UserRole,
    title: 'Compliance Auditor',
    email: 'viewer@sentinel.local',
    desc: 'Read-only dashboards, coverage, analytics, and reports',
    icon: Eye,
    badge: 'Read-Only',
  },
];

export const LoginPage: React.FC = () => {
  const [mode, setMode] = useState<'signin' | 'register'>('signin');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [orgMode, setOrgMode] = useState<'create' | 'join'>('create');
  const [organizationName, setOrganizationName] = useState('');
  const [organizationId, setOrganizationId] = useState<number | ''>('');
  const [organizations, setOrganizations] = useState<OrganizationSummary[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { token, setAuth, addToast } = useGatewayStore();
  const navigate = useNavigate();

  useEffect(() => {
    if (mode !== 'register') return;
    apiFetch<OrganizationSummary[]>('/auth/organizations')
      .then((items) => {
        setOrganizations(items || []);
        if (items?.length && organizationId === '') {
          setOrganizationId(items[0].id);
        }
      })
      .catch(() => setOrganizations([]));
  }, [mode]);

  if (token) {
    return <Navigate to="/" replace />;
  }

  const redirectByRole = (role: UserRole) => {
    if (role === 'analyst') navigate('/alerts');
    else if (role === 'developer') navigate('/inventory');
    else navigate('/');
  };

  const handleSignIn = async (e: React.FormEvent) => {
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

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }
    if (orgMode === 'create' && organizationName.trim().length < 2) {
      setError('Enter an organization name');
      return;
    }
    if (orgMode === 'join' && !organizationId) {
      setError('Select an organization to join');
      return;
    }
    setLoading(true);
    try {
      const res = await apiFetch('/auth/register', {
        method: 'POST',
        body: JSON.stringify({
          email,
          full_name: fullName,
          password,
          organization_mode: orgMode,
          organization_name: orgMode === 'create' ? organizationName.trim() : undefined,
          organization_id: orgMode === 'join' ? Number(organizationId) : undefined,
        }),
      });
      setAuth(res.access_token, res.user);
      addToast({
        title: 'Account created',
        message:
          res.user.role === 'admin'
            ? `You are the admin of ${res.user.organization_name || 'your organization'}.`
            : `Joined ${res.user.organization_name || 'the organization'} as a viewer. An org admin can raise your access.`,
        severity: 'info',
      });
      navigate('/');
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const fillSeededAccount = (accountEmail: string) => {
    setMode('signin');
    setEmail(accountEmail);
    setPassword('sentinel123');
    setError('');
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 sm:p-6">
      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        <div className="lg:col-span-5 bg-slate-900 border border-slate-800 rounded-2xl p-5 sm:p-7 shadow-2xl">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2.5 rounded-xl bg-cyan-500/15 border border-cyan-500/40 text-cyan-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg sm:text-xl font-bold text-white">SentinelGW Control Plane</h1>
              <p className="text-xs text-slate-400">API Security Gateway & OWASP Threat Monitoring</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-1 p-1 mb-5 rounded-lg bg-slate-950 border border-slate-800">
            <button
              type="button"
              onClick={() => {
                setMode('signin');
                setError('');
              }}
              className={`py-2 rounded-md text-xs font-semibold transition ${
                mode === 'signin'
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError('');
              }}
              className={`py-2 rounded-md text-xs font-semibold transition ${
                mode === 'register'
                  ? 'bg-cyan-500/20 text-cyan-300'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Create Account
            </button>
          </div>

          {mode === 'signin' ? (
            <form onSubmit={handleSignIn} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
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
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition disabled:opacity-50"
              >
                <span>{loading ? 'Signing in...' : 'Sign In to Control Plane'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>
          ) : (
            <form onSubmit={handleRegister} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Full Name</label>
                <div className="relative">
                  <UserRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="text"
                    required
                    minLength={2}
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Jordan Hayes"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Email Address</label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Password</label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="At least 8 characters"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">Confirm Password</label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    required
                    minLength={8}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>

              <div className="space-y-3 p-3 rounded-xl bg-slate-950 border border-slate-800">
                <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
                  <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                  Organization
                </div>
                <div className="grid grid-cols-2 gap-1 p-1 rounded-lg bg-slate-900 border border-slate-800">
                  <button
                    type="button"
                    onClick={() => setOrgMode('create')}
                    className={`py-1.5 rounded-md text-[11px] font-semibold transition ${
                      orgMode === 'create'
                        ? 'bg-cyan-500/20 text-cyan-300'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Create new
                  </button>
                  <button
                    type="button"
                    onClick={() => setOrgMode('join')}
                    className={`py-1.5 rounded-md text-[11px] font-semibold transition ${
                      orgMode === 'join'
                        ? 'bg-cyan-500/20 text-cyan-300'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Join existing
                  </button>
                </div>

                {orgMode === 'create' ? (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Organization Name
                    </label>
                    <input
                      type="text"
                      required
                      minLength={2}
                      value={organizationName}
                      onChange={(e) => setOrganizationName(e.target.value)}
                      placeholder="Acme Security"
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                    />
                    <p className="text-[11px] text-slate-500 mt-1.5">
                      You become the organization admin and can manage roles for members.
                    </p>
                  </div>
                ) : organizations.length === 0 ? (
                  <p className="text-[11px] text-amber-300">
                    No organizations exist yet. Create one instead.
                  </p>
                ) : (
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Select Organization
                    </label>
                    <select
                      required
                      value={organizationId}
                      onChange={(e) => setOrganizationId(Number(e.target.value))}
                      className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500"
                    >
                      {organizations.map((org) => (
                        <option key={org.id} value={org.id}>
                          {org.name}
                        </option>
                      ))}
                    </select>
                    <p className="text-[11px] text-slate-500 mt-1.5">
                      New members join as viewers. An org admin can raise your role later.
                    </p>
                  </div>
                )}
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-xs text-rose-300">
                  {error}
                </div>
              )}

              <button
                type="submit"
                disabled={loading || (orgMode === 'join' && organizations.length === 0)}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition disabled:opacity-50"
              >
                <span>{loading ? 'Creating account...' : 'Create Account & Sign In'}</span>
                <ArrowRight className="w-4 h-4" />
              </button>
            </form>
          )}
        </div>

        <div className="lg:col-span-7 space-y-4">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Seeded Demo Accounts
            </span>
            <h2 className="text-2xl font-bold text-white mt-1">Sign in with a demo persona</h2>
            <p className="text-xs text-slate-400 mt-1">
              These accounts belong to the <span className="text-slate-200">Sentinel Demo</span>{' '}
              organization. Password:{' '}
              <span className="font-mono text-slate-200">sentinel123</span>. Org admins only manage
              users in their own organization.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
            {seededAccounts.map((p) => {
              const Icon = p.icon;
              return (
                <button
                  key={p.role}
                  type="button"
                  onClick={() => fillSeededAccount(p.email)}
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
