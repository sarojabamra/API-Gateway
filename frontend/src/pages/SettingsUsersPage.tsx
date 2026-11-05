import React, { useEffect, useState } from 'react';
import { Users, RotateCcw, Plus, Building2, Shield, Power } from 'lucide-react';
import { apiFetch, formatDateTimeIST } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { LoadError } from '../components/shared/LoadError';

export const SettingsUsersPage: React.FC = () => {
  const { user, addToast, canMutate, setGatewayEnabled } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('viewer');
  const [reseeding, setReseeding] = useState(false);

  const fetchSettings = async () => {
    try {
      const res = await apiFetch('/settings');
      setData(res);
      setLoadError(null);
    } catch (err: any) {
      setLoadError(err?.message || 'Failed to load settings');
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch('/settings/users', {
        method: 'POST',
        body: JSON.stringify({
          email: newEmail,
          full_name: newName,
          role: newRole,
          password: newPassword,
        }),
      });
      addToast({ title: 'User Created', message: `Added ${newEmail} (${newRole})`, severity: 'info' });
      setNewEmail('');
      setNewName('');
      setNewPassword('');
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Failed', message: err.message, severity: 'high' });
    }
  };

  const handleRoleChange = async (userId: number, role: string) => {
    try {
      const current = (data?.users || []).find((u: any) => u.id === userId);
      await apiFetch(`/settings/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role, is_active: current?.is_active ?? true }),
      });
      addToast({ title: 'Role Updated', message: `User #${userId} assigned role '${role}'`, severity: 'info' });
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Role Update Failed', message: err.message, severity: 'high' });
    }
  };

  const handleReseed = async () => {
    setReseeding(true);
    try {
      const res = await apiFetch('/settings/reseed', { method: 'POST' });
      addToast({ title: 'Demo Data Re-Seeded', message: res.message, severity: 'info' });
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Re-Seed Failed', message: err.message, severity: 'high' });
    } finally {
      setReseeding(false);
    }
  };

  const orgName = data?.organization?.name || user?.organization_name || 'Your organization';

  const system = data?.system;

  const handleAutoBlockToggle = async () => {
    if (!system) return;
    try {
      await apiFetch('/blocklist/auto-config', {
        method: 'PUT',
        body: JSON.stringify({
          auto_block_critical: !system.auto_block_critical,
          auto_block_duration_minutes: system.auto_block_duration_minutes || 60,
        }),
      });
      addToast({
        title: 'Auto-Block Updated',
        message: `Critical auto-block is now ${!system.auto_block_critical ? 'ON' : 'OFF'}`,
        severity: 'info',
      });
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    }
  };

  const handleGatewayToggle = async () => {
    if (!system) return;
    try {
      const next = !system.gateway_enabled;
      await apiFetch('/simulator/gateway-toggle', {
        method: 'POST',
        body: JSON.stringify({ gateway_enabled: next }),
      });
      setGatewayEnabled(next);
      addToast({
        title: 'Gateway Protection',
        message: `Master switch is now ${next ? 'ON' : 'OFF'}`,
        severity: next ? 'info' : 'high',
      });
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Toggle Failed', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-white">
            Organization Users & Access
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage members of <span className="text-slate-200">{orgName}</span>. Organization admins
            can only change roles for users in the same organization.
          </p>
        </div>

        {canMutate(['admin', 'analyst']) && (
          <button
            disabled={reseeding}
            onClick={handleReseed}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            {reseeding ? 'Resetting...' : 'Reset & Re-Seed Clean Demo Telemetry'}
          </button>
        )}
      </div>

      {loadError && <LoadError message={loadError} onRetry={fetchSettings} />}

      {system && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Shield className="w-4 h-4 text-cyan-400" />
            Gateway Runtime Settings
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
            <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3">
              <div className="text-slate-400 mb-1">Master Protection</div>
              <div className="flex items-center justify-between gap-2">
                <span className={system.gateway_enabled ? 'text-emerald-300 font-semibold' : 'text-rose-300 font-semibold'}>
                  {system.gateway_enabled ? 'ON' : 'OFF'}
                </span>
                {canMutate(['admin', 'analyst']) && (
                  <button
                    type="button"
                    onClick={handleGatewayToggle}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 text-slate-200"
                  >
                    <Power className="w-3 h-3" /> Toggle
                  </button>
                )}
              </div>
            </div>
            <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3">
              <div className="text-slate-400 mb-1">Auto-Block Critical</div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-200 font-semibold">
                  {system.auto_block_critical ? 'Enabled' : 'Disabled'}
                </span>
                {canMutate(['admin', 'analyst']) && (
                  <button
                    type="button"
                    onClick={handleAutoBlockToggle}
                    className="px-2 py-1 rounded bg-slate-800 text-slate-200"
                  >
                    Toggle
                  </button>
                )}
              </div>
            </div>
            <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3">
              <div className="text-slate-400 mb-1">Auto-Block Duration</div>
              <div className="text-slate-200 font-semibold">{system.auto_block_duration_minutes || 60} min</div>
            </div>
            <div className="rounded-lg bg-slate-950/80 border border-slate-800 p-3">
              <div className="text-slate-400 mb-1">Anomaly Z-Score Threshold</div>
              <div className="text-slate-200 font-semibold">{system.anomaly_zscore_threshold ?? 3}</div>
            </div>
          </div>
          <p className="text-[11px] text-slate-500">
            Retention window: {system.retention_days || 30} days. Optional critical-alert webhook is configured via{' '}
            <code className="text-cyan-400">WEBHOOK_URL</code> on the backend.
          </p>
        </div>
      )}

      {data?.organization && (
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Building2 className="w-4 h-4" />
          </div>
          <div>
            <div className="text-sm font-semibold text-white">{data.organization.name}</div>
            <div className="text-[11px] font-mono text-slate-400">/{data.organization.slug}</div>
          </div>
          <div className="ml-auto text-xs text-slate-400">
            {(data?.users || []).length} member{(data?.users || []).length === 1 ? '' : 's'}
          </div>
        </div>
      )}

      {canMutate(['admin']) && (
        <form
          onSubmit={handleCreateUser}
          className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-end gap-3 text-xs"
        >
          <div className="flex-1 min-w-0 sm:min-w-[200px] w-full sm:w-auto">
            <label className="block text-slate-400 mb-1">Full Name</label>
            <input
              type="text"
              required
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              placeholder="Jordan Hayes"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
            />
          </div>
          <div className="flex-1 min-w-0 sm:min-w-[200px] w-full sm:w-auto">
            <label className="block text-slate-400 mb-1">Email Address</label>
            <input
              type="email"
              required
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="jordan@company.com"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div className="flex-1 min-w-0 sm:min-w-[180px] w-full sm:w-auto">
            <label className="block text-slate-400 mb-1">Password</label>
            <input
              type="password"
              required
              minLength={8}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="At least 8 characters"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">Assigned Role</label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
            >
              <option value="admin">admin</option>
              <option value="analyst">analyst</option>
              <option value="developer">developer</option>
              <option value="viewer">viewer</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold inline-flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add to Organization
          </button>
        </form>
      )}

      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white">Organization Members</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-3 px-4">Name</th>
                <th className="py-3 px-3">Email</th>
                <th className="py-3 px-3">Organization</th>
                <th className="py-3 px-3">RBAC Role</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Last Login (IST)</th>
                <th className="py-3 px-4 text-right">Modify Role (Org Admin)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {(data?.users || []).length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400">
                    No organization members found.
                  </td>
                </tr>
              ) : (
                (data?.users || []).map((u: any) => (
                  <tr key={u.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-semibold text-white">{u.full_name}</td>
                    <td className="py-3 px-3 font-mono text-cyan-300">{u.email}</td>
                    <td className="py-3 px-3 text-slate-300">{u.organization_name || '—'}</td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-200 font-mono uppercase text-[11px]">
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded font-mono uppercase text-[10px] ${
                          u.is_active
                            ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {u.is_active ? 'Active' : 'Disabled'}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {u.last_login_at ? formatDateTimeIST(u.last_login_at) : 'Never'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <select
                        disabled={!canMutate(['admin'])}
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value)}
                        className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-white font-mono disabled:opacity-50"
                      >
                        <option value="admin">admin</option>
                        <option value="analyst">analyst</option>
                        <option value="developer">developer</option>
                        <option value="viewer">viewer</option>
                      </select>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
