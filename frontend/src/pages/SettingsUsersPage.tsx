import React, { useEffect, useState } from 'react';
import { Users, RotateCcw, Plus, CheckCircle2 } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';

export const SettingsUsersPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [newEmail, setNewEmail] = useState('');
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState('analyst');
  const [reseeding, setReseeding] = useState(false);

  const fetchSettings = async () => {
    try {
      const res = await apiFetch('/settings');
      setData(res);
    } catch {
      // ignore
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
          password: 'sentinel123',
        }),
      });
      addToast({ title: 'User Created', message: `Added ${newEmail} (${newRole})`, severity: 'info' });
      setNewEmail('');
      setNewName('');
      fetchSettings();
    } catch (err: any) {
      addToast({ title: 'Failed', message: err.message, severity: 'high' });
    }
  };

  const handleRoleChange = async (userId: number, role: string) => {
    try {
      await apiFetch(`/settings/users/${userId}`, {
        method: 'PATCH',
        body: JSON.stringify({ role, is_active: true }),
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

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Platform Settings & Role-Based User Administration
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage platform accounts, RBAC role assignments (`admin`, `analyst`, `developer`, `viewer`), and demo database state.
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

      {/* RBAC Matrix Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {(data?.rbac_matrix || []).map((rm: any) => (
          <div key={rm.role} className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-mono text-xs uppercase font-bold">
                {rm.role}
              </span>
              <span className="text-[11px] font-mono text-slate-400">{rm.default_account}</span>
            </div>
            <div className="font-bold text-sm text-white">{rm.label}</div>
            <ul className="space-y-1.5 text-xs text-slate-300">
              {(rm.permissions || []).map((p: string, idx: number) => (
                <li key={idx} className="flex items-start gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{p}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* Add User Form (Admin Only) */}
      {canMutate(['admin']) && (
        <form
          onSubmit={handleCreateUser}
          className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-end gap-3 text-xs"
        >
          <div className="flex-1 min-w-[200px]">
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
          <div className="flex-1 min-w-[200px]">
            <label className="block text-slate-400 mb-1">Email Address</label>
            <input
              type="email"
              required
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              placeholder="jordan@sentinel.local"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
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
            Add User
          </button>
        </form>
      )}

      {/* Users Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-slate-800 flex items-center gap-2">
          <Users className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white">Registered Platform Users</h3>
        </div>
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <th className="py-3 px-4">Name</th>
              <th className="py-3 px-3">Email</th>
              <th className="py-3 px-3">RBAC Role</th>
              <th className="py-3 px-3">Last Login</th>
              <th className="py-3 px-4 text-right">Modify Role (Admin)</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {(data?.users || []).map((u: any) => (
              <tr key={u.id} className="hover:bg-slate-800/40">
                <td className="py-3 px-4 font-semibold text-white">{u.full_name}</td>
                <td className="py-3 px-3 font-mono text-cyan-300">{u.email}</td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-200 font-mono uppercase text-[11px]">
                    {u.role}
                  </span>
                </td>
                <td className="py-3 px-3 font-mono text-slate-400">
                  {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'Never'}
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
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
