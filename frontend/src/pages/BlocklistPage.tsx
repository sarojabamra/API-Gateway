import React, { useEffect, useState } from 'react';
import { ShieldAlert, Trash2, Plus } from 'lucide-react';
import { apiFetch, formatDateTimeIST } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OwaspBadge } from '../components/shared/Badges';

export const BlocklistPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [targetType, setTargetType] = useState('ip');
  const [targetValue, setTargetValue] = useState('');
  const [reason, setReason] = useState('Manual SOC Analyst block');
  const [owaspId, setOwaspId] = useState('API2');
  const [duration, setDuration] = useState(1440);

  const fetchBlocklist = async () => {
    try {
      const res = await apiFetch('/blocklist');
      setData(res);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchBlocklist();
  }, []);

  const handleAddBlock = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim()) return;
    try {
      await apiFetch('/blocklist', {
        method: 'POST',
        body: JSON.stringify({
          target_type: targetType,
          value: targetValue.trim(),
          reason,
          owasp_id: owaspId,
          duration_minutes: duration,
        }),
      });
      addToast({
        title: 'Added to Blocklist',
        message: `Blocked ${targetType}=${targetValue}`,
        severity: 'info',
      });
      setTargetValue('');
      fetchBlocklist();
    } catch (err: any) {
      addToast({ title: 'Block Failed', message: err.message, severity: 'high' });
    }
  };

  const handleUnblock = async (id: number) => {
    try {
      await apiFetch(`/blocklist/${id}`, { method: 'DELETE' });
      addToast({ title: 'Entry Unblocked', message: `Removed block #${id}`, severity: 'info' });
      fetchBlocklist();
    } catch (err: any) {
      addToast({ title: 'Unblock Failed', message: err.message, severity: 'high' });
    }
  };

  const handleToggleAutoBlock = async () => {
    try {
      const next = !data?.auto_block_critical;
      await apiFetch('/blocklist/auto-config', {
        method: 'PUT',
        body: JSON.stringify({
          auto_block_critical: next,
          auto_block_duration_minutes: 60,
        }),
      });
      addToast({
        title: next ? 'Auto-Block Enabled' : 'Auto-Block Disabled',
        message: next
          ? 'Critical alerts will now automatically ban offending IPs for 60m'
          : 'Critical alerts require analyst confirmation before blocking',
        severity: 'info',
      });
      fetchBlocklist();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Active Blocklist & Automated Defense</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Fast-reject (`Stage 3 - 403 Forbidden`) for blocked Client IPs, User `sub` principals, and compromised API keys.
          </p>
        </div>

        {/* Auto-Block Toggle */}
        <div className="flex items-center gap-3 p-3 rounded-xl bg-slate-900 border border-slate-800 text-xs">
          <ShieldAlert className="w-4 h-4 text-rose-400" />
          <div>
            <div className="font-semibold text-white">Auto-Block on Critical Alerts</div>
            <div className="text-[11px] text-slate-400">60-minute automatic IP quarantine</div>
          </div>
          {canMutate(['admin', 'analyst']) && (
            <button
              onClick={handleToggleAutoBlock}
              className={`px-3 py-1 rounded-lg font-mono text-xs font-bold border transition ${
                data?.auto_block_critical
                  ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                  : 'bg-slate-950 text-slate-400 border-slate-800'
              }`}
            >
              {data?.auto_block_critical ? 'ON' : 'OFF'}
            </button>
          )}
        </div>
      </div>

      {/* Add Block Form */}
      {canMutate(['admin', 'analyst']) && (
        <form
          onSubmit={handleAddBlock}
          className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-end gap-3 text-xs"
        >
          <div>
            <label className="block text-slate-400 mb-1">Target Type</label>
            <select
              value={targetType}
              onChange={(e) => setTargetType(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
            >
              <option value="ip">Client IP Address</option>
              <option value="user_sub">JWT Principal (sub)</option>
              <option value="api_key">API Key ID</option>
            </select>
          </div>
          <div className="w-48">
            <label className="block text-slate-400 mb-1">Value to Block</label>
            <input
              type="text"
              required
              value={targetValue}
              onChange={(e) => setTargetValue(e.target.value)}
              placeholder="e.g., 203.0.113.99 or user-102"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
            />
          </div>
          <div className="flex-1 min-w-[200px]">
            <label className="block text-slate-400 mb-1">Block Reason</label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
            />
          </div>
          <div>
            <label className="block text-slate-400 mb-1">OWASP Tag</label>
            <select
              value={owaspId}
              onChange={(e) => setOwaspId(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
            >
              {['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9'].map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-slate-400 mb-1">Duration</label>
            <select
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white"
            >
              <option value={15}>15 Minutes</option>
              <option value={60}>1 Hour</option>
              <option value={1440}>24 Hours</option>
              <option value={10080}>7 Days</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-1.5 rounded-lg bg-rose-500 hover:bg-rose-400 text-white font-semibold inline-flex items-center gap-1"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Block
          </button>
        </form>
      )}

      {/* Blocklist Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-3">Type & Target Value</th>
              <th className="py-3 px-3">Reason</th>
              <th className="py-3 px-3">OWASP</th>
              <th className="py-3 px-3">Source & Author</th>
              <th className="py-3 px-3">Expires At (IST)</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/70">
            {(data?.items || []).map((b: any) => (
              <tr key={b.id} className={!b.active ? 'opacity-50' : 'hover:bg-slate-800/40'}>
                <td className="py-3 px-4">
                  {b.active ? (
                    <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-mono text-[10px]">
                      BLOCKING
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
                      UNBLOCKED
                    </span>
                  )}
                </td>
                <td className="py-3 px-3 font-mono">
                  <span className="uppercase text-[10px] text-slate-400 mr-1.5">[{b.target_type}]</span>
                  <span className="font-bold text-white">{b.value}</span>
                </td>
                <td className="py-3 px-3 text-slate-300">{b.reason}</td>
                <td className="py-3 px-3">
                  <OwaspBadge owaspId={b.owasp_id} />
                </td>
                <td className="py-3 px-3 font-mono text-slate-400">
                  {b.source} ({b.created_by})
                </td>
                <td className="py-3 px-3 font-mono text-slate-400">
                  {b.expires_at ? formatDateTimeIST(b.expires_at) : 'Permanent'}
                </td>
                <td className="py-3 px-4 text-right">
                  {b.active && canMutate(['admin', 'analyst']) && (
                    <button
                      onClick={() => handleUnblock(b.id)}
                      className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs"
                    >
                      <Trash2 className="w-3 h-3" />
                      Unblock
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
