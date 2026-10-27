import React, { useEffect, useState } from 'react';
import { Plus, Shield, Eye, Power, X } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OwaspBadge } from '../components/shared/Badges';

export const PoliciesPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [policies, setPolicies] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);

  const [newName, setNewName] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newType, setNewType] = useState('signature');
  const [newOwasp, setNewOwasp] = useState('API8');
  const [newMode, setNewMode] = useState('enforce');
  const [newConfigText, setNewConfigText] = useState('{"custom_rule": true}');

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const res = await apiFetch('/policies');
      setPolicies(res || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleToggleMode = async (pol: any, nextMode: 'enforce' | 'monitor') => {
    try {
      await apiFetch(`/policies/${pol.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ mode: nextMode, enabled: true }),
      });
      addToast({
        title: `Policy Mode Updated`,
        message: `'${pol.name}' set to ${nextMode.toUpperCase()} mode`,
        severity: 'info',
      });
      fetchPolicies();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    }
  };

  const handleToggleEnabled = async (pol: any) => {
    try {
      await apiFetch(`/policies/${pol.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ enabled: !pol.enabled }),
      });
      addToast({
        title: pol.enabled ? 'Policy Disabled' : 'Policy Enabled',
        message: `${pol.name}`,
        severity: 'info',
      });
      fetchPolicies();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const parsedConfig = JSON.parse(newConfigText || '{}');
      await apiFetch('/policies', {
        method: 'POST',
        body: JSON.stringify({
          name: newName,
          description: newDesc,
          type: newType,
          scope: 'global',
          owasp_id: newOwasp,
          mode: newMode,
          config: parsedConfig,
          enabled: true,
        }),
      });
      addToast({
        title: 'Policy Created',
        message: `Added ${newName} (${newOwasp})`,
        severity: 'info',
      });
      setModalOpen(false);
      setNewName('');
      setNewDesc('');
      fetchPolicies();
    } catch (err: any) {
      addToast({ title: 'Creation Failed', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Policy Engine & Dry-Run Controls</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Configure OWASP API Top 10 enforcement rules. Switch any policy between <strong>Enforce (Block)</strong> and <strong>Monitor (Dry-Run Log Only)</strong> to eliminate false positives safely.
          </p>
        </div>
        {canMutate(['admin', 'analyst', 'developer']) && (
          <button
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
          >
            <Plus className="w-4 h-4" />
            Create Security Policy
          </button>
        )}
      </div>

      {/* Policies Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {loading && policies.length === 0 ? (
          <div className="col-span-2 py-12 text-center text-slate-400 text-sm">Loading policies...</div>
        ) : (
          policies.map((pol) => (
            <div
              key={pol.id}
              className={`p-5 rounded-xl border transition flex flex-col justify-between ${
                !pol.enabled
                  ? 'bg-slate-900/40 border-slate-800/60 opacity-65'
                  : pol.mode === 'enforce'
                  ? 'bg-slate-900/90 border-slate-800'
                  : 'bg-slate-900/90 border-sky-500/30'
              }`}
            >
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <OwaspBadge owaspId={pol.owasp_id} />
                    <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      type: {pol.type}
                    </span>
                    <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      scope: {pol.scope}
                    </span>
                  </div>

                  {/* Enable / Disable Button */}
                  {canMutate(['admin', 'analyst', 'developer']) && (
                    <button
                      onClick={() => handleToggleEnabled(pol)}
                      className={`px-2.5 py-1 rounded text-[11px] font-mono uppercase border transition inline-flex items-center gap-1 ${
                        pol.enabled
                          ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                          : 'bg-slate-800 text-slate-400 border-slate-700'
                      }`}
                    >
                      <Power className="w-3 h-3" />
                      {pol.enabled ? 'Enabled' : 'Disabled'}
                    </button>
                  )}
                </div>

                <h3 className="text-base font-bold text-white mt-3">{pol.name}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{pol.description}</p>

                <pre className="mt-3 text-[11px] font-mono text-slate-300 bg-slate-950 p-2.5 rounded-lg border border-slate-800 overflow-x-auto">
                  {JSON.stringify(pol.config, null, 2)}
                </pre>
              </div>

              {/* Enforce vs Monitor (Dry-Run) Mode Selector */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-xs text-slate-400">Enforcement Mode:</span>
                <div className="flex items-center gap-2">
                  <button
                    disabled={!canMutate(['admin', 'analyst', 'developer'])}
                    onClick={() => handleToggleMode(pol, 'enforce')}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition ${
                      pol.enabled && pol.mode === 'enforce'
                        ? 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <Shield className="w-3.5 h-3.5" />
                    Enforce (Block)
                  </button>
                  <button
                    disabled={!canMutate(['admin', 'analyst', 'developer'])}
                    onClick={() => handleToggleMode(pol, 'monitor')}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-semibold border transition ${
                      pol.enabled && pol.mode === 'monitor'
                        ? 'bg-sky-500/20 text-sky-300 border-sky-500/40'
                        : 'bg-slate-950 text-slate-400 border-slate-800 hover:text-slate-200'
                    }`}
                  >
                    <Eye className="w-3.5 h-3.5" />
                    Monitor (Dry-Run)
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Create Policy Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-base font-bold text-white">Create Custom Security Policy</h3>
              <button onClick={() => setModalOpen(false)} className="text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleCreatePolicy} className="space-y-4 mt-4 text-xs">
              <div>
                <label className="block text-slate-300 mb-1">Policy Name</label>
                <input
                  type="text"
                  required
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g., GeoIP High-Risk ASN Filter"
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-300 mb-1">Description</label>
                <input
                  type="text"
                  required
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  placeholder="Blocks or monitors anomalous requests..."
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
                />
              </div>
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Policy Type</label>
                  <select
                    value={newType}
                    onChange={(e) => setNewType(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-white"
                  >
                    <option value="signature">signature</option>
                    <option value="rate_limit">rate_limit</option>
                    <option value="bola">bola</option>
                    <option value="bfla">bfla</option>
                    <option value="ssrf">ssrf</option>
                    <option value="field_redaction">field_redaction</option>
                    <option value="size_limit">size_limit</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">OWASP Category</label>
                  <select
                    value={newOwasp}
                    onChange={(e) => setNewOwasp(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-white"
                  >
                    {['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9'].map((o) => (
                      <option key={o} value={o}>
                        {o}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Initial Mode</label>
                  <select
                    value={newMode}
                    onChange={(e) => setNewMode(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-2 text-white"
                  >
                    <option value="enforce">Enforce (Block)</option>
                    <option value="monitor">Monitor (Dry-Run)</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-slate-300 mb-1">JSON Rule Configuration</label>
                <textarea
                  rows={3}
                  value={newConfigText}
                  onChange={(e) => setNewConfigText(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-cyan-300"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setModalOpen(false)}
                  className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-semibold"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
