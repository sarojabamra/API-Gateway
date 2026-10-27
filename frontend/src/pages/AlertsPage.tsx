import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckSquare, RefreshCw, ShieldAlert } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OwaspBadge, SeverityBadge } from '../components/shared/Badges';
import { AlertItem } from '../types/api';

export const AlertsPage: React.FC = () => {
  const { addToast, canMutate, liveAlerts } = useGatewayStore();
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [summary, setSummary] = useState<any>({});
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [owaspFilter, setOwaspFilter] = useState('');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchAlerts = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter) params.set('severity', severityFilter);
      if (statusFilter) params.set('status', statusFilter);
      if (owaspFilter) params.set('owasp_id', owaspFilter);
      const res = await apiFetch(`/alerts?${params.toString()}`);
      setAlerts(res.items || []);
      setSummary(res.summary || {});
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [severityFilter, statusFilter, owaspFilter, liveAlerts.length]);

  const toggleSelect = (id: number) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const handleBulkStatus = async (status: string) => {
    if (selectedIds.length === 0) return;
    try {
      await apiFetch('/alerts/bulk', {
        method: 'POST',
        body: JSON.stringify({ alert_ids: selectedIds, status }),
      });
      addToast({
        title: 'Bulk Incident Update',
        message: `Updated ${selectedIds.length} alert(s) to '${status}'`,
        severity: 'info',
      });
      setSelectedIds([]);
      fetchAlerts();
    } catch (err: any) {
      addToast({ title: 'Bulk Action Failed', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts & Incident Queue</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Deduplicated OWASP threat detections with status workflow, bulk triage, and AI-assisted forensics.
          </p>
        </div>
        <button
          onClick={fetchAlerts}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh Queue
        </button>
      </div>

      {/* Status Summary Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {[
          { label: 'Open Incidents', val: summary.open || 0, color: 'text-rose-400 border-rose-500/30' },
          { label: 'Investigating', val: summary.investigating || 0, color: 'text-amber-300 border-amber-500/30' },
          { label: 'Resolved', val: summary.resolved || 0, color: 'text-emerald-400 border-emerald-500/30' },
          { label: 'False Positives', val: summary.false_positive || 0, color: 'text-slate-400 border-slate-700' },
          { label: 'Critical / High Open', val: `${summary.critical || 0} / ${summary.high || 0}`, color: 'text-orange-400 border-orange-500/30' },
        ].map((s) => (
          <div key={s.label} className={`p-3.5 rounded-xl bg-slate-900/90 border ${s.color}`}>
            <div className="text-xs text-slate-400">{s.label}</div>
            <div className="text-xl font-bold font-mono mt-1">{s.val}</div>
          </div>
        ))}
      </div>

      {/* Filter & Bulk Action Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
          </select>

          <select
            value={owaspFilter}
            onChange={(e) => setOwaspFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
          >
            <option value="">All OWASP Categories</option>
            {['API1', 'API2', 'API3', 'API4', 'API5', 'API6', 'API7', 'API8', 'API9'].map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </div>

        {canMutate(['admin', 'analyst']) && selectedIds.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400">
              {selectedIds.length} selected:
            </span>
            <button
              onClick={() => handleBulkStatus('investigating')}
              className="px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-medium"
            >
              Mark Investigating
            </button>
            <button
              onClick={() => handleBulkStatus('resolved')}
              className="px-2.5 py-1 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-medium"
            >
              Resolve Selected
            </button>
            <button
              onClick={() => handleBulkStatus('false_positive')}
              className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 border border-slate-700 text-xs font-medium"
            >
              False Positive
            </button>
          </div>
        )}
      </div>

      {/* Alerts Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-3 px-4 w-8">
                  <CheckSquare className="w-3.5 h-3.5 text-slate-500" />
                </th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">OWASP</th>
                <th className="py-3 px-3">Incident Title & Target</th>
                <th className="py-3 px-3">Offender IP / Sub</th>
                <th className="py-3 px-3">Events</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-4 text-right">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading && alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    Loading alerts...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400">
                    No security alerts match the current filters.
                  </td>
                </tr>
              ) : (
                alerts.map((a) => (
                  <tr
                    key={a.id}
                    onClick={() => navigate(`/alerts/${a.id}`)}
                    className="hover:bg-slate-800/60 cursor-pointer transition"
                  >
                    <td
                      className="py-3 px-4"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleSelect(a.id);
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={selectedIds.includes(a.id)}
                        onChange={() => {}}
                        className="rounded border-slate-700 bg-slate-950"
                      />
                    </td>
                    <td className="py-3 px-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="py-3 px-3" onClick={(e) => e.stopPropagation()}>
                      <OwaspBadge owaspId={a.owasp_id} />
                    </td>
                    <td className="py-3 px-3">
                      <div className="font-semibold text-white">{a.title}</div>
                      <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                        Target: {a.target_path} · Type: {a.type}
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      <div className="text-slate-200">{a.client_ip}</div>
                      {a.user_sub && <div className="text-[10px] text-cyan-400">{a.user_sub}</div>}
                    </td>
                    <td className="py-3 px-3 font-mono font-bold text-slate-200">
                      {a.event_count}x
                    </td>
                    <td className="py-3 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase ${
                          a.status === 'open'
                            ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30'
                            : a.status === 'investigating'
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : a.status === 'resolved'
                            ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {a.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right font-mono text-slate-400 whitespace-nowrap">
                      {new Date(a.ts).toLocaleTimeString()}
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
