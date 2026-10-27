import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import {
  ArrowLeft,
  Sparkles,
  Ban,
  UserX,
  KeyRound,
  CheckCircle2,
  Sliders,
  MessageSquarePlus,
  Eye,
} from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { DecisionBadge, MethodBadge, OwaspBadge, SeverityBadge } from '../components/shared/Badges';

export const AlertDetailPage: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { addToast, canMutate, openRequestDrawer } = useGatewayStore();
  const [alert, setAlert] = useState<any | null>(null);
  const [noteText, setNoteText] = useState('');
  const [loading, setLoading] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);

  const fetchDetail = async () => {
    setLoading(true);
    try {
      const res = await apiFetch(`/alerts/${id}`);
      setAlert(res);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [id]);

  const runAction = async (payload: any, toastMsg: string) => {
    setActionBusy(true);
    try {
      const res = await apiFetch(`/alerts/${id}/actions`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      setAlert(res);
      addToast({ title: 'Incident Action Executed', message: toastMsg, severity: 'info' });
    } catch (err: any) {
      addToast({ title: 'Action Failed', message: err.message, severity: 'high' });
    } finally {
      setActionBusy(false);
    }
  };

  if (loading && !alert) {
    return <div className="py-16 text-center text-slate-400 text-sm">Loading incident forensics...</div>;
  }
  if (!alert) {
    return <div className="py-16 text-center text-slate-400 text-sm">Alert not found.</div>;
  }

  const ai = alert.ai_summary || {};
  const offender = alert.offender_profile || {};

  return (
    <div className="space-y-6">
      {/* Top Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/alerts')}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-400 hover:text-white"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <div className="flex items-center gap-2.5">
              <SeverityBadge severity={alert.severity} />
              <OwaspBadge owaspId={alert.owasp_id} />
              <span className="text-xs font-mono text-slate-400">
                Incident #{alert.id} · {alert.event_count} correlated events
              </span>
            </div>
            <h1 className="text-xl font-bold text-white mt-1">{alert.title}</h1>
          </div>
        </div>

        {/* Status Workflow Selector */}
        {canMutate(['admin', 'analyst']) && (
          <div className="flex items-center gap-2">
            {(['open', 'investigating', 'resolved', 'false_positive'] as const).map((st) => (
              <button
                key={st}
                disabled={actionBusy}
                onClick={() => runAction({ action: 'update_status', status: st }, `Status changed to ${st}`)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono uppercase border transition ${
                  alert.status === st
                    ? 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40 font-bold'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-white'
                }`}
              >
                {st.replace('_', ' ')}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Main Grid: AI Triage Panel + Offender Profile & Containment Actions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* AI Triage Panel */}
        <div className="lg:col-span-8 bg-gradient-to-br from-slate-900 via-slate-900 to-indigo-950/30 border border-indigo-500/30 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="p-2 rounded-lg bg-indigo-500/20 border border-indigo-500/40 text-indigo-300">
                <Sparkles className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-white">
                  AI-Assisted Threat Triage & Remediation
                </h3>
                <p className="text-[11px] font-mono text-indigo-300">
                  {ai.engine || 'SentinelAI Neural Threat Triage Engine'} · Confidence: {ai.confidence_score || 95}%
                </p>
              </div>
            </div>
            {canMutate(['admin', 'analyst']) && (
              <button
                disabled={actionBusy}
                onClick={() => runAction({ action: 'ai_triage' }, 'Regenerated AI Triage Analysis')}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-200 border border-indigo-500/40 transition"
              >
                Regenerate AI Triage
              </button>
            )}
          </div>

          <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 text-xs text-slate-200 leading-relaxed">
            <div className="text-[10px] font-mono uppercase text-cyan-400 mb-1">Executive Summary</div>
            {ai.executive_summary || alert.description}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <div className="text-[10px] font-mono uppercase text-amber-400 mb-1">
                Upstream Root Cause Analysis
              </div>
              <p className="text-slate-300">{ai.root_cause_analysis}</p>
            </div>
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <div className="text-[10px] font-mono uppercase text-rose-400 mb-1">
                Blast Radius & Impact Assessment
              </div>
              <p className="text-slate-300">{ai.blast_radius}</p>
            </div>
          </div>

          {Array.isArray(ai.recommended_actions) && (
            <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
              <div className="text-[10px] font-mono uppercase text-emerald-400 mb-2">
                Recommended SOC & Engineering Remediations
              </div>
              <ul className="space-y-1.5 text-xs text-slate-200">
                {ai.recommended_actions.map((step: string, idx: number) => (
                  <li key={idx} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Offender Profile & 1-Click Containment Actions */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-5">
          <div className="space-y-4">
            <h3 className="text-sm font-bold text-white">Offender Profile & Active Response</h3>
            <div className="grid grid-cols-2 gap-2.5 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Source IP</div>
                <div className="font-mono font-bold text-white mt-0.5">{offender.client_ip}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Principal Sub</div>
                <div className="font-mono text-cyan-300 mt-0.5">{offender.user_sub || 'anonymous'}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Blocked / Total</div>
                <div className="font-mono text-rose-400 font-bold mt-0.5">
                  {offender.blocked_requests} / {offender.total_requests}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Anomaly Z-Score</div>
                <div className="font-mono text-amber-300 font-bold mt-0.5">
                  Z = {offender.anomaly_zscore} ({offender.mean_rpm} RPM avg)
                </div>
              </div>
            </div>

            {canMutate(['admin', 'analyst']) ? (
              <div className="space-y-2 pt-2">
                <div className="text-[10px] font-mono uppercase text-slate-400">
                  One-Click Containment Actions
                </div>
                <button
                  disabled={actionBusy || offender.is_ip_blocked}
                  onClick={() =>
                    runAction(
                      { action: 'block_ip', block_duration_minutes: 1440 },
                      `Blocked IP ${offender.client_ip} for 24h`
                    )
                  }
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 disabled:opacity-50 transition"
                >
                  <Ban className="w-3.5 h-3.5" />
                  {offender.is_ip_blocked
                    ? `IP ${offender.client_ip} Already Blocked`
                    : `Block IP ${offender.client_ip} (24h)`}
                </button>

                {offender.user_sub && (
                  <button
                    disabled={actionBusy}
                    onClick={() =>
                      runAction(
                        { action: 'block_user', block_duration_minutes: 1440 },
                        `Blocked principal ${offender.user_sub}`
                      )
                    }
                    className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold bg-orange-500/20 hover:bg-orange-500/30 text-orange-300 border border-orange-500/40 transition"
                  >
                    <UserX className="w-3.5 h-3.5" />
                    Block Principal ({offender.user_sub})
                  </button>
                )}

                <button
                  disabled={actionBusy}
                  onClick={() =>
                    runAction({ action: 'revoke_token' }, 'Added token JTI to revocation blacklist')
                  }
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 transition"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  Revoke Associated JWT Token (JTI)
                </button>

                <button
                  disabled={actionBusy}
                  onClick={() =>
                    runAction(
                      { action: 'create_exception' },
                      `Marked False Positive & switched ${alert.owasp_id} policy to Monitor Mode`
                    )
                  }
                  className="w-full flex items-center justify-center gap-2 py-2 px-3 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
                >
                  <Sliders className="w-3.5 h-3.5" />
                  Create Exception (Switch Policy to Monitor)
                </button>
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-400">
                Read-only view: Switch to <strong>Admin</strong> or <strong>Analyst</strong> persona in the topbar to execute containment actions.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Correlated Request Timeline & Analyst Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Timeline of Related Requests */}
        <div className="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-3">
            Forensic Timeline of Correlated Requests ({alert.timeline?.length || 0})
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 pr-2">Time</th>
                  <th className="py-2 px-2">Req ID</th>
                  <th className="py-2 px-2">Decision</th>
                  <th className="py-2 px-2">Endpoint</th>
                  <th className="py-2 px-2">Diagnostic Reason</th>
                  <th className="py-2 pl-2 text-right">Inspect</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(alert.timeline || []).map((r: any) => (
                  <tr
                    key={r.request_id}
                    onClick={() => openRequestDrawer(r.id)}
                    className="hover:bg-slate-800/60 cursor-pointer"
                  >
                    <td className="py-2.5 pr-2 font-mono text-slate-400 whitespace-nowrap">
                      {new Date(r.ts).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 px-2 font-mono text-cyan-300">{r.request_id}</td>
                    <td className="py-2.5 px-2">
                      <DecisionBadge decision={r.decision} />
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-1.5">
                        <MethodBadge method={r.method} />
                        <span className="font-mono text-slate-200">
                          {r.path}
                          {r.query_params ? `?${r.query_params}` : ''}
                        </span>
                      </div>
                    </td>
                    <td className="py-2.5 px-2 text-slate-300 max-w-xs truncate">
                      {r.block_reason || 'Allowed'}
                    </td>
                    <td className="py-2.5 pl-2 text-right">
                      <button className="p-1 rounded bg-slate-800 text-cyan-400">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Analyst Investigation Notes */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white mb-3">SOC Investigation Log & Notes</h3>
            <div className="space-y-2.5 max-h-64 overflow-y-auto pr-1">
              {(alert.notes || []).length === 0 ? (
                <div className="text-xs text-slate-500 py-6 text-center">
                  No investigation notes recorded yet.
                </div>
              ) : (
                (alert.notes || []).map((n: any, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mb-1">
                      <span className="text-cyan-400">{n.author}</span>
                      <span>{new Date(n.ts).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-slate-200">{n.text}</div>
                  </div>
                ))
              )}
            </div>
          </div>

          {canMutate(['admin', 'analyst']) && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (!noteText.trim()) return;
                runAction({ action: 'add_note', note: noteText.trim() }, 'Added investigation note');
                setNoteText('');
              }}
              className="mt-4 flex gap-2"
            >
              <input
                type="text"
                value={noteText}
                onChange={(e) => setNoteText(e.target.value)}
                placeholder="Add forensic note..."
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white"
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs inline-flex items-center gap-1"
              >
                <MessageSquarePlus className="w-3.5 h-3.5" />
                Add
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
