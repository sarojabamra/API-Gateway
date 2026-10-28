import React, { useEffect, useState } from 'react';
import { X, Ban, KeyRound, ExternalLink, CheckCircle2, XCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { apiFetch, formatDateTimeIST } from '../../lib/api';
import { useGatewayStore } from '../../store/useGatewayStore';
import { DecisionBadge, MethodBadge, OwaspBadge } from './Badges';

export const RequestDetailDrawer: React.FC = () => {
  const { selectedRequestId, closeRequestDrawer, addToast, canMutate } = useGatewayStore();
  const [detail, setDetail] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const loadRequestDetails = async () => {
      if (!selectedRequestId) {
        setDetail(null);
        return;
      }
      setLoading(true);
      try {
        const res = await apiFetch(`/traffic/${selectedRequestId}`);
        setDetail(res);
      } catch {
        setDetail(null);
      } finally {
        setLoading(false);
      }
    };

    loadRequestDetails();
  }, [selectedRequestId]);

  if (!selectedRequestId) return null;

  const handleBlockIp = async () => {
    if (!detail) return;
    try {
      await apiFetch('/blocklist', {
        method: 'POST',
        body: JSON.stringify({
          target_type: 'ip',
          value: detail.client_ip,
          reason: `Blocked from Request Details (${detail.request_id})`,
          owasp_id: detail.owasp_id || 'API2',
          duration_minutes: 1440,
        }),
      });
      addToast({
        title: 'IP Blocked',
        message: `Blocked ${detail.client_ip} for 24 hours`,
        severity: 'info',
      });
    } catch (err: any) {
      addToast({ title: 'Could Not Block IP', message: err.message, severity: 'high' });
    }
  };

  const handleRevokeJti = async () => {
    const jti = detail?.decoded_jwt?.payload?.jti;
    if (!jti) return;
    try {
      await apiFetch('/auth/revoked-tokens', {
        method: 'POST',
        body: JSON.stringify({
          jti,
          user_sub: detail?.user_sub || 'unknown',
          reason: `Revoked from Request Details (${detail.request_id})`,
        }),
      });
      addToast({
        title: 'Token Revoked',
        message: `Token ${jti} is now blocked`,
        severity: 'info',
      });
    } catch (err: any) {
      addToast({ title: 'Could Not Revoke Token', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-slate-950/75 backdrop-blur-sm">
      <div className="w-full max-w-2xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto p-6 shadow-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Request Details
            </span>
            <h3 className="text-lg font-semibold text-white font-mono mt-0.5">
              {detail?.request_id || `Request #${selectedRequestId}`}
            </h3>
          </div>
          <button
            onClick={closeRequestDrawer}
            className="p-2 rounded-lg bg-slate-800/80 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading && (
          <div className="py-16 text-center text-slate-400 text-sm">
            Loading request details...
          </div>
        )}

        {!loading && detail && (
          <div className="space-y-6 mt-5">
            {/* Decision Banner */}
            <div
              className={`p-4 rounded-xl border ${
                detail.decision === 'blocked'
                  ? 'bg-rose-950/30 border-rose-500/40'
                  : detail.decision === 'rate_limited'
                  ? 'bg-amber-950/30 border-amber-500/40'
                  : 'bg-emerald-950/20 border-emerald-500/30'
              }`}
            >
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2.5">
                  <DecisionBadge decision={detail.decision} />
                  <MethodBadge method={detail.method} />
                  <span className="font-mono text-sm text-white font-semibold">
                    {detail.path}
                    {detail.query_params ? `?${detail.query_params}` : ''}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <OwaspBadge owaspId={detail.owasp_id} />
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-200">
                    HTTP {detail.status_code} · {detail.latency_ms} ms
                  </span>
                </div>
              </div>
              {detail.block_reason && (
                <p className="mt-2.5 text-xs font-mono text-slate-200 bg-slate-950/60 p-2.5 rounded border border-slate-800">
                  {detail.block_reason}
                </p>
              )}
            </div>

            {/* Quick Response Actions */}
            <div className="flex flex-wrap items-center gap-2.5">
              {canMutate(['admin', 'analyst']) && (
                <button
                  onClick={handleBlockIp}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 transition"
                >
                  <Ban className="w-3.5 h-3.5" />
                  Block IP ({detail.client_ip})
                </button>
              )}
              {canMutate(['admin', 'analyst', 'developer']) && detail.decoded_jwt?.payload?.jti && (
                <button
                  onClick={handleRevokeJti}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 transition"
                >
                  <KeyRound className="w-3.5 h-3.5" />
                  Block This Token ({detail.decoded_jwt.payload.jti})
                </button>
              )}
              {detail.linked_alert_id && (
                <button
                  onClick={() => {
                    const aid = detail.linked_alert_id;
                    closeRequestDrawer();
                    navigate(`/alerts/${aid}`);
                  }}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 transition"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                  View Related Alert #{detail.linked_alert_id}
                </button>
              )}
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Sender IP</div>
                <div className="font-mono text-slate-100 mt-1 font-semibold">{detail.client_ip}</div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Logged-In User</div>
                <div className="font-mono text-slate-100 mt-1">
                  {detail.user_sub || 'Guest / None'} ({detail.user_role || 'none'})
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Risk Score</div>
                <div className="font-mono text-slate-100 mt-1">
                  Score: <span className="text-rose-400 font-bold">{detail.threat_score}/100</span>
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Security Rule Triggered</div>
                <div className="text-slate-100 mt-1 truncate">
                  {detail.matched_policy_name || 'Standard Route Check'}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Request / Response Size</div>
                <div className="font-mono text-slate-100 mt-1">
                  {detail.req_size_bytes} B / {detail.resp_size_bytes} B
                </div>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400">Time (IST)</div>
                <div className="font-mono text-slate-100 mt-1">
                  {formatDateTimeIST(detail.ts)}
                </div>
              </div>
            </div>

            {/* Decoded JWT Claims & Checklist */}
            {detail.decoded_jwt && Object.keys(detail.decoded_jwt).length > 0 && (
              <div className="rounded-xl bg-slate-950 border border-slate-800 p-4">
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                  JWT Token Check Results
                </h4>
                <pre className="text-xs font-mono text-cyan-300 overflow-x-auto bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                  {JSON.stringify(
                    {
                      header: detail.decoded_jwt.header,
                      payload: detail.decoded_jwt.payload,
                    },
                    null,
                    2
                  )}
                </pre>
                {Array.isArray(detail.decoded_jwt.steps) && (
                  <div className="mt-3 space-y-1.5">
                    {detail.decoded_jwt.steps.map((st: any) => (
                      <div
                        key={st.step}
                        className="flex items-start gap-2 text-xs p-2 rounded bg-slate-900 border border-slate-800/80"
                      >
                        {st.passed ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                        ) : (
                          <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                        )}
                        <div>
                          <span className="font-semibold text-slate-200">
                            Check {st.step}: {st.name}
                          </span>
                          <p className="text-slate-400 font-mono text-[11px]">{st.detail}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Sanitized Request Headers */}
            <div className="rounded-xl bg-slate-950 border border-slate-800 p-4">
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Request Headers (Secrets Hidden)
              </h4>
              <pre className="text-xs font-mono text-slate-300 overflow-x-auto bg-slate-900 p-3 rounded-lg border border-slate-800">
                {JSON.stringify(detail.request_headers, null, 2)}
              </pre>
            </div>

            {/* Request & Response Body Previews */}
            <div className="grid grid-cols-1 gap-4">
              {detail.request_body_preview && (
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    Request Body Sent by Client
                  </h4>
                  <pre className="text-xs font-mono text-amber-300 overflow-x-auto bg-slate-900 p-3 rounded-lg border border-slate-800 whitespace-pre-wrap">
                    {detail.request_body_preview}
                  </pre>
                </div>
              )}
              {detail.response_body_preview && (
                <div className="rounded-xl bg-slate-950 border border-slate-800 p-4">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                    Response Returned to Client
                  </h4>
                  <pre className="text-xs font-mono text-emerald-300 overflow-x-auto bg-slate-900 p-3 rounded-lg border border-slate-800 whitespace-pre-wrap">
                    {detail.response_body_preview}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
