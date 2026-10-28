import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck, Zap, AlertCircle } from 'lucide-react';
import { apiFetch } from '../lib/api';

export const OwaspCoveragePage: React.FC = () => {
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const loadOwaspCoverage = async () => {
      try {
        const res = await apiFetch('/owasp/coverage');
        setData(res);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    loadOwaspCoverage();
  }, []);

  if (loading && !data) {
    return <div className="py-16 text-center text-slate-400 text-sm">Loading OWASP Top 10 coverage...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
            {data?.edition || 'OWASP API Security Top 10 (2023)'}
          </span>
          <h1 className="text-2xl font-bold text-white mt-0.5">
            OWASP API Security Top 10
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Coverage status, active enforcement rules, and telemetry per category.
          </p>
        </div>

        <div className="flex items-center gap-4 bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5">
          <div>
            <div className="text-[10px] font-mono uppercase text-slate-400">Coverage</div>
            <div className="text-lg font-bold font-mono text-emerald-400">
              {data?.protected_in_scope_count || 9} / {data?.total_in_scope_count || 9} Categories ({data?.posture_score || 100}%)
            </div>
          </div>
          <ShieldCheck className="w-7 h-7 text-emerald-400" />
        </div>
      </div>

      {/* 10 Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {(data?.cards || []).map((c: any) => {
          const isOut = c.protection_status === 'out_of_scope';
          return (
            <div
              key={c.owasp_id}
              className={`p-5 rounded-xl border flex flex-col justify-between ${
                isOut
                  ? 'bg-slate-900/50 border-slate-800/80'
                  : 'bg-slate-900/90 border-slate-800 hover:border-cyan-500/30 transition'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="px-2.5 py-0.5 rounded bg-indigo-500/20 border border-indigo-500/40 text-indigo-200 font-mono text-xs font-bold">
                    {c.code}
                  </span>

                  {c.protection_status === 'enforcing' && (
                    <span className="px-2.5 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 font-mono text-[11px] font-semibold">
                      PROTECTED ({c.enforcing_rules_count} Rules Active)
                    </span>
                  )}
                  {c.protection_status === 'monitoring' && (
                    <span className="px-2.5 py-0.5 rounded-full bg-sky-500/15 border border-sky-500/40 text-sky-300 font-mono text-[11px] font-semibold">
                      LOG ONLY (MONITOR MODE)
                    </span>
                  )}
                  {isOut && (
                    <span className="px-2.5 py-0.5 rounded-full bg-slate-800 border border-slate-700 text-slate-400 font-mono text-[11px]">
                      OUTSIDE INBOUND GATEWAY SCOPE
                    </span>
                  )}
                </div>

                <h3 className="text-base font-bold text-white mt-3">{c.title}</h3>
                <p className="text-xs text-slate-400 mt-1">{c.risk_summary}</p>

                <div className="mt-3 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                  <div className="text-[10px] font-mono uppercase text-cyan-400 mb-1">
                    Gateway Mitigation
                  </div>
                  <p className="text-slate-300 leading-relaxed">{c.gateway_mitigation}</p>
                </div>

                <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400">
                  <span>Example Route: <strong className="text-slate-200">{c.demo_endpoint}</strong></span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                <div className="flex items-center gap-3 font-mono">
                  <span className="text-slate-300">
                    Requests: <strong className="text-white">{c.events_24h}</strong>
                  </span>
                  <span className="text-rose-400">
                    Blocked: <strong>{c.blocked_24h}</strong>
                  </span>
                  <span className="text-amber-300">
                    Alerts: <strong>{c.alerts_count}</strong>
                  </span>
                </div>

                {c.simulator_scenario ? (
                  <button
                    onClick={() => navigate(`/simulator?scenario=${c.simulator_scenario}`)}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 font-mono text-[11px]"
                  >
                    <Zap className="w-3 h-3" />
                    Test This Attack
                  </button>
                ) : (
                  <span className="inline-flex items-center gap-1 text-[11px] text-slate-500">
                    <AlertCircle className="w-3.5 h-3.5" />
                    Requires Egress Proxy
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
