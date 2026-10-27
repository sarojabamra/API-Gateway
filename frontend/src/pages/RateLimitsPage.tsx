import React, { useEffect, useState } from 'react';
import { Zap, Gauge, Save } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { MethodBadge, OwaspBadge } from '../components/shared/Badges';

export const RateLimitsPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [burstPath, setBurstPath] = useState('/coupons/redeem');
  const [burstMethod, setBurstMethod] = useState('POST');
  const [burstCount, setBurstCount] = useState(12);
  const [burstRunning, setBurstRunning] = useState(false);
  const [burstResult, setBurstResult] = useState<any | null>(null);

  const fetchRateLimits = async () => {
    try {
      const res = await apiFetch('/ratelimits');
      setData(res);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchRateLimits();
  }, []);

  const handleUpdateRouteLimit = async (route: any, rpm: number, burst: number) => {
    try {
      await apiFetch(`/ratelimits/routes/${route.id}`, {
        method: 'PATCH',
        body: JSON.stringify({
          rate_limit_rpm: rpm,
          burst_capacity: burst,
          is_sensitive_flow: route.is_sensitive_flow,
        }),
      });
      addToast({
        title: 'Rate Limit Updated',
        message: `${route.path_pattern}: ${rpm} RPM / ${burst} burst`,
        severity: 'info',
      });
      fetchRateLimits();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    }
  };

  const handleRunBurstTest = async (e: React.FormEvent) => {
    e.preventDefault();
    setBurstRunning(true);
    try {
      const res = await apiFetch('/ratelimits/test-burst', {
        method: 'POST',
        body: JSON.stringify({
          path: burstPath,
          method: burstMethod,
          request_count: burstCount,
          client_ip: '198.51.100.77',
        }),
      });
      setBurstResult(res);
      addToast({
        title: 'Burst Simulation Completed',
        message: `${res.allowed_count} Allowed (200) · ${res.throttled_429_count} Rate Limited (429)`,
        severity: res.throttled_429_count > 0 ? 'high' : 'info',
      });
      fetchRateLimits();
    } catch (err: any) {
      addToast({ title: 'Burst Test Failed', message: err.message, severity: 'high' });
    } finally {
      setBurstRunning(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Rate Limits, Token Buckets & Velocity Studio
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Hybrid <strong>Sliding Window Counter</strong> (sustained RPM) + <strong>Token Bucket</strong> (burst capacity) for OWASP API4 & API6 protection.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
          <Gauge className="w-4 h-4 text-cyan-400" />
          <span>Counter Store: {data?.backend_engine || 'in-memory'}</span>
        </div>
      </div>

      {/* Interactive Burst Simulator Box + Live Usage Meters */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Burst Tester */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div>
            <span className="text-[10px] font-mono uppercase text-cyan-400">
              Live Rate-Limiter Verification Tool
            </span>
            <h3 className="text-sm font-bold text-white mt-0.5">
              Simulate N Rapid Requests & Inspect `429 Too Many Requests` Headers
            </h3>
          </div>

          <form onSubmit={handleRunBurstTest} className="grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
            <div className="sm:col-span-2">
              <label className="block text-slate-400 mb-1">Target Gateway Route</label>
              <select
                value={`${burstMethod}:${burstPath}`}
                onChange={(e) => {
                  const [m, p] = e.target.value.split(':');
                  setBurstMethod(m);
                  setBurstPath(p);
                }}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              >
                <option value="POST:/coupons/redeem">POST /gw/coupons/redeem (Sensitive: 6 RPM / 4 Burst)</option>
                <option value="GET:/products">GET /gw/products (Standard: 60 RPM / 20 Burst)</option>
                <option value="GET:/users/me">GET /gw/users/me (Profile: 60 RPM / 15 Burst)</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Burst Request Count (N)</label>
              <input
                type="number"
                min={1}
                max={50}
                value={burstCount}
                onChange={(e) => setBurstCount(Number(e.target.value))}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={burstRunning}
                className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold transition"
              >
                <Zap className="w-4 h-4" />
                {burstRunning ? 'Firing...' : `Fire ${burstCount} Reqs`}
              </button>
            </div>
          </form>

          {burstResult && (
            <div className="space-y-3 pt-2">
              <div className="flex items-center justify-between text-xs bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                <span>Target: {burstResult.target}</span>
                <span className="text-emerald-400">200 Allowed: {burstResult.allowed_count}</span>
                <span className="text-rose-400 font-bold">
                  429 Throttled: {burstResult.throttled_429_count}
                </span>
              </div>
              <div className="max-h-56 overflow-y-auto border border-slate-800 rounded-lg">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  <thead>
                    <tr className="bg-slate-950 border-b border-slate-800 text-slate-400 text-[10px]">
                      <th className="py-1.5 px-3">#</th>
                      <th className="py-1.5 px-2">HTTP Status</th>
                      <th className="py-1.5 px-2">X-RateLimit-Limit</th>
                      <th className="py-1.5 px-2">X-RateLimit-Remaining</th>
                      <th className="py-1.5 px-2">Retry-After</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {burstResult.results.map((r: any) => (
                      <tr
                        key={r.seq}
                        className={r.status_code === 429 ? 'bg-rose-950/25 text-rose-300' : 'text-slate-300'}
                      >
                        <td className="py-1.5 px-3">#{r.seq}</td>
                        <td className="py-1.5 px-2 font-bold">
                          {r.status_code === 429 ? '429 Too Many Requests' : `${r.status_code} OK`}
                        </td>
                        <td className="py-1.5 px-2">{r.limit}</td>
                        <td className="py-1.5 px-2">{r.remaining}</td>
                        <td className="py-1.5 px-2">{r.retry_after}s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Live Client Usage Meters */}
        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">Active Client Bucket Usage Meters</h3>
          <p className="text-xs text-slate-400 mb-4">Real-time sliding window & token bucket state</p>
          <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
            {(data?.active_meters || []).length === 0 ? (
              <div className="text-xs text-slate-500 py-8 text-center">
                Run the Burst Tester on the left to watch live client bucket meters fill up.
              </div>
            ) : (
              (data?.active_meters || []).map((m: any) => (
                <div key={m.key} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                  <div className="flex items-center justify-between font-mono text-[11px] mb-1.5">
                    <span className="text-slate-200 truncate max-w-[230px]">{m.key}</span>
                    <span className="text-cyan-400">
                      {m.current_rpm}/{m.limit_rpm} RPM ({m.utilization_pct}%)
                    </span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all ${
                        m.utilization_pct >= 90
                          ? 'bg-rose-500'
                          : m.utilization_pct >= 60
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.min(100, m.utilization_pct)}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] font-mono text-slate-400 mt-1.5">
                    <span>Burst Tokens Left: {m.tokens_remaining}/{m.burst_capacity}</span>
                    <span className={m.throttled_count > 0 ? 'text-rose-400 font-bold' : ''}>
                      429 Drops: {m.throttled_count}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Per-Route Rate Limit Configuration Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-white mb-1">Per-Route Sustained & Burst Limits</h3>
        <p className="text-xs text-slate-400 mb-4">
          Sensitive business flows (`API6`) enforce tighter token bucket limits than standard read routes (`API4`).
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-2 pr-3">Route</th>
                <th className="py-2 px-2">OWASP</th>
                <th className="py-2 px-2">Flow Class</th>
                <th className="py-2 px-2">Sustained Limit (RPM)</th>
                <th className="py-2 px-2">Token Bucket Burst</th>
                <th className="py-2 pl-2 text-right">Quick Tune</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {(data?.route_limits || []).map((r: any) => (
                <RouteLimitRow
                  key={r.id}
                  route={r}
                  canEdit={canMutate(['admin', 'analyst', 'developer'])}
                  onSave={handleUpdateRouteLimit}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const RouteLimitRow: React.FC<{
  route: any;
  canEdit: boolean;
  onSave: (route: any, rpm: number, burst: number) => void;
}> = ({ route, canEdit, onSave }) => {
  const [rpm, setRpm] = useState<number>(route.rate_limit_rpm);
  const [burst, setBurst] = useState<number>(route.burst_capacity);

  return (
    <tr className="hover:bg-slate-800/40">
      <td className="py-2.5 pr-3">
        <div className="flex items-center gap-2">
          <MethodBadge method={route.method} />
          <span className="font-mono text-white font-semibold">{route.path_pattern}</span>
        </div>
        <div className="text-[11px] text-slate-400 mt-0.5">{route.description}</div>
      </td>
      <td className="py-2.5 px-2">
        <OwaspBadge owaspId={route.owasp_id} />
      </td>
      <td className="py-2.5 px-2">
        {route.is_sensitive_flow ? (
          <span className="px-2 py-0.5 rounded bg-amber-500/15 text-amber-300 border border-amber-500/30 font-mono text-[10px]">
            SENSITIVE FLOW (API6)
          </span>
        ) : (
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-mono text-[10px]">
            STANDARD (API4)
          </span>
        )}
      </td>
      <td className="py-2.5 px-2">
        <input
          type="number"
          disabled={!canEdit}
          value={rpm}
          onChange={(e) => setRpm(Number(e.target.value))}
          className="w-24 bg-slate-950 border border-slate-800 rounded px-2 py-1 font-mono text-white"
        />
      </td>
      <td className="py-2.5 px-2">
        <input
          type="number"
          disabled={!canEdit}
          value={burst}
          onChange={(e) => setBurst(Number(e.target.value))}
          className="w-24 bg-slate-950 border border-slate-800 rounded px-2 py-1 font-mono text-white"
        />
      </td>
      <td className="py-2.5 pl-2 text-right">
        {canEdit && (
          <button
            onClick={() => onSave(route, rpm, burst)}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 text-xs font-mono"
          >
            <Save className="w-3 h-3" />
            Save
          </button>
        )}
      </td>
    </tr>
  );
};
