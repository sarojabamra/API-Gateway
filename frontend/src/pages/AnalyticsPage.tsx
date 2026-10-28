import React, { useEffect, useState } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  Legend,
} from 'recharts';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';

export const AnalyticsPage: React.FC = () => {
  const { selectedProjectId, selectedProjectName } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const loadAnalytics = async () => {
      try {
        if (!selectedProjectId) return;
        const res = await apiFetch(`/analytics?upstream_id=${selectedProjectId}`);
        setData(res);
      } catch {
        // ignore
      } finally {
        setLoading(false);
      }
    };

    loadAnalytics();
  }, [selectedProjectId]);

  if (loading && !data) {
    return <div className="py-16 text-center text-slate-400 text-sm">Loading analytics...</div>;
  }

  const p = data?.overall_percentiles || {};
  const hours = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">
          {selectedProjectName || 'Project'} Analytics
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Gateway latency percentiles, HTTP status distribution, endpoint volume, and client rate baselines.
        </p>
      </div>

      {/* Latency Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="text-xs text-slate-400">p50 Latency</div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{p.p50_ms || 2.1} ms</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Median gateway processing time</div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="text-xs text-slate-400">p95 Latency</div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">{p.p95_ms || 6.4} ms</div>
          <div className="text-[11px] text-slate-500 mt-0.5">95th percentile processing time</div>
        </div>
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
          <div className="text-xs text-slate-400">p99 Latency</div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{p.p99_ms || 11.8} ms</div>
          <div className="text-[11px] text-slate-500 mt-0.5">99th percentile processing time</div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">Latency Percentiles (IST)</h3>
          <p className="text-xs text-slate-400 mb-4">p50, p95, and p99 response time in milliseconds</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={data?.latency_series || []}>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                />
                <Legend />
                <Line type="monotone" dataKey="p50" stroke="#10b981" strokeWidth={2} name="p50 (ms)" />
                <Line type="monotone" dataKey="p95" stroke="#06b6d4" strokeWidth={2} name="p95 (ms)" />
                <Line type="monotone" dataKey="p99" stroke="#f59e0b" strokeWidth={2} name="p99 (ms)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">HTTP Status Distribution (IST)</h3>
          <p className="text-xs text-slate-400 mb-4">Breakdown of 2xx, 401, 403, and 429 responses</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.status_series || []}>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                />
                <Legend />
                <Bar dataKey="s2xx" stackId="a" fill="#10b981" name="2xx Success" />
                <Bar dataKey="s401" stackId="a" fill="#f59e0b" name="401 Login Failed" />
                <Bar dataKey="s403" stackId="a" fill="#f43f5e" name="403 Blocked" />
                <Bar dataKey="s429" stackId="a" fill="#a855f7" name="429 Too Many Requests" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 2: Busiest Endpoints by Hour + Request Sizes */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">Busiest Endpoints by Time of Day (IST)</h3>
          <p className="text-xs text-slate-400 mb-4">Number of requests per 4-hour block (Indian Standard Time)</p>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                  <th className="py-2 pr-3">API Endpoint</th>
                  {hours.map((h) => (
                    <th key={h} className="py-2 px-2 text-center">
                      {h}
                    </th>
                  ))}
                  <th className="py-2 pl-2 text-right">Total</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.endpoint_heatmap || []).map((row: any) => (
                  <tr key={row.endpoint}>
                    <td className="py-2.5 pr-3 font-mono text-slate-200">{row.endpoint}</td>
                    {hours.map((h) => {
                      const val = row.hours?.[h] || 0;
                      const intensity =
                        val > 12
                          ? 'bg-rose-500/40 text-rose-200 border-rose-500/40'
                          : val > 6
                          ? 'bg-cyan-500/30 text-cyan-200 border-cyan-500/30'
                          : val > 0
                          ? 'bg-slate-800 text-slate-300 border-slate-700'
                          : 'bg-slate-950 text-slate-600 border-slate-900';
                      return (
                        <td key={h} className="py-1.5 px-1.5 text-center">
                          <div className={`py-1 rounded border font-mono text-[11px] ${intensity}`}>
                            {val}
                          </div>
                        </td>
                      );
                    })}
                    <td className="py-2.5 pl-2 text-right font-mono font-bold text-white">
                      {row.total}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <h3 className="text-sm font-bold text-white mb-1">Request Payload Size</h3>
          <p className="text-xs text-slate-400 mb-4">Distribution of inbound request body sizes</p>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.size_distribution || []}>
                <XAxis dataKey="bucket" stroke="#64748b" fontSize={10} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                />
                <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} name="Requests" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 3: Client Rate Baselines */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5">
        <h3 className="text-sm font-bold text-white mb-1">
          Client Rate Anomaly Detection
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Rolling Z-score comparison of current request rate against historical baseline per client.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-2 pr-3">Client IP or User</th>
                <th className="py-2 px-3">Normal Speed</th>
                <th className="py-2 px-3">Normal Variation</th>
                <th className="py-2 px-3">Current Speed</th>
                <th className="py-2 px-3">Spike Score</th>
                <th className="py-2 pl-3 text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {(data?.client_anomalies || []).map((c: any) => (
                <tr key={c.client_key} className="hover:bg-slate-800/40">
                  <td className="py-2.5 pr-3 font-mono font-semibold text-white">{c.client_key}</td>
                  <td className="py-2.5 px-3 font-mono text-slate-300">{c.mean_rpm} req/min</td>
                  <td className="py-2.5 px-3 font-mono text-slate-400">±{c.std_rpm}</td>
                  <td className="py-2.5 px-3 font-mono font-bold text-slate-200">{c.current_rpm} req/min</td>
                  <td className="py-2.5 px-3 font-mono font-bold">
                    <span className={c.is_anomalous ? 'text-rose-400' : 'text-emerald-400'}>
                      Z = {c.last_zscore}
                    </span>
                  </td>
                  <td className="py-2.5 pl-3 text-right">
                    {c.is_anomalous ? (
                      <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 font-mono text-[11px]">
                        UNUSUAL TRAFFIC SPIKE
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-mono text-[11px]">
                        NORMAL
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
