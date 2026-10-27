import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Activity,
  ShieldAlert,
  Bell,
  Clock,
  AlertTriangle,
  Users,
  Ban,
  CheckCircle2,
  Zap,
  RefreshCw,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OwaspBadge, SeverityBadge } from '../components/shared/Badges';

const OWASP_COLORS = [
  '#f43f5e',
  '#f97316',
  '#eab308',
  '#06b6d4',
  '#8b5cf6',
  '#ec4899',
  '#10b981',
  '#3b82f6',
  '#6366f1',
];

export const OverviewPage: React.FC = () => {
  const { timeRange, setGatewayEnabled, addToast, canMutate, liveTraffic } = useGatewayStore();
  const [data, setData] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const fetchOverview = async () => {
    try {
      const res = await apiFetch(`/overview?time_range=${timeRange}`);
      setData(res);
      setGatewayEnabled(res.gateway_enabled);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, [timeRange, liveTraffic.length]);

  const handleBlockOffender = async (ip: string) => {
    try {
      await apiFetch('/blocklist', {
        method: 'POST',
        body: JSON.stringify({
          target_type: 'ip',
          value: ip,
          reason: 'Blocked from Overview Top Offenders table',
          owasp_id: 'API2',
          duration_minutes: 1440,
        }),
      });
      addToast({
        title: 'IP Blocked',
        message: `${ip} added to active blocklist for 24h`,
        severity: 'info',
      });
      fetchOverview();
    } catch (err: any) {
      addToast({ title: 'Block Failed', message: err.message, severity: 'high' });
    }
  };

  if (loading && !data) {
    return <div className="py-20 text-center text-slate-400 text-sm">Loading SOC telemetry...</div>;
  }

  const kpis = data?.kpis || {};
  const statCards = [
    {
      label: 'Total Gateway Requests',
      value: kpis.total_requests?.toLocaleString() || '0',
      delta: `${kpis.total_requests_delta_pct >= 0 ? '+' : ''}${kpis.total_requests_delta_pct || 0}% vs prior`,
      icon: Activity,
      color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    },
    {
      label: 'Blocked & Throttled Threats',
      value: kpis.blocked_requests?.toLocaleString() || '0',
      delta: `${kpis.block_rate_pct || 0}% block rate`,
      icon: ShieldAlert,
      color: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
    },
    {
      label: 'Active Security Alerts',
      value: kpis.active_alerts || 0,
      delta: `${kpis.critical_alerts || 0} Critical · ${kpis.high_alerts || 0} High`,
      icon: Bell,
      color: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    },
    {
      label: 'Avg Gateway Latency',
      value: `${kpis.avg_latency_ms || 0} ms`,
      delta: `${kpis.latency_delta_ms >= 0 ? '+' : ''}${kpis.latency_delta_ms || 0} ms vs prior`,
      icon: Clock,
      color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    },
    {
      label: '4xx / 5xx Error Ratio',
      value: `${kpis.error_rate_pct || 0}%`,
      delta: 'Includes 401/403/429 blocks',
      icon: AlertTriangle,
      color: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
    },
    {
      label: 'Unique Client Sources',
      value: kpis.unique_clients || 0,
      delta: `Window: ${timeRange}`,
      icon: Users,
      color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Security Operations Center (SOC) Overview
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time OWASP API Top 10 (2023) enforcement, request telemetry, and active threat correlation.
          </p>
        </div>
        <div className="flex items-center gap-2.5">
          <button
            onClick={fetchOverview}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
          <Link
            to="/simulator"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
          >
            <Zap className="w-3.5 h-3.5" />
            Launch Attack Simulator
          </Link>
        </div>
      </div>

      {/* 6 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        {statCards.map((c) => {
          const Icon = c.icon;
          return (
            <div
              key={c.label}
              className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400 font-medium">{c.label}</span>
                <div className={`p-1.5 rounded-lg border ${c.color}`}>
                  <Icon className="w-4 h-4" />
                </div>
              </div>
              <div className="mt-3">
                <div className="text-2xl font-bold text-white font-mono">{c.value}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-1">{c.delta}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Row: Traffic Over Time + OWASP Donut + Top Endpoints */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Traffic Over Time */}
        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Gateway Traffic Decisions Over Time</h3>
              <p className="text-xs text-slate-400">Allowed vs Blocked vs 429 Rate Limited</p>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data?.traffic_series || []}>
                <XAxis dataKey="time" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    fontSize: '12px',
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="allowed"
                  stackId="1"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.25}
                  name="Allowed"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  stackId="1"
                  stroke="#f43f5e"
                  fill="#f43f5e"
                  fillOpacity={0.4}
                  name="Blocked"
                />
                <Area
                  type="monotone"
                  dataKey="rate_limited"
                  stackId="1"
                  stroke="#f59e0b"
                  fill="#f59e0b"
                  fillOpacity={0.35}
                  name="429 Rate Limited"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Targeted Endpoints Bar Chart */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <div className="mb-4">
            <h3 className="text-sm font-semibold text-white">Top Targeted Endpoints</h3>
            <p className="text-xs text-slate-400">Total volume vs blocked attacks per route</p>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.top_endpoints || []} layout="vertical" margin={{ left: 20 }}>
                <XAxis type="number" stroke="#64748b" fontSize={11} />
                <YAxis
                  type="category"
                  dataKey="endpoint"
                  stroke="#94a3b8"
                  fontSize={10}
                  width={120}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="total" fill="#38bdf8" name="Total Requests" radius={[0, 4, 4, 0]} />
                <Bar dataKey="blocked" fill="#f43f5e" name="Blocked Attacks" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* OWASP Category Donut */}
        <div className="lg:col-span-3 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <div className="mb-2">
            <h3 className="text-sm font-semibold text-white">Detections by OWASP ID</h3>
            <p className="text-xs text-slate-400">2023 API Top 10 distribution</p>
          </div>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data?.owasp_distribution || []}
                  dataKey="count"
                  nameKey="owasp_id"
                  cx="50%"
                  cy="50%"
                  innerRadius={42}
                  outerRadius={72}
                  paddingAngle={3}
                >
                  {(data?.owasp_distribution || []).map((_: any, idx: number) => (
                    <Cell key={idx} fill={OWASP_COLORS[idx % OWASP_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#1e293b',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-1.5 mt-2">
            {(data?.owasp_distribution || []).map((item: any, idx: number) => (
              <span
                key={item.owasp_id}
                className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800"
              >
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: OWASP_COLORS[idx % OWASP_COLORS.length] }}
                />
                {item.owasp_id}: {item.count}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Split Tables: Latest 10 Alerts + Top Offending IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Latest 10 Alerts */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Latest Active Security Alerts</h3>
              <p className="text-xs text-slate-400">Click any alert to open incident timeline & AI Triage</p>
            </div>
            <Link to="/alerts" className="text-xs font-semibold text-cyan-400 hover:underline">
              View All Alerts →
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 px-2">OWASP</th>
                  <th className="py-2 px-2">Incident Title</th>
                  <th className="py-2 px-2">Source IP</th>
                  <th className="py-2 pl-2 text-right">Events</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.latest_alerts || []).map((al: any) => (
                  <tr
                    key={al.id}
                    onClick={() => navigate(`/alerts/${al.id}`)}
                    className="hover:bg-slate-800/60 cursor-pointer transition"
                  >
                    <td className="py-2.5 pr-3">
                      <SeverityBadge severity={al.severity} />
                    </td>
                    <td className="py-2.5 px-2">
                      <OwaspBadge owaspId={al.owasp_id} clickable={false} />
                    </td>
                    <td className="py-2.5 px-2 font-medium text-slate-200 max-w-xs truncate">
                      {al.title}
                    </td>
                    <td className="py-2.5 px-2 font-mono text-slate-300">{al.client_ip}</td>
                    <td className="py-2.5 pl-2 text-right font-mono font-bold text-slate-200">
                      {al.event_count}x
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top Offending IPs */}
        <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Top Offending Client IPs</h3>
              <p className="text-xs text-slate-400">Ranked by blocked volume & threat score</p>
            </div>
            <Link to="/blocklist" className="text-xs font-semibold text-cyan-400 hover:underline">
              Blocklist →
            </Link>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 pr-2">Client IP</th>
                  <th className="py-2 px-2">Blocked / Total</th>
                  <th className="py-2 px-2">OWASP</th>
                  <th className="py-2 pl-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.top_offenders || []).map((off: any) => (
                  <tr key={off.client_ip} className="hover:bg-slate-800/50">
                    <td className="py-2.5 pr-2 font-mono font-semibold text-white">
                      {off.client_ip}
                    </td>
                    <td className="py-2.5 px-2 font-mono">
                      <span className="text-rose-400 font-bold">{off.blocked_requests}</span>
                      <span className="text-slate-500"> / {off.total_requests}</span>
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex flex-wrap gap-1">
                        {(off.owasp_tags || []).slice(0, 2).map((t: string) => (
                          <span
                            key={t}
                            className="px-1.5 py-0.5 rounded bg-indigo-500/15 text-indigo-300 font-mono text-[10px]"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 pl-2 text-right">
                      {off.is_blocked ? (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-rose-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Blocked
                        </span>
                      ) : canMutate(['admin', 'analyst']) ? (
                        <button
                          onClick={() => handleBlockOffender(off.client_ip)}
                          className="inline-flex items-center gap-1 px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-[11px] font-mono transition"
                        >
                          <Ban className="w-3 h-3" />
                          Block IP
                        </button>
                      ) : (
                        <span className="text-slate-500 text-[11px]">Active</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
