import React, { useEffect, useState } from 'react';
import { Download, Printer, ShieldCheck } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { OwaspBadge, SeverityBadge } from '../components/shared/Badges';

export const ReportsPage: React.FC = () => {
  const [report, setReport] = useState<any | null>(null);
  const [timeRange, setTimeRange] = useState('24h');

  useEffect(() => {
    const loadReport = async () => {
      try {
        const res = await apiFetch(`/reports/summary?time_range=${timeRange}`);
        setReport(res);
      } catch {
        // ignore
      }
    };

    loadReport();
  }, [timeRange]);

  const m = report?.executive_metrics || {};

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Security Summary & Export Reports
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Download traffic logs or security alerts as CSV spreadsheets, or print a clean PDF summary.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono"
          >
            <option value="1h">Last 1 Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
          </select>

          <a
            href="/api/v1/reports/export/traffic.csv"
            download
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-cyan-500/30 transition"
          >
            <Download className="w-3.5 h-3.5" />
            Download Traffic CSV
          </a>

          <a
            href="/api/v1/reports/export/alerts.csv"
            download
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-indigo-300 border border-indigo-500/30 transition"
          >
            <Download className="w-3.5 h-3.5" />
            Download Alerts CSV
          </a>

          <button
            onClick={() => window.print()}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition"
          >
            <Printer className="w-3.5 h-3.5" />
            Print / Save PDF
          </button>
        </div>
      </div>

      {/* Printable Report Sheet */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-5 border-b border-slate-800">
          <div>
            <span className="text-xs font-mono uppercase text-cyan-400">
              SentinelGW Security Report
            </span>
            <h2 className="text-xl font-bold text-white mt-0.5">
              API Security & Traffic Summary
            </h2>
            <p className="text-xs font-mono text-slate-400 mt-0.5">
              Generated: {report?.generated_at ? new Date(report.generated_at).toLocaleString() : ''} · Time Window: {timeRange}
            </p>
          </div>

          <div className="flex items-center gap-3 p-4 rounded-xl bg-slate-950 border border-emerald-500/40">
            <ShieldCheck className="w-8 h-8 text-emerald-400" />
            <div>
              <div className="text-[10px] font-mono uppercase text-slate-400">
                Security Health Score
              </div>
              <div className="text-2xl font-bold font-mono text-emerald-400">
                {report?.posture_score || 94} / 100
              </div>
            </div>
          </div>
        </div>

        {/* Summary Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-slate-400">Total API Requests</div>
            <div className="text-xl font-bold font-mono text-white mt-1">{m.total_requests || 0}</div>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-slate-400">Blocked Attacks</div>
            <div className="text-xl font-bold font-mono text-rose-400 mt-1">
              {m.blocked_requests || 0} ({m.block_rate_pct || 0}%)
            </div>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-slate-400">Active Security Rules</div>
            <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
              {m.enforcing_policies || 0} / {m.total_policies || 0}
            </div>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
            <div className="text-slate-400">Known vs Unregistered Routes</div>
            <div className="text-xl font-bold font-mono text-cyan-400 mt-1">
              {m.registered_routes || 0} Known · {m.shadow_routes_discovered || 0} Unknown
            </div>
          </div>
        </div>

        {/* OWASP Incident Breakdown & Top Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          <div className="lg:col-span-4 space-y-3">
            <h3 className="text-sm font-bold text-white">Blocked Events by Category</h3>
            <div className="space-y-2">
              {(report?.owasp_breakdown || []).map((row: any) => (
                <div
                  key={row.owasp_id}
                  className="p-3 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                >
                  <OwaspBadge owaspId={row.owasp_id} />
                  <span className="font-mono font-bold text-white">{row.incidents} events</span>
                </div>
              ))}
            </div>
          </div>

          <div className="lg:col-span-8 space-y-3">
            <h3 className="text-sm font-bold text-white">Top Security Alerts</h3>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                    <th className="py-2 pr-2">Severity</th>
                    <th className="py-2 px-2">Category</th>
                    <th className="py-2 px-2">What Happened</th>
                    <th className="py-2 px-2">Sender IP</th>
                    <th className="py-2 pl-2 text-right">Count</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/70">
                  {(report?.top_alerts || []).map((a: any) => (
                    <tr key={a.id}>
                      <td className="py-2 pr-2">
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td className="py-2 px-2">
                        <OwaspBadge owaspId={a.owasp_id} clickable={false} />
                      </td>
                      <td className="py-2 px-2 text-slate-200">{a.title}</td>
                      <td className="py-2 px-2 font-mono text-slate-300">{a.client_ip}</td>
                      <td className="py-2 pl-2 text-right font-mono font-bold text-white">
                        {a.event_count}x
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
