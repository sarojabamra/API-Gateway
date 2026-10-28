import React, { useEffect, useState } from 'react';
import { Pause, Play, RefreshCw, Filter, Eye } from 'lucide-react';
import { apiFetch, formatTimeIST } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { DecisionBadge, MethodBadge, OwaspBadge } from '../components/shared/Badges';
import { TrafficLogItem } from '../types/api';

export const LiveTrafficPage: React.FC = () => {
  const {
    liveTraffic,
    liveStreamPaused,
    setLiveStreamPaused,
    openRequestDrawer,
    globalSearch,
    selectedProjectId,
    selectedProjectName,
  } = useGatewayStore();

  const [historyLogs, setHistoryLogs] = useState<TrafficLogItem[]>([]);
  const [decisionFilter, setDecisionFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [owaspFilter, setOwaspFilter] = useState('');
  const [ipFilter, setIpFilter] = useState(globalSearch || '');
  const [loading, setLoading] = useState(true);

  const fetchTraffic = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('limit', '120');
      if (selectedProjectId) params.set('upstream_id', String(selectedProjectId));
      if (decisionFilter) params.set('decision', decisionFilter);
      if (methodFilter) params.set('method', methodFilter);
      if (statusFilter) params.set('status_class', statusFilter);
      if (owaspFilter) params.set('owasp_id', owaspFilter);
      if (ipFilter) params.set('search', ipFilter);
      const res = await apiFetch(`/traffic?${params.toString()}`);
      setHistoryLogs(res.items || []);
    } catch {
      // ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTraffic();
  }, [decisionFilter, methodFilter, statusFilter, owaspFilter, selectedProjectId]);

  useEffect(() => {
    if (liveStreamPaused) return;
    const interval = setInterval(() => {
      fetchTraffic();
    }, 3000);
    return () => clearInterval(interval);
  }, [decisionFilter, methodFilter, statusFilter, owaspFilter, liveStreamPaused, selectedProjectId]);

  useEffect(() => {
    if (globalSearch) {
      setIpFilter(globalSearch);
    }
  }, [globalSearch]);

  // Merge WebSocket live stream items with fetched logs
  const mergedMap = new Map<string, TrafficLogItem>();
  for (const item of [...liveTraffic, ...historyLogs]) {
    if (selectedProjectId && item.upstream_id !== selectedProjectId) continue;
    if (decisionFilter && item.decision !== decisionFilter) continue;
    if (methodFilter && item.method !== methodFilter) continue;
    if (owaspFilter && item.owasp_id !== owaspFilter) continue;
    if (statusFilter === '2xx' && !(item.status_code >= 200 && item.status_code < 300)) continue;
    if (statusFilter === '4xx' && !(item.status_code >= 400 && item.status_code < 500)) continue;
    if (statusFilter === '5xx' && item.status_code < 500) continue;
    if (ipFilter) {
      const q = ipFilter.toLowerCase();
      const hay = `${item.request_id} ${item.client_ip} ${item.path} ${item.user_sub || ''} ${item.owasp_id || ''} ${item.block_reason || ''}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    if (!mergedMap.has(item.request_id)) {
      mergedMap.set(item.request_id, item);
    }
  }
  const rows = Array.from(mergedMap.values()).slice(0, 120);

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold text-white">
              {selectedProjectName || 'Project'} Live Gateway Traffic
            </h1>
            <span
              className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono ${
                liveStreamPaused
                  ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                  : 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
              }`}
            >
              <span
                className={`w-2 h-2 rounded-full ${
                  liveStreamPaused ? 'bg-amber-400' : 'bg-emerald-400 animate-ping'
                }`}
              />
              {liveStreamPaused ? 'STREAM PAUSED' : 'WEBSOCKET LIVE'}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Click any request row to open the Forensic Request Detail Drawer (headers, decoded JWT, matched policy, and 1-click IP block).
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => setLiveStreamPaused(!liveStreamPaused)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
              liveStreamPaused
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-amber-500/20 text-amber-300 border-amber-500/40'
            }`}
          >
            {liveStreamPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
            {liveStreamPaused ? 'Resume Stream' : 'Pause Stream'}
          </button>
          <button
            onClick={fetchTraffic}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Reload
          </button>
        </div>
      </div>

      {/* Filters Bar */}
      <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-slate-400">
          <Filter className="w-3.5 h-3.5 text-cyan-400" />
          <span>Filters:</span>
        </div>

        <input
          type="text"
          value={ipFilter}
          onChange={(e) => setIpFilter(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && fetchTraffic()}
          placeholder="Filter IP, path, req ID..."
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-white placeholder-slate-500 w-52"
        />

        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
        >
          <option value="">All Decisions</option>
          <option value="allowed">Allowed</option>
          <option value="blocked">Blocked</option>
          <option value="rate_limited">429 Rate Limited</option>
          <option value="monitored">Monitored (Dry-Run)</option>
        </select>

        <select
          value={methodFilter}
          onChange={(e) => setMethodFilter(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
        >
          <option value="">All Methods</option>
          <option value="GET">GET</option>
          <option value="POST">POST</option>
          <option value="PUT">PUT</option>
          <option value="DELETE">DELETE</option>
        </select>

        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200"
        >
          <option value="">All Status Codes</option>
          <option value="2xx">2xx Success</option>
          <option value="4xx">4xx Client / Security Block</option>
          <option value="5xx">5xx Upstream Error</option>
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

        {(decisionFilter || methodFilter || statusFilter || owaspFilter || ipFilter) && (
          <button
            onClick={() => {
              setDecisionFilter('');
              setMethodFilter('');
              setStatusFilter('');
              setOwaspFilter('');
              setIpFilter('');
            }}
            className="text-xs text-cyan-400 hover:underline ml-auto"
          >
            Clear Filters
          </button>
        )}
      </div>

      {/* Streaming Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-3 px-4">Time (IST)</th>
                <th className="py-3 px-3">Decision</th>
                <th className="py-3 px-3">Method & Route</th>
                <th className="py-3 px-3">Client IP / Principal</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Latency</th>
                <th className="py-3 px-3">OWASP Tag</th>
                <th className="py-3 px-3">Threat Score</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {loading && rows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    Loading traffic logs...
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    No traffic logs match the current filter criteria.
                  </td>
                </tr>
              ) : (
                rows.map((r) => (
                  <tr
                    key={r.request_id}
                    onClick={() => r.id && openRequestDrawer(r.id)}
                    className="hover:bg-slate-800/60 cursor-pointer transition"
                  >
                    <td className="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                      {formatTimeIST(r.ts)}
                    </td>
                    <td className="py-2.5 px-3">
                      <DecisionBadge decision={r.decision} />
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center gap-2">
                        <MethodBadge method={r.method} />
                        <span className="font-mono text-slate-100 font-medium truncate max-w-xs">
                          {r.path}
                          {r.query_params ? `?${r.query_params}` : ''}
                        </span>
                      </div>
                      {r.block_reason && (
                        <div className="text-[11px] text-slate-400 truncate max-w-md mt-0.5">
                          {r.block_reason}
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono">
                      <div className="text-slate-200">{r.client_ip}</div>
                      {r.user_sub && (
                        <div className="text-[10px] text-cyan-400">
                          {r.user_sub} ({r.user_role || 'user'})
                        </div>
                      )}
                    </td>
                    <td className="py-2.5 px-3 font-mono">
                      <span
                        className={`px-2 py-0.5 rounded font-bold ${
                          r.status_code >= 500
                            ? 'bg-rose-500/20 text-rose-300'
                            : r.status_code >= 400
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-emerald-500/15 text-emerald-300'
                        }`}
                      >
                        {r.status_code}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-slate-300">{r.latency_ms} ms</td>
                    <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <OwaspBadge owaspId={r.owasp_id} />
                    </td>
                    <td className="py-2.5 px-3 font-mono">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full ${
                              r.threat_score >= 80
                                ? 'bg-rose-500'
                                : r.threat_score >= 50
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${Math.min(100, r.threat_score)}%` }}
                          />
                        </div>
                        <span className="text-slate-300">{r.threat_score}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400">
                        <Eye className="w-3.5 h-3.5" />
                      </button>
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
