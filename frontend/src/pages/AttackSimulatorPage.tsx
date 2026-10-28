import React, { useEffect, useState } from 'react';
import { useSearchParams, Link } from 'react-router-dom';
import {
  Zap,
  ShieldCheck,
  ShieldOff,
  Play,
  Terminal,
  ExternalLink,
} from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { OwaspBadge, SeverityBadge } from '../components/shared/Badges';

export const AttackSimulatorPage: React.FC = () => {
  const [searchParams] = useSearchParams();
  const {
    gatewayEnabled,
    setGatewayEnabled,
    addToast,
    canMutate,
    selectedProjectId,
    selectedProjectName,
  } = useGatewayStore();
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [owaspData, setOwaspData] = useState<any | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<any | null>(null);

  const loadData = async () => {
    try {
      const promises: Promise<any>[] = [apiFetch('/owasp/coverage')];
      if (selectedProjectId) {
        promises.push(apiFetch(`/simulator/scenarios?upstream_id=${selectedProjectId}`));
      }
      const [owaspRes, simRes] = await Promise.all(promises);
      setOwaspData(owaspRes);
      if (simRes) {
        setScenarios(simRes.scenarios || []);
        setGatewayEnabled(simRes.gateway_enabled);
      }
    } catch {
      // ignore
    }
  };

  const handleRunScenario = async (scenarioId: string) => {
    setRunningId(scenarioId);
    try {
      const res = await apiFetch('/simulator/run', {
        method: 'POST',
        body: JSON.stringify({
          scenario_id: scenarioId,
          upstream_id: selectedProjectId,
        }),
      });
      setLastResult(res);
      addToast({
        title: `Attack Test Finished (${res.owasp_id || 'ALL'})`,
        message: `${res.blocked_count} Blocked · ${res.passed_through_count} Reached Server`,
        severity: res.passed_through_count > 0 && !res.gateway_enabled ? 'critical' : 'info',
      });
      await loadData();
    } catch (err: any) {
      addToast({ title: 'Simulation Error', message: err.message, severity: 'high' });
    } finally {
      setRunningId(null);
    }
  };

  useEffect(() => {
    const init = async () => {
      await loadData();
      const preselect = searchParams.get('scenario');
      if (preselect && selectedProjectId) {
        await handleRunScenario(preselect);
      }
    };
    init();
  }, [selectedProjectId]);

  const handleToggleGateway = async (nextState: boolean) => {
    try {
      const res = await apiFetch('/simulator/gateway-toggle', {
        method: 'POST',
        body: JSON.stringify({ gateway_enabled: nextState }),
      });
      setGatewayEnabled(res.gateway_enabled);
      addToast({
        title: res.gateway_enabled ? 'Gateway Protection ON' : 'Gateway Protection OFF',
        message: res.status_text,
        severity: res.gateway_enabled ? 'info' : 'critical',
      });
    } catch (err: any) {
      addToast({ title: 'Could Not Change Mode', message: err.message, severity: 'high' });
    }
  };

  const owaspCards = owaspData?.cards || [];
  const owaspByCode: Record<string, any> = {};
  for (const c of owaspCards) {
    owaspByCode[c.owasp_id] = c;
  }

  return (
    <div className="space-y-6">
      {/* Top Banner with Gateway Master Switch & OWASP Coverage Summary */}
      <div
        className={`p-6 rounded-2xl border transition ${
          gatewayEnabled
            ? 'bg-gradient-to-r from-slate-900 via-emerald-950/30 to-slate-900 border-emerald-500/40'
            : 'bg-gradient-to-r from-slate-900 via-rose-950/40 to-slate-900 border-rose-500/50'
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1 max-w-2xl">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
                OWASP API Security Top 10 (2023)
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold ${
                  gatewayEnabled
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-rose-500/25 text-rose-200 border border-rose-500/50'
                }`}
              >
                {gatewayEnabled ? 'GATEWAY ON' : 'GATEWAY OFF'}
              </span>
              {owaspData && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-950/80 text-emerald-300 border border-emerald-500/30">
                  {owaspData.protected_in_scope_count}/{owaspData.total_in_scope_count} Risks Protected ({owaspData.posture_score}%)
                </span>
              )}
            </div>
            <h1 className="text-2xl font-bold text-white">
              Attack Simulator — {selectedProjectName || 'Selected Project'}
            </h1>
            <p className="text-xs text-slate-300 leading-relaxed">
              Execute OWASP API Top 10 test payloads through the gateway pipeline against {selectedProjectName || 'the selected project'} routes.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center bg-slate-950 p-1 rounded-xl border border-slate-800">
              <button
                disabled={!canMutate(['admin', 'analyst', 'developer'])}
                onClick={() => handleToggleGateway(true)}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-mono font-bold transition ${
                  gatewayEnabled
                    ? 'bg-emerald-500 text-slate-950 shadow-lg'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <ShieldCheck className="w-4 h-4" />
                GATEWAY ON
              </button>
              <button
                disabled={!canMutate(['admin', 'analyst', 'developer'])}
                onClick={() => handleToggleGateway(false)}
                className={`flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-mono font-bold transition ${
                  !gatewayEnabled
                    ? 'bg-rose-500 text-white shadow-lg'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                <ShieldOff className="w-4 h-4" />
                GATEWAY OFF
              </button>
            </div>

            {canMutate(['admin', 'analyst', 'developer']) && (
              <button
                disabled={runningId !== null}
                onClick={() => handleRunScenario('all')}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg transition"
              >
                <Zap className="w-4 h-4" />
                {runningId === 'all' ? 'Running Scenarios...' : 'Run All Scenarios'}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Live Execution Console (if an attack was run) */}
      {lastResult && (
        <div className="bg-slate-900 border border-cyan-500/40 rounded-2xl p-5 space-y-4 shadow-2xl">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2.5">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <div>
                <h3 className="text-sm font-bold text-white">
                  Test Results: {lastResult.title}
                </h3>
                <p className="text-xs font-mono text-slate-400">
                  Project: <strong className="text-cyan-300">{lastResult.project_name}</strong> · Gateway:{' '}
                  <strong className={lastResult.gateway_enabled ? 'text-emerald-400' : 'text-rose-400'}>
                    {lastResult.gateway_enabled ? 'ON' : 'OFF'}
                  </strong>{' '}
                  · Sent: {lastResult.total_requests} · Blocked: {lastResult.blocked_count} · Passed: {lastResult.passed_through_count}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Link
                to="/alerts"
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 text-xs font-medium"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Security Alerts
              </Link>
              <Link
                to="/traffic"
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-slate-800 text-slate-200 text-xs font-medium"
              >
                Live Traffic
              </Link>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-[420px] overflow-y-auto pr-1">
            {(lastResult.steps || []).map((step: any, idx: number) => {
              const isBlocked = step.blocked_by_gateway;
              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border text-xs font-mono ${
                    isBlocked
                      ? 'bg-rose-950/25 border-rose-500/40'
                      : 'bg-emerald-950/20 border-emerald-500/30'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-bold text-white truncate">{step.request}</span>
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold shrink-0 ${
                        isBlocked
                          ? 'bg-rose-500/25 text-rose-300 border border-rose-500/40'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      }`}
                    >
                      HTTP {step.status_code} ({isBlocked ? 'BLOCKED' : 'PASSED'})
                    </span>
                  </div>
                  <div className="text-[10px] text-slate-400 mb-1.5">
                    Risk: {step.owasp_id} · ID: {step.request_id}
                  </div>
                  <pre className="text-[11px] text-slate-200 bg-slate-950 p-2.5 rounded border border-slate-800 overflow-x-auto max-h-40">
                    {step.response_preview}
                  </pre>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Unified Attack Scenarios & OWASP Coverage Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {scenarios.map((sc) => {
          const cov = owaspByCode[sc.owasp_id];
          return (
            <div
              key={sc.id}
              className="p-5 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-col justify-between hover:border-slate-700 transition"
            >
              <div>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <OwaspBadge owaspId={sc.owasp_id} clickable={false} />
                    <SeverityBadge severity={sc.severity} />
                  </div>
                  {cov && (
                    <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 font-mono text-[10px]">
                      {cov.enforcing_rules_count} Rules Active · {cov.blocked_24h} Blocked
                    </span>
                  )}
                </div>

                <h3 className="text-base font-bold text-white mt-3">{sc.title}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{sc.description}</p>

                {cov?.gateway_mitigation && (
                  <div className="mt-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                    <span className="text-[10px] font-mono uppercase text-cyan-400 mr-1.5">
                      Mitigation:
                    </span>
                    <span className="text-slate-300">{cov.gateway_mitigation}</span>
                  </div>
                )}

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 mt-3 text-[11px]">
                  <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-500/30">
                    <div className="font-mono font-bold text-emerald-400 uppercase text-[10px]">
                      With Gateway ON:
                    </div>
                    <p className="text-slate-300 mt-0.5">{sc.expected_when_on}</p>
                  </div>
                  <div className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-500/30">
                    <div className="font-mono font-bold text-rose-400 uppercase text-[10px]">
                      With Gateway OFF:
                    </div>
                    <p className="text-slate-300 mt-0.5">{sc.expected_when_off}</p>
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between">
                <span className="text-[11px] font-mono text-slate-400 truncate max-w-[240px]">
                  {sc.target_endpoint}
                </span>
                <button
                  disabled={runningId !== null || !canMutate(['admin', 'analyst', 'developer'])}
                  onClick={() => handleRunScenario(sc.id)}
                  className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-mono font-bold disabled:opacity-50 transition"
                >
                  <Play className="w-3.5 h-3.5" />
                  {runningId === sc.id ? 'Running...' : 'Run Scenario'}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
