import React from 'react';
import { X, Shield, Eye, Wrench, Terminal, CheckCircle2 } from 'lucide-react';
import { useGatewayStore } from '../../store/useGatewayStore';

export const RoleGuideModal: React.FC = () => {
  const { roleGuideOpen, setRoleGuideOpen, user } = useGatewayStore();
  if (!roleGuideOpen) return null;

  const roles = [
    {
      role: 'admin',
      title: '1. Platform Administrator (admin@sentinel.local)',
      icon: Shield,
      color: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
      steps: [
        'Manage Users & RBAC Roles in Settings & Users (/settings) and reset/re-seed demo data.',
        'Control the Gateway Master Protection Switch (ON/OFF) in the Topbar or Attack Simulator.',
        'Configure global JWT signing secrets, issuer/audience binding, and Auto-Block rules.',
        'Full read/write access across all 16 security, monitoring, and governance pages.',
      ],
    },
    {
      role: 'analyst',
      title: '2. SOC Security Analyst (analyst@sentinel.local)',
      icon: Terminal,
      color: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
      steps: [
        'Monitor real-time attacks in Overview (/) and Live Traffic (/traffic) via WebSocket.',
        'Investigate correlated incidents in Alerts (/alerts/:id) and run AI-Assisted Alert Triage.',
        'Execute 1-click containment: Block Offending IP, Block User Principal, or Revoke JWT JTI.',
        'Tune policies between Monitor (Dry-Run) and Enforce (Block) in Security Policies (/policies).',
      ],
    },
    {
      role: 'developer',
      title: '3. API Owner / Developer (dev@sentinel.local)',
      icon: Wrench,
      color: 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10',
      steps: [
        'Register upstream APIs and import OpenAPI 3.0 JSON/YAML specs in API Inventory (/inventory).',
        'Review discovered Shadow APIs (OWASP API9) and promote or permanently block them.',
        'Configure per-route Rate Limits & Token Bucket bursts (/rate-limits) and run the N-Request Burst Tester.',
        'Use the interactive 8-Step JWT Token Tester (/auth-settings) to debug consumer tokens and mint API keys.',
      ],
    },
    {
      role: 'viewer',
      title: '4. Executive / Compliance Auditor (viewer@sentinel.local)',
      icon: Eye,
      color: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
      steps: [
        'Audit OWASP API Security Top 10 (2023) protection posture in OWASP Coverage (/owasp).',
        'Review p50/p95/p99 gateway latency percentiles and client Z-score anomalies in Analytics (/analytics).',
        'Generate and export CSV traffic/alert logs and Printable Executive Reports (/reports).',
        'Safe read-only mode: all mutating controls are automatically locked for compliance safety.',
      ],
    },
  ];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[88vh] overflow-y-auto p-6 shadow-2xl">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div>
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Role-Based Operational Guide
            </span>
            <h2 className="text-xl font-bold text-white mt-0.5">
              How to Use SentinelGW by Role (Current Role: <span className="text-cyan-400 uppercase">{user?.role}</span>)
            </h2>
          </div>
          <button
            onClick={() => setRoleGuideOpen(false)}
            className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-5">
          {roles.map((r) => {
            const Icon = r.icon;
            const isCurrent = user?.role === r.role;
            return (
              <div
                key={r.role}
                className={`p-4 rounded-xl border bg-slate-950/70 ${
                  isCurrent ? 'border-cyan-500/60 ring-1 ring-cyan-500/30' : 'border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-lg border ${r.color}`}>
                      <Icon className="w-4 h-4" />
                    </div>
                    <h3 className="text-sm font-semibold text-white">{r.title}</h3>
                  </div>
                  {isCurrent && (
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                      Active Role
                    </span>
                  )}
                </div>
                <ul className="space-y-2 text-xs text-slate-300">
                  {r.steps.map((step, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                      <span>{step}</span>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>

        <div className="mt-5 p-4 rounded-xl bg-indigo-950/30 border border-indigo-500/30 text-xs text-slate-300 space-y-1.5">
          <div className="font-semibold text-indigo-300 uppercase tracking-wider">
            5. API Consumer / Client Integration (`/gw/*`) & 5-Minute Judge Demo Flow
          </div>
          <p>
            • <strong>Consumer Gateway Endpoint</strong>: Send requests to <code className="text-cyan-300 font-mono">http://localhost:8000/gw/&lt;path&gt;</code> with <code className="text-cyan-300 font-mono">Authorization: Bearer &lt;JWT&gt;</code> or <code className="text-cyan-300 font-mono">X-API-Key: &lt;key&gt;</code>.
          </p>
          <p>
            • <strong>Live Judge Demo</strong>: Open <strong>Attack Simulator (/simulator)</strong> → Toggle <strong>Gateway OFF</strong> and run an attack to see raw VulnShop data leaks → Toggle <strong>Gateway ON</strong> and re-run to watch real-time blocks, OWASP tags, and AI Triage alerts!
          </p>
          <p className="text-slate-400">
            Full documentation is also saved in <code className="font-mono text-slate-200">docs/ROLE_BASED_USER_GUIDE.md</code>.
          </p>
        </div>
      </div>
    </div>
  );
};
