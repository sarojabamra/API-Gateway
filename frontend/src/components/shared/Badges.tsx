import React from 'react';
import { Link } from 'react-router-dom';

export const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const s = (severity || 'low').toLowerCase();
  const styles: Record<string, string> = {
    critical: 'bg-rose-500/15 text-rose-400 border-rose-500/40 ring-1 ring-rose-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/40',
    medium: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
    low: 'bg-sky-500/15 text-sky-300 border-sky-500/40',
    healthy: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40',
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${
        styles[s] || styles.low
      }`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          s === 'critical'
            ? 'bg-rose-400 animate-pulse'
            : s === 'high'
            ? 'bg-orange-400'
            : s === 'medium'
            ? 'bg-amber-400'
            : s === 'healthy'
            ? 'bg-emerald-400'
            : 'bg-sky-400'
        }`}
      />
      {severity}
    </span>
  );
};

export const OwaspBadge: React.FC<{ owaspId?: string | null; clickable?: boolean }> = ({
  owaspId,
  clickable = true,
}) => {
  if (!owaspId) {
    return <span className="text-xs font-mono text-slate-500">—</span>;
  }
  const labels: Record<string, string> = {
    API1: 'BOLA',
    API2: 'Broken Auth',
    API3: 'Property Auth',
    API4: 'Resource Cap',
    API5: 'BFLA',
    API6: 'Sensitive Flow',
    API7: 'SSRF',
    API8: 'Misconfig/Inj',
    API9: 'Shadow API',
    API10: 'Unsafe API',
  };
  const content = (
    <span className="inline-flex items-center gap-1 whitespace-nowrap px-2 py-0.5 rounded bg-indigo-500/15 border border-indigo-500/30 text-indigo-300 text-xs font-mono hover:bg-indigo-500/25 transition">
      <span className="font-bold text-indigo-200">{owaspId}</span>
      {labels[owaspId] && <span className="text-indigo-300/80">· {labels[owaspId]}</span>}
    </span>
  );
  return clickable ? <Link to="/simulator">{content}</Link> : content;
};

export const DecisionBadge: React.FC<{ decision: string }> = ({ decision }) => {
  const d = (decision || 'allowed').toLowerCase();
  if (d.includes('blocked')) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
        BLOCKED
      </span>
    );
  }
  if (d.includes('rate_limited')) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
        429 LIMITED
      </span>
    );
  }
  if (d.includes('monitored')) {
    return (
      <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-sky-500/15 text-sky-300 border border-sky-500/30">
        MONITORED
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
      ALLOWED
    </span>
  );
};

export const MethodBadge: React.FC<{ method: string }> = ({ method }) => {
  const m = (method || 'GET').toUpperCase();
  const colors: Record<string, string> = {
    GET: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30',
    POST: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30',
    PUT: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
    PATCH: 'text-purple-400 bg-purple-500/10 border-purple-500/30',
    DELETE: 'text-rose-400 bg-rose-500/10 border-rose-500/30',
  };
  return (
    <span
      className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-bold border ${
        colors[m] || colors.GET
      }`}
    >
      {m}
    </span>
  );
};
