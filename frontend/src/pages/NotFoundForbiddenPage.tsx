import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldAlert, ArrowLeft } from 'lucide-react';

export const NotFoundForbiddenPage: React.FC<{ mode?: '404' | '403' }> = ({ mode = '404' }) => {
  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center text-center p-6">
      <div className="p-4 rounded-2xl bg-rose-500/15 border border-rose-500/40 text-rose-400 mb-4">
        <ShieldAlert className="w-10 h-10" />
      </div>
      <div className="text-xs font-mono uppercase tracking-wider text-rose-400">
        {mode === '403' ? 'HTTP 403 · Role Permission Denied' : 'HTTP 404 · Route Not Found'}
      </div>
      <h1 className="text-2xl font-bold text-white mt-1">
        {mode === '403'
          ? 'Your Current Role Cannot Access This Resource'
          : 'Control Plane Screen Not Found'}
      </h1>
      <p className="text-xs text-slate-400 max-w-md mt-2">
        {mode === '403'
          ? 'Use the Instant Persona Switcher in the top navigation bar to switch to Admin, Analyst, or Developer.'
          : 'The requested dashboard path does not exist in SentinelGW.'}
      </p>
      <Link
        to="/"
        className="mt-5 inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
      >
        <ArrowLeft className="w-4 h-4" />
        Return to SOC Overview
      </Link>
    </div>
  );
};
