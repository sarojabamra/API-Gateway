import React, { useEffect, useId, useState } from 'react';
import { CheckCircle2, ChevronDown, Eraser, KeyRound, XCircle } from 'lucide-react';
import { apiFetch } from '../../lib/api';
import {
  clearProjectCredentials,
  readProjectApiKey,
  readProjectJwt,
  writeProjectApiKey,
  writeProjectJwt,
} from '../../lib/projectCredentials';
import { useGatewayStore } from '../../store/useGatewayStore';

type JwtStatus = 'idle' | 'validating' | 'valid' | 'invalid';

interface ProjectTestCredentialsProps {
  /** Compact strip for Inventory / Rate Limits; full panel for Simulator. */
  compact?: boolean;
  /** When true, show the Validate JWT button (Simulator). */
  allowJwtValidation?: boolean;
  onCredentialsChange?: (creds: { jwt: string; apiKey: string }) => void;
}

export const ProjectTestCredentials: React.FC<ProjectTestCredentialsProps> = ({
  compact = false,
  allowJwtValidation = false,
  onCredentialsChange,
}) => {
  const { selectedProjectId, selectedProjectName, canMutate, addToast } = useGatewayStore();
  const [open, setOpen] = useState(false);
  const [jwt, setJwt] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [jwtStatus, setJwtStatus] = useState<JwtStatus>('idle');
  const [jwtError, setJwtError] = useState('');
  const [jwtMeta, setJwtMeta] = useState<any | null>(null);
  const [validatingJwt, setValidatingJwt] = useState(false);
  const panelId = useId();

  const canEdit = canMutate(['admin', 'analyst', 'developer']);
  const hasJwt = Boolean(jwt.trim());
  const hasApiKey = Boolean(apiKey.trim());

  useEffect(() => {
    const nextJwt = readProjectJwt(selectedProjectId);
    const nextKey = readProjectApiKey(selectedProjectId);
    setJwt(nextJwt);
    setApiKey(nextKey);
    setJwtStatus('idle');
    setJwtError('');
    setJwtMeta(null);
    setOpen(false);
    onCredentialsChange?.({ jwt: nextJwt, apiKey: nextKey });
  }, [selectedProjectId]);

  const persistJwt = (value: string) => {
    setJwt(value);
    writeProjectJwt(selectedProjectId, value);
    if (jwtStatus !== 'idle') {
      setJwtStatus('idle');
      setJwtError('');
      setJwtMeta(null);
    }
    onCredentialsChange?.({ jwt: value, apiKey });
  };

  const persistApiKey = (value: string) => {
    setApiKey(value);
    writeProjectApiKey(selectedProjectId, value);
    onCredentialsChange?.({ jwt, apiKey: value });
  };

  const handleClear = () => {
    clearProjectCredentials(selectedProjectId);
    setJwt('');
    setApiKey('');
    setJwtStatus('idle');
    setJwtError('');
    setJwtMeta(null);
    onCredentialsChange?.({ jwt: '', apiKey: '' });
  };

  const validateJwt = async () => {
    const trimmed = jwt.trim();
    if (!trimmed) {
      setJwtStatus('invalid');
      setJwtError('Invalid JWT: token is empty');
      return { valid: false, error: 'Invalid JWT: token is empty' };
    }
    if (!selectedProjectId) {
      setJwtStatus('invalid');
      setJwtError('Select a project before validating a JWT');
      return { valid: false, error: 'Select a project before validating a JWT' };
    }
    setValidatingJwt(true);
    setJwtStatus('validating');
    setJwtError('');
    try {
      const res = await apiFetch('/simulator/validate-token', {
        method: 'POST',
        body: JSON.stringify({ token: trimmed, upstream_id: selectedProjectId }),
      });
      setJwtStatus('valid');
      setJwtMeta(res);
      writeProjectJwt(selectedProjectId, trimmed);
      return { valid: true, error: '' };
    } catch (err: any) {
      const message = err?.message || 'Invalid JWT';
      setJwtStatus('invalid');
      setJwtError(message);
      setJwtMeta(null);
      return { valid: false, error: message };
    } finally {
      setValidatingJwt(false);
    }
  };

  if (!selectedProjectId) return null;

  const statusChips = (
    <div className="flex flex-wrap items-center gap-1.5">
      <span
        className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
          hasJwt
            ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30'
            : 'bg-slate-800/80 text-slate-500 border-slate-700'
        }`}
      >
        JWT {hasJwt ? 'set' : 'empty'}
      </span>
      <span
        className={`px-2 py-0.5 rounded text-[10px] font-mono border ${
          hasApiKey
            ? 'bg-amber-500/15 text-amber-200 border-amber-500/30'
            : 'bg-slate-800/80 text-slate-500 border-slate-700'
        }`}
      >
        API key {hasApiKey ? 'set' : 'empty'}
      </span>
      {jwtStatus === 'valid' && jwtMeta?.subject && (
        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
          sub={jwtMeta.subject}
        </span>
      )}
    </div>
  );

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((prev) => !prev)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-slate-800/40 transition"
      >
        <KeyRound className="w-4 h-4 text-cyan-400 shrink-0" />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-sm font-bold text-white">
              Test credentials for {selectedProjectName || 'this project'}
            </h2>
            {statusChips}
          </div>
          {!open && (
            <p className="text-[11px] text-slate-500 mt-0.5 truncate">
              Click to enter JWT and/or API key for Inventory, Rate Limits, and Simulator
            </p>
          )}
        </div>
        <ChevronDown
          className={`w-4 h-4 text-slate-400 shrink-0 transition-transform duration-200 ${
            open ? 'rotate-180' : ''
          }`}
        />
      </button>

      <div
        id={panelId}
        hidden={!open}
        className={`border-t border-slate-800 ${compact ? 'p-4 space-y-3' : 'p-5 space-y-4'}`}
      >
        <p className="text-xs text-slate-400 leading-relaxed">
          Shared across Inventory Test Route, Rate Limit burst tests, and the Attack Simulator.
          JWT is sent as <code className="text-cyan-300">Authorization: Bearer</code>; the API key
          as <code className="text-cyan-300">X-API-Key</code>. Either credential can unlock the
          gateway; if both are set, a valid JWT is preferred and a valid API key is used as
          fallback. An API key alone may still not be enough: if this project&apos;s backend
          expects a JWT, enter that token here as well. Stored in this browser only.
        </p>

        <div className={`grid gap-3 ${compact ? 'grid-cols-1' : 'grid-cols-1 lg:grid-cols-2'}`}>
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">Project JWT (optional)</label>
            <textarea
              rows={compact ? 2 : 3}
              value={jwt}
              disabled={!canEdit}
              onChange={(e) => persistJwt(e.target.value)}
              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-xs text-cyan-300 placeholder:text-slate-600 disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-[11px] text-slate-400 mb-1">
              Consumer API key (optional)
            </label>
            <textarea
              rows={compact ? 2 : 3}
              value={apiKey}
              disabled={!canEdit}
              onChange={(e) => persistApiKey(e.target.value)}
              placeholder="sgw_live_...."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 font-mono text-xs text-amber-200 placeholder:text-slate-600 disabled:opacity-50"
            />
            <p className="text-[11px] text-slate-500 mt-1">
              Use a key created under Auth &amp; JWT → Consumer API Keys for this org.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="min-h-[1.25rem] text-xs">
            {jwtStatus === 'valid' && (
              <div className="inline-flex items-center gap-1.5 font-mono text-emerald-300">
                <CheckCircle2 className="w-4 h-4" />
                Valid JWT ready for this project
              </div>
            )}
            {jwtStatus === 'invalid' && (
              <div className="inline-flex items-start gap-1.5 font-mono text-rose-300">
                <XCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{jwtError || 'Invalid JWT'}</span>
              </div>
            )}
            {jwtStatus === 'idle' && !hasJwt && !hasApiKey && (
              <p className="text-slate-500">
                No credentials yet — protected routes will return 401 until you add a JWT and/or
                API key.
              </p>
            )}
            {jwtStatus === 'idle' && (hasJwt || hasApiKey) && (
              <p className="text-slate-400">
                {hasApiKey ? 'API key saved for this project. ' : ''}
                {hasJwt && allowJwtValidation
                  ? 'Validate the JWT before running attack simulations.'
                  : hasJwt
                    ? 'JWT saved for this project.'
                    : ''}
              </p>
            )}
            {jwtStatus === 'validating' && (
              <p className="font-mono text-slate-400">Validating JWT…</p>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!canEdit || (!hasJwt && !hasApiKey)}
              onClick={handleClear}
              className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium disabled:opacity-40 transition"
            >
              <Eraser className="w-3.5 h-3.5" />
              Clear
            </button>
            {allowJwtValidation && (
              <button
                type="button"
                disabled={validatingJwt || !hasJwt || !canEdit}
                onClick={async () => {
                  const check = await validateJwt();
                  addToast({
                    title: check.valid ? 'JWT Accepted' : 'Invalid JWT',
                    message: check.valid
                      ? `This token will be used for ${selectedProjectName || 'project'} tests.`
                      : check.error || 'The token is not a valid JWT for this project.',
                    severity: check.valid ? 'info' : 'high',
                  });
                }}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs disabled:opacity-50 transition"
              >
                <KeyRound className="w-3.5 h-3.5" />
                {validatingJwt ? 'Validating...' : 'Validate JWT'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
