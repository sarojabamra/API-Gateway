import React, { useEffect, useState } from 'react';
import { CheckCircle2, XCircle, KeyRound, ShieldCheck, Copy, Ban, Sparkles } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';

export const AuthSettingsPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [jwtConfig, setJwtConfig] = useState<any>({});
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [revokedTokens, setRevokedTokens] = useState<any[]>([]);
  const [testToken, setTestToken] = useState('');
  const [testResult, setTestResult] = useState<any | null>(null);
  const [newKeyName, setNewKeyName] = useState('Partner Analytics Service Key');
  const [newlyCreatedRawKey, setNewlyCreatedRawKey] = useState<string | null>(null);
  const [revokeJtiInput, setRevokeJtiInput] = useState('');

  const fetchAll = async () => {
    try {
      const [cfg, keys, rev] = await Promise.all([
        apiFetch('/auth/jwt-config'),
        apiFetch('/auth/api-keys'),
        apiFetch('/auth/revoked-tokens'),
      ]);
      setJwtConfig(cfg);
      setApiKeys(keys || []);
      setRevokedTokens(rev || []);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchAll();
    // Mint a default valid user token on first load so the Token Tester is ready immediately
    handleMintPreset('valid_user');
  }, []);

  const handleMintPreset = async (preset: string) => {
    try {
      const res = await apiFetch('/auth/token-mint', {
        method: 'POST',
        body: JSON.stringify({ preset }),
      });
      setTestToken(res.token);
      setTestResult(res.validation);
    } catch (err: any) {
      addToast({ title: 'Token Mint Failed', message: err.message, severity: 'high' });
    }
  };

  const handleRunTokenTest = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/auth/token-test', {
        method: 'POST',
        body: JSON.stringify({ token: testToken }),
      });
      setTestResult(res);
    } catch (err: any) {
      addToast({ title: 'Validation Error', message: err.message, severity: 'high' });
    }
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/auth/api-keys', {
        method: 'POST',
        body: JSON.stringify({
          name: newKeyName,
          owner_email: 'dev@sentinel.local',
          role: 'user',
          scopes: ['read:products', 'read:orders'],
        }),
      });
      setNewlyCreatedRawKey(res.raw_key);
      addToast({
        title: 'API Key Generated',
        message: 'Copy your secret key now — it is only shown once.',
        severity: 'info',
      });
      fetchAll();
    } catch (err: any) {
      addToast({ title: 'Error', message: err.message, severity: 'high' });
    }
  };

  const handleRevokeApiKey = async (id: number) => {
    try {
      await apiFetch(`/auth/api-keys/${id}/revoke`, { method: 'POST' });
      addToast({ title: 'API Key Revoked', message: `Key #${id} revoked`, severity: 'info' });
      fetchAll();
    } catch (err: any) {
      addToast({ title: 'Error', message: err.message, severity: 'high' });
    }
  };

  const handleRevokeJti = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!revokeJtiInput.trim()) return;
    try {
      await apiFetch('/auth/revoked-tokens', {
        method: 'POST',
        body: JSON.stringify({
          jti: revokeJtiInput.trim(),
          user_sub: 'user-101',
          reason: 'Manual JTI revocation in Auth Center',
        }),
      });
      addToast({
        title: 'Token JTI Blacklisted',
        message: `Added ${revokeJtiInput} to revocation list`,
        severity: 'info',
      });
      setRevokeJtiInput('');
      fetchAll();
    } catch (err: any) {
      addToast({ title: 'Error', message: err.message, severity: 'high' });
    }
  };

  const presets = [
    { id: 'valid_user', label: 'Valid Customer JWT', color: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30' },
    { id: 'valid_admin', label: 'Valid Admin JWT', color: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30' },
    { id: 'alg_none', label: 'Attack: alg=none Unsigned', color: 'bg-rose-500/15 text-rose-300 border-rose-500/30' },
    { id: 'tampered_sig', label: 'Attack: Tampered Payload', color: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
    { id: 'expired', label: 'Attack: Expired Token', color: 'bg-amber-500/15 text-amber-300 border-amber-500/30' },
    { id: 'wrong_issuer', label: 'Attack: Untrusted Issuer', color: 'bg-purple-500/15 text-purple-300 border-purple-500/30' },
    { id: 'revoked_jti', label: 'Attack: Revoked JTI', color: 'bg-pink-500/15 text-pink-300 border-pink-500/30' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">
          Authentication Settings & 8-Step JWT Token Tester
        </h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Enforces OWASP API2 (Broken Authentication) via algorithm pinning, `alg=none` rejection, `kid` allowlisting, temporal leeway, `iss`/`aud` binding, and JTI revocation.
        </p>
      </div>

      {/* Interactive 8-Step JWT Token Tester & Minting Workbench */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">
              Interactive JWT Token Tester & Adversarial Preset Generator
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">
            Click any preset below to mint a real token and run the 8-step gateway validator
          </span>
        </div>

        {/* Preset Buttons */}
        <div className="flex flex-wrap gap-2">
          {presets.map((p) => (
            <button
              key={p.id}
              onClick={() => handleMintPreset(p.id)}
              className={`px-2.5 py-1.5 rounded-lg text-xs font-mono border transition hover:opacity-90 ${p.color}`}
            >
              {p.label}
            </button>
          ))}
        </div>

        <form onSubmit={handleRunTokenTest} className="space-y-3">
          <textarea
            rows={3}
            value={testToken}
            onChange={(e) => setTestToken(e.target.value)}
            placeholder="Paste any Bearer JWT token here..."
            className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 font-mono text-xs text-cyan-300"
          />
          <div className="flex justify-end">
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs"
            >
              Validate Token Against 8-Point Checklist
            </button>
          </div>
        </form>

        {testResult && (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 pt-2">
            {/* 8-Step Checklist */}
            <div className="lg:col-span-7 space-y-2">
              <div
                className={`p-3 rounded-lg border text-xs font-mono font-bold flex items-center justify-between ${
                  testResult.valid
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-300'
                    : 'bg-rose-500/15 border-rose-500/40 text-rose-300'
                }`}
              >
                <span>
                  OVERALL VERDICT: {testResult.valid ? 'VALID TOKEN (200 PASS)' : `REJECTED — 401 (${testResult.failure_code})`}
                </span>
                <span>{testResult.reason}</span>
              </div>

              <div className="space-y-1.5">
                {(testResult.steps || []).map((st: any) => (
                  <div
                    key={st.step}
                    className={`flex items-start gap-2.5 p-2.5 rounded-lg border text-xs ${
                      st.passed
                        ? 'bg-slate-950/90 border-slate-800'
                        : 'bg-rose-950/30 border-rose-500/40'
                    }`}
                  >
                    {st.passed ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    )}
                    <div>
                      <div className="font-semibold text-white">
                        Step {st.step}: {st.name}
                      </div>
                      <div className="text-[11px] font-mono text-slate-400 mt-0.5">{st.detail}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Decoded Header & Payload */}
            <div className="lg:col-span-5 bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-3">
              <div>
                <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">
                  Decoded JWT Header
                </div>
                <pre className="text-xs font-mono text-amber-300 bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto">
                  {JSON.stringify(testResult.header, null, 2)}
                </pre>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">
                  Decoded JWT Payload Claims
                </div>
                <pre className="text-xs font-mono text-cyan-300 bg-slate-900 p-2.5 rounded border border-slate-800 overflow-x-auto">
                  {JSON.stringify(testResult.payload, null, 2)}
                </pre>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Bottom Row: Gateway JWT Policy Summary + API Key Management + Revoked JTI Blacklist */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Active JWT Policy Config */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3 text-xs">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-sm font-bold text-white">Pinned JWT Validation Config</h3>
          </div>
          <div className="space-y-2 font-mono">
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Allowed Algorithms:</span>
              <span className="text-emerald-400 font-bold">
                {(jwtConfig.allowed_algorithms || ['HS256']).join(', ')}
              </span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Reject alg=none:</span>
              <span className="text-emerald-400 font-bold">STRICTLY ENFORCED</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Required Issuer (iss):</span>
              <span className="text-cyan-300">{jwtConfig.issuer}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Required Audience (aud):</span>
              <span className="text-cyan-300">{jwtConfig.audience}</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Clock Skew Leeway:</span>
              <span className="text-slate-200">{jwtConfig.leeway_seconds} seconds</span>
            </div>
            <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex justify-between">
              <span className="text-slate-400">Trusted Key IDs (kid):</span>
              <span className="text-slate-200">{(jwtConfig.trusted_kids || []).join(', ')}</span>
            </div>
          </div>
        </div>

        {/* Consumer API Keys */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">Consumer API Keys (`X-API-Key`)</h3>
          </div>

          {canMutate(['admin', 'developer']) && (
            <form onSubmit={handleCreateApiKey} className="flex gap-2">
              <input
                type="text"
                value={newKeyName}
                onChange={(e) => setNewKeyName(e.target.value)}
                placeholder="Key name..."
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-cyan-500 text-slate-950 font-semibold"
              >
                Create Key
              </button>
            </form>
          )}

          {newlyCreatedRawKey && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/40 space-y-1">
              <div className="text-[10px] font-mono uppercase text-emerald-300">
                Copy New Secret Key Now (Shown Once):
              </div>
              <div className="flex items-center justify-between font-mono text-white bg-slate-950 p-2 rounded">
                <span className="truncate">{newlyCreatedRawKey}</span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(newlyCreatedRawKey);
                    addToast({ title: 'Copied', message: 'API key copied to clipboard', severity: 'info' });
                  }}
                  className="text-cyan-400 hover:text-cyan-300 ml-2"
                >
                  <Copy className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}

          <div className="space-y-2 max-h-52 overflow-y-auto">
            {apiKeys.map((k) => (
              <div
                key={k.id}
                className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
              >
                <div>
                  <div className="font-semibold text-white">{k.name}</div>
                  <div className="font-mono text-[11px] text-slate-400">
                    Prefix: {k.key_prefix}*** · Owner: {k.owner_email}
                  </div>
                </div>
                {k.revoked ? (
                  <span className="px-2 py-0.5 rounded bg-rose-500/15 text-rose-400 font-mono text-[10px]">
                    REVOKED
                  </span>
                ) : (
                  canMutate(['admin', 'analyst', 'developer']) && (
                    <button
                      onClick={() => handleRevokeApiKey(k.id)}
                      className="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 text-[11px] font-mono"
                    >
                      Revoke
                    </button>
                  )
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Revoked Token JTI Blacklist */}
        <div className="lg:col-span-4 bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <Ban className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold text-white">Revoked JWT (`jti`) Blacklist</h3>
          </div>

          {canMutate(['admin', 'analyst', 'developer']) && (
            <form onSubmit={handleRevokeJti} className="flex gap-2">
              <input
                type="text"
                value={revokeJtiInput}
                onChange={(e) => setRevokeJtiInput(e.target.value)}
                placeholder="Enter token jti to revoke..."
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
              />
              <button
                type="submit"
                className="px-3 py-1.5 rounded-lg bg-rose-500/20 text-rose-300 border border-rose-500/40 font-semibold"
              >
                Revoke JTI
              </button>
            </form>
          )}

          <div className="space-y-2 max-h-52 overflow-y-auto">
            {revokedTokens.map((t) => (
              <div key={t.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800">
                <div className="flex items-center justify-between font-mono">
                  <span className="text-rose-300 font-bold">{t.jti}</span>
                  <span className="text-[10px] text-slate-400">{t.user_sub}</span>
                </div>
                <div className="text-[11px] text-slate-400 mt-0.5">{t.reason}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
