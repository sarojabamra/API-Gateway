import React, { useEffect, useState } from 'react';
import {
  FileCode2,
  ShieldAlert,
  CheckCircle2,
  Ban,
  Plus,
  Globe,
  Server,
  Trash2,
  ArrowRight,
} from 'lucide-react';
import { apiFetch } from '../lib/api';
import { useGatewayStore } from '../store/useGatewayStore';
import { MethodBadge, OwaspBadge } from '../components/shared/Badges';

const SAMPLE_OPENAPI_SPEC = `openapi: 3.0.3
info:
  title: My Custom App API
  version: 1.2.0
paths:
  /checkout/instant:
    post:
      summary: One-click partner checkout flow
      tags: [checkout]
  /users/{id}/payment-methods:
    get:
      summary: Customer saved cards lookup
  /admin/audit-export:
    post:
      summary: Export system audit logs
      tags: [admin]`;

export const InventoryPage: React.FC = () => {
  const { addToast, canMutate } = useGatewayStore();
  const [tab, setTab] = useState<'routes' | 'shadow' | 'openapi'>('routes');
  const [data, setData] = useState<any | null>(null);
  const [specContent, setSpecContent] = useState(SAMPLE_OPENAPI_SPEC);

  // Add New API Project (Upstream) state
  const [showAddApi, setShowAddApi] = useState(false);
  const [apiName, setApiName] = useState('');
  const [apiSlug, setApiSlug] = useState('');
  const [apiBaseUrl, setApiBaseUrl] = useState('');
  const [apiAuthMode, setApiAuthMode] = useState('none');

  // Add Route state
  const [selectedUpstreamId, setSelectedUpstreamId] = useState<number>(1);
  const [newMethod, setNewMethod] = useState('GET');
  const [newPath, setNewPath] = useState('/v2/inventory');
  const [newDesc, setNewDesc] = useState('Warehouse stock endpoint');
  const [newRole, setNewRole] = useState('');
  const [authReq, setAuthReq] = useState(false);

  const fetchInventory = async () => {
    try {
      const res = await apiFetch('/inventory');
      setData(res);
    } catch {
      // ignore
    }
  };

  useEffect(() => {
    fetchInventory();
  }, []);

  const handleCreateUpstream = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await apiFetch('/inventory/upstreams', {
        method: 'POST',
        body: JSON.stringify({
          name: apiName,
          slug: apiSlug,
          base_url: apiBaseUrl,
          auth_mode: apiAuthMode,
        }),
      });
      addToast({
        title: 'API Project Connected!',
        message: `Call it through SentinelGW at /gw/${created.slug}/* or set it as default.`,
        severity: 'info',
      });
      setApiName('');
      setApiSlug('');
      setApiBaseUrl('');
      setShowAddApi(false);
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Could Not Add API', message: err.message, severity: 'high' });
    }
  };

  const handleActivateUpstream = async (upstreamId: number, name: string) => {
    try {
      await apiFetch(`/inventory/upstreams/${upstreamId}/activate`, { method: 'POST' });
      addToast({
        title: 'Default API Switched',
        message: `All /gw/* requests now forward to ${name}`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Could Not Switch API', message: err.message, severity: 'high' });
    }
  };

  const handleDeleteUpstream = async (upstreamId: number) => {
    try {
      await apiFetch(`/inventory/upstreams/${upstreamId}`, { method: 'DELETE' });
      addToast({
        title: 'API Removed',
        message: 'Removed custom API project',
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Could Not Remove API', message: err.message, severity: 'high' });
    }
  };

  const handlePromoteShadow = async (routeId: number) => {
    try {
      const res = await apiFetch(`/inventory/shadow/${routeId}/register`, { method: 'POST' });
      addToast({
        title: 'Route Approved',
        message: `Added ${res.path_pattern} to your official route list`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Action Failed', message: err.message, severity: 'high' });
    }
  };

  const handleBlockShadow = async (routeId: number) => {
    try {
      const res = await apiFetch(`/inventory/shadow/${routeId}/block`, { method: 'POST' });
      addToast({
        title: 'Unknown Route Blocked',
        message: `Blocked ${res.path_pattern} permanently`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Action Failed', message: err.message, severity: 'high' });
    }
  };

  const handleImportOpenAPI = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/inventory/import-openapi', {
        method: 'POST',
        body: JSON.stringify({ upstream_id: selectedUpstreamId, spec_content: specContent }),
      });
      addToast({
        title: 'OpenAPI Spec Imported',
        message: `Added ${res.imported_count} routes to your route list`,
        severity: 'info',
      });
      setTab('routes');
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'OpenAPI Import Error', message: err.message, severity: 'high' });
    }
  };

  const handleCreateRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch('/inventory/routes', {
        method: 'POST',
        body: JSON.stringify({
          upstream_id: selectedUpstreamId,
          method: newMethod,
          path_pattern: newPath,
          description: newDesc,
          auth_required: authReq,
          required_role: newRole || null,
          rate_limit_rpm: 60,
          burst_capacity: 15,
          bola_check_enabled: newPath.includes('{'),
        }),
      });
      addToast({
        title: 'Route Added',
        message: `Added ${newMethod} ${newPath}`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Failed to Add Route', message: err.message, severity: 'high' });
    }
  };

  const shadowCount = data?.shadow_routes?.length || 0;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Connected APIs & Route List
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Connect <strong>any local or deployed API project</strong>, register its allowed URL routes, or spot unknown &quot;Shadow&quot; routes automatically.
          </p>
        </div>

        {canMutate(['admin', 'developer']) && (
          <button
            onClick={() => setShowAddApi(!showAddApi)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs shadow-lg transition"
          >
            <Plus className="w-4 h-4" />
            {showAddApi ? 'Close Form' : 'Connect Another API (Local or Deployed)'}
          </button>
        )}
      </div>

      {/* Connect Any Local or Deployed API Form */}
      {showAddApi && (
        <div className="p-5 rounded-2xl bg-slate-900 border border-cyan-500/40 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">
                Connect Any Local or Deployed Backend API
              </h3>
              <p className="text-xs text-slate-400">
                Point SentinelGW to any server (Node/Express, FastAPI, Django, Spring Boot, Go, or a public cloud URL).
              </p>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400">Quick Fill:</span>
              <button
                type="button"
                onClick={() => {
                  setApiName('My Local Dev Server');
                  setApiSlug('my-local-api');
                  setApiBaseUrl('http://localhost:3000');
                  setApiAuthMode('none');
                }}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-mono text-[11px]"
              >
                Localhost (:3000)
              </button>
              <button
                type="button"
                onClick={() => {
                  setApiName('JSONPlaceholder Cloud API');
                  setApiSlug('json-cloud');
                  setApiBaseUrl('https://jsonplaceholder.typicode.com');
                  setApiAuthMode('none');
                }}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-indigo-300 font-mono text-[11px]"
              >
                Live Cloud API (JSONPlaceholder)
              </button>
            </div>
          </div>

          <form onSubmit={handleCreateUpstream} className="grid grid-cols-1 md:grid-cols-4 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Project Name</label>
              <input
                type="text"
                required
                placeholder="e.g. Payment Service"
                value={apiName}
                onChange={(e) => setApiName(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Short URL Prefix (Slug)</label>
              <input
                type="text"
                required
                placeholder="e.g. payments"
                value={apiSlug}
                onChange={(e) => setApiSlug(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Target Base URL (Local or Cloud)</label>
              <input
                type="url"
                required
                placeholder="http://localhost:3000 or https://api.example.com"
                value={apiBaseUrl}
                onChange={(e) => setApiBaseUrl(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-white font-mono"
              />
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                className="w-full py-2 px-4 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold"
              >
                Save & Connect API
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Connected API Projects Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {(data?.upstreams || []).map((u: any) => {
          const isLocal = u.base_url.includes('localhost') || u.base_url.includes('127.0.0.1');
          return (
            <div
              key={u.id}
              className={`p-4 rounded-xl border flex flex-col justify-between ${
                u.enabled
                  ? 'bg-slate-900 border-emerald-500/50 shadow-lg'
                  : 'bg-slate-900/70 border-slate-800'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-xs font-mono text-cyan-400">
                    {isLocal ? <Server className="w-3.5 h-3.5" /> : <Globe className="w-3.5 h-3.5" />}
                    {isLocal ? 'Local API' : 'Deployed Cloud API'}
                  </span>
                  {u.enabled ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-mono font-bold">
                      DEFAULT ACTIVE TARGET
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                      CONNECTED BY SLUG
                    </span>
                  )}
                </div>

                <div className="font-bold text-base text-white mt-2">{u.name}</div>
                <div className="mt-2 p-2.5 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] space-y-1">
                  <div className="text-slate-400">
                    Gateway URL:{' '}
                    <span className="text-cyan-300 font-bold">
                      {u.enabled ? '/gw/*' : `/gw/${u.slug}/*`}
                    </span>
                  </div>
                  <div className="text-slate-400 flex items-center gap-1 truncate">
                    <ArrowRight className="w-3 h-3 text-emerald-400 shrink-0" />
                    <span className="text-slate-200 truncate">{u.base_url}</span>
                  </div>
                </div>
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-xs">
                {!u.enabled && canMutate(['admin', 'developer']) ? (
                  <button
                    onClick={() => handleActivateUpstream(u.id, u.name)}
                    className="px-2.5 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 font-medium"
                  >
                    Make Default for /gw/*
                  </button>
                ) : (
                  <span className="text-[11px] text-slate-500">
                    Also accessible via <code className="text-slate-300">/gw/{u.slug}/*</code>
                  </span>
                )}

                {u.id !== 1 && canMutate(['admin', 'developer']) && (
                  <button
                    onClick={() => handleDeleteUpstream(u.id)}
                    className="p-1 text-slate-400 hover:text-rose-400"
                    title="Remove API"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Tabs for Routes / Shadow APIs / OpenAPI */}
      <div className="flex items-center gap-2 bg-slate-900 border border-slate-800 p-1 rounded-xl text-xs w-fit">
        <button
          onClick={() => setTab('routes')}
          className={`px-3.5 py-1.5 rounded-lg font-medium transition ${
            tab === 'routes' ? 'bg-cyan-500/20 text-cyan-300' : 'text-slate-400 hover:text-white'
          }`}
        >
          Registered Routes ({data?.registered_routes?.length || 0})
        </button>
        <button
          onClick={() => setTab('shadow')}
          className={`px-3.5 py-1.5 rounded-lg font-medium transition flex items-center gap-1.5 ${
            tab === 'shadow' ? 'bg-rose-500/20 text-rose-300' : 'text-slate-400 hover:text-white'
          }`}
        >
          <span>Unknown / Shadow Routes</span>
          <span className="px-1.5 py-0.2 rounded-full bg-rose-500/30 text-rose-200 font-mono text-[10px]">
            {shadowCount}
          </span>
        </button>
        <button
          onClick={() => setTab('openapi')}
          className={`px-3.5 py-1.5 rounded-lg font-medium transition ${
            tab === 'openapi' ? 'bg-indigo-500/20 text-indigo-300' : 'text-slate-400 hover:text-white'
          }`}
        >
          Import OpenAPI File
        </button>
      </div>

      {tab === 'routes' && (
        <div className="space-y-4">
          {canMutate(['admin', 'developer']) && (
            <form
              onSubmit={handleCreateRoute}
              className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-end gap-3 text-xs"
            >
              <div>
                <label className="block text-slate-400 mb-1">API Project</label>
                <select
                  value={selectedUpstreamId}
                  onChange={(e) => setSelectedUpstreamId(Number(e.target.value))}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white"
                >
                  {(data?.upstreams || []).map((u: any) => (
                    <option key={u.id} value={u.id}>
                      {u.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Method</label>
                <select
                  value={newMethod}
                  onChange={(e) => setNewMethod(e.target.value)}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white font-mono"
                >
                  <option>GET</option>
                  <option>POST</option>
                  <option>PUT</option>
                  <option>DELETE</option>
                </select>
              </div>
              <div className="flex-1 min-w-[160px]">
                <label className="block text-slate-400 mb-1">URL Path Pattern</label>
                <input
                  type="text"
                  value={newPath}
                  onChange={(e) => setNewPath(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white font-mono"
                />
              </div>
              <div className="flex-1 min-w-[180px]">
                <label className="block text-slate-400 mb-1">What does this route do?</label>
                <input
                  type="text"
                  value={newDesc}
                  onChange={(e) => setNewDesc(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-1.5 text-white"
                />
              </div>
              <div>
                <label className="block text-slate-400 mb-1">Access Level</label>
                <select
                  value={!authReq ? 'public' : newRole === 'admin' ? 'admin' : 'user'}
                  onChange={(e) => {
                    if (e.target.value === 'public') {
                      setAuthReq(false);
                      setNewRole('');
                    } else if (e.target.value === 'admin') {
                      setAuthReq(true);
                      setNewRole('admin');
                    } else {
                      setAuthReq(true);
                      setNewRole('');
                    }
                  }}
                  className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-white"
                >
                  <option value="public">Public (No Login Required)</option>
                  <option value="user">Logged-in Users (JWT / API Key)</option>
                  <option value="admin">Admins Only</option>
                </select>
              </div>
              <button
                type="submit"
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold inline-flex items-center gap-1"
              >
                <Plus className="w-3.5 h-3.5" />
                Add Route
              </button>
            </form>
          )}

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-3 px-4">Method & URL Path</th>
                  <th className="py-3 px-3">Who Can Access</th>
                  <th className="py-3 px-3">ID Ownership Check</th>
                  <th className="py-3 px-3">Hidden Response Fields</th>
                  <th className="py-3 px-3">Speed Limit</th>
                  <th className="py-3 px-4 text-right">Requests</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.registered_routes || []).map((r: any) => (
                  <tr key={r.id} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <MethodBadge method={r.method} />
                        <span className="font-mono font-bold text-white">{r.path_pattern}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{r.description}</div>
                    </td>
                    <td className="py-3 px-3 font-mono">
                      {r.auth_required ? (
                        <span className="text-emerald-400">
                          Login Required ({r.required_role || 'any user'})
                        </span>
                      ) : (
                        <span className="text-slate-400">Public</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {r.bola_check_enabled ? (
                        <span className="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-mono text-[10px]">
                          User Can Only View Own ID
                        </span>
                      ) : (
                        <span className="text-slate-500">—</span>
                      )}
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px] text-slate-300">
                      {(r.response_redact_fields || []).slice(0, 3).join(', ')}
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {r.rate_limit_rpm} / min
                    </td>
                    <td className="py-3 px-4 text-right font-mono font-bold text-slate-200">
                      {r.hit_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'shadow' && (
        <div className="bg-slate-900/90 border border-rose-500/30 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <div>
                <h3 className="text-sm font-bold text-white">
                  Unknown / Undocumented Routes Discovered in Traffic (Shadow APIs)
                </h3>
                <p className="text-xs text-slate-400">
                  Someone tried calling these URLs through the gateway, but they aren&apos;t in your official Route List. You can approve them or block them with 1 click.
                </p>
              </div>
            </div>
            <OwaspBadge owaspId="API9" />
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                  <th className="py-2 pr-3">Unknown URL Called</th>
                  <th className="py-2 px-3">Notes</th>
                  <th className="py-2 px-3">Times Called</th>
                  <th className="py-2 px-3">Last Seen</th>
                  <th className="py-2 pl-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {(data?.shadow_routes || []).map((sr: any) => (
                  <tr key={sr.id} className="hover:bg-slate-800/40">
                    <td className="py-3 pr-3">
                      <div className="flex items-center gap-2">
                        <MethodBadge method={sr.method} />
                        <span className="font-mono font-bold text-rose-300">{sr.path_pattern}</span>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-slate-300">{sr.description}</td>
                    <td className="py-3 px-3 font-mono font-bold text-rose-400">{sr.hit_count} hits</td>
                    <td className="py-3 px-3 font-mono text-slate-400">
                      {sr.last_seen_at ? new Date(sr.last_seen_at).toLocaleTimeString() : 'recently'}
                    </td>
                    <td className="py-3 pl-3 text-right space-x-2">
                      {canMutate(['admin', 'developer', 'analyst']) && (
                        <>
                          <button
                            onClick={() => handlePromoteShadow(sr.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            Approve & Add to List
                          </button>
                          <button
                            onClick={() => handleBlockShadow(sr.id)}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/30 text-xs font-medium"
                          >
                            <Ban className="w-3.5 h-3.5" />
                            Block Route
                          </button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'openapi' && (
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center gap-2.5">
            <FileCode2 className="w-5 h-5 text-indigo-400" />
            <div>
              <h3 className="text-sm font-bold text-white">
                Bulk Import Routes from OpenAPI / Swagger (JSON or YAML)
              </h3>
              <p className="text-xs text-slate-400">
                Paste your project&apos;s OpenAPI spec to register all its endpoints at once.
              </p>
            </div>
          </div>

          <form onSubmit={handleImportOpenAPI} className="space-y-3">
            <textarea
              rows={12}
              value={specContent}
              onChange={(e) => setSpecContent(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 font-mono text-xs text-cyan-300"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={!canMutate(['admin', 'developer'])}
                className="px-4 py-2 rounded-lg bg-indigo-500 hover:bg-indigo-400 text-white font-semibold text-xs disabled:opacity-50"
              >
                Import All Routes
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
