import React, { useEffect, useState } from 'react';
import {
  FileCode2,
  ShieldAlert,
  CheckCircle2,
  Ban,
  Plus,
  Server,
  Trash2,
  ExternalLink,
  RefreshCw,
  Play,
  Activity,
  FolderKanban,
  Layers,
} from 'lucide-react';
import { apiFetch, formatTimeIST } from '../lib/api';
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
  const {
    addToast,
    canMutate,
    trafficTick,
    selectedProjectId,
    setSelectedProject,
  } = useGatewayStore();
  const [tab, setTab] = useState<'routes' | 'shadow' | 'openapi'>('routes');
  const [data, setData] = useState<any | null>(null);
  const [specContent, setSpecContent] = useState(SAMPLE_OPENAPI_SPEC);
  const [callingRouteId, setCallingRouteId] = useState<number | null>(null);

  // Connect API input
  const [swaggerUrlInput, setSwaggerUrlInput] = useState('');
  const [projectNameInput, setProjectNameInput] = useState('');
  const [syncingSwagger, setSyncingSwagger] = useState(false);

  // Add Route state
  const [newMethod, setNewMethod] = useState('GET');
  const [newPath, setNewPath] = useState('/v2/inventory');
  const [newDesc, setNewDesc] = useState('Warehouse stock endpoint');
  const [newRole, setNewRole] = useState('');
  const [authReq, setAuthReq] = useState(false);

  const fetchInventory = async () => {
    try {
      const res = await apiFetch('/inventory');
      setData(res);
      if (
        res.upstreams?.length &&
        !res.upstreams.some((u: any) => u.id === selectedProjectId)
      ) {
        const active = res.upstreams.find((u: any) => u.enabled) || res.upstreams[0];
        setSelectedProject(active.id, active.name, active.slug);
      }
    } catch {
      // ignore
    }
  };

  // Auto-update whenever a live request arrives OR every 2.5 seconds
  useEffect(() => {
    fetchInventory();
  }, [trafficTick]);

  useEffect(() => {
    const timer = setInterval(() => {
      fetchInventory();
    }, 2500);
    return () => clearInterval(timer);
  }, [selectedProjectId]);

  const upstreams = data?.upstreams || [];
  const currentProject =
    upstreams.find((u: any) => u.id === selectedProjectId) ||
    upstreams.find((u: any) => u.enabled) ||
    upstreams[0];
  const currentProjectId = currentProject?.id || 1;

  // Filter routes and shadow routes ONLY for the currently selected project tab
  const projectRoutes = (data?.registered_routes || []).filter(
    (r: any) => r.upstream_id === currentProjectId
  );
  const projectShadowRoutes = (data?.shadow_routes || []).filter(
    (sr: any) => sr.upstream_id === currentProjectId
  );

  // Test calling a specific route through SentinelGW (/gw/...) so user sees Requests counter go up +1 immediately
  const handleTestRouteCall = async (route: any) => {
    setCallingRouteId(route.id);
    try {
      const concretePath = route.path_pattern.replace(/\{[^}]+\}/g, '101');
      // If this route belongs to a project that isn't currently the default active target, route via its slug (/gw/{slug}/...)
      const targetProj = upstreams.find((u: any) => u.id === route.upstream_id);
      const gwUrl =
        targetProj && !targetProj.enabled
          ? `/gw/${targetProj.slug}${concretePath}`
          : `/gw${concretePath}`;

      const res = await fetch(gwUrl, {
        method: route.method,
        headers: { 'Content-Type': 'application/json' },
      });
      await fetchInventory();
      addToast({
        title: `Request Recorded (+1) -> HTTP ${res.status}`,
        message: `Called ${route.method} ${gwUrl}. Request count is now ${(route.hit_count || 0) + 1}.`,
        severity: 'info',
      });
    } catch (err: any) {
      addToast({ title: 'Test Call Failed', message: err.message, severity: 'high' });
    } finally {
      setCallingRouteId(null);
    }
  };

  const handleActivateUpstream = async (upstreamId: number, name: string) => {
    try {
      await apiFetch(`/inventory/upstreams/${upstreamId}/activate`, { method: 'POST' });
      const project = upstreams.find((u: any) => u.id === upstreamId);
      setSelectedProject(upstreamId, name, project?.slug || '');
      addToast({
        title: 'Active Backend Switched',
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
      if (selectedProjectId === upstreamId) {
        const fallback = upstreams.find((u: any) => u.id !== upstreamId);
        if (fallback) setSelectedProject(fallback.id, fallback.name, fallback.slug);
      }
      addToast({
        title: 'API Project Removed',
        message: 'Removed custom API project and its routes',
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
        message: `Added ${res.path_pattern} to ${currentProject?.name || 'project'}`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Action Failed', message: err.message, severity: 'high' });
    }
  };

  const handleBlockShadow = async (routeId: number) => {
    try {
      await apiFetch(`/inventory/shadow/${routeId}/block`, { method: 'POST' });
      addToast({
        title: 'Unknown Route Blocked',
        message: 'Any future calls to this unknown endpoint will be blocked',
        severity: 'high',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Action Failed', message: err.message, severity: 'high' });
    }
  };

  const handleSyncSwaggerUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!swaggerUrlInput.trim()) return;
    setSyncingSwagger(true);
    try {
      const res = await apiFetch('/inventory/sync-swagger-url', {
        method: 'POST',
        body: JSON.stringify({
          base_url: swaggerUrlInput.trim(),
          name: projectNameInput.trim() || undefined,
          make_default: true,
        }),
      });
      const connectedUrl = res.upstream?.base_url || res.base_url || swaggerUrlInput.trim();
      const importedCount = res.imported_count ?? res.imported_routes ?? 0;
      if (res.upstream?.id) {
        setSelectedProject(res.upstream.id, res.upstream.name, res.upstream.slug);
      }
      addToast({
        title: 'New Project Tab Created!',
        message: `Connected ${connectedUrl} with ${importedCount} Swagger routes in its own tab.`,
        severity: 'info',
      });
      setSwaggerUrlInput('');
      setProjectNameInput('');
      setTab('routes');
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Connection Failed', message: err.message, severity: 'high' });
    } finally {
      setSyncingSwagger(false);
    }
  };

  const handleImportOpenAPI = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/inventory/import-openapi', {
        method: 'POST',
        body: JSON.stringify({
          spec_content: specContent,
          content: specContent,
          upstream_id: currentProjectId,
        }),
      });
      addToast({
        title: `OpenAPI Imported into ${currentProject?.name}`,
        message: `Imported ${res.imported_count ?? res.created_count ?? 0} routes into ${currentProject?.name}`,
        severity: 'info',
      });
      setTab('routes');
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Import Error', message: err.message, severity: 'high' });
    }
  };

  const handleCreateRoute = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch('/inventory/routes', {
        method: 'POST',
        body: JSON.stringify({
          upstream_id: currentProjectId,
          method: newMethod,
          path_pattern: newPath,
          description: newDesc,
          auth_required: authReq,
          required_role: newRole || null,
          rate_limit_rpm: 60,
          burst_capacity: 15,
        }),
      });
      addToast({
        title: 'Route Added',
        message: `${newMethod} ${newPath} added to ${currentProject?.name}`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Could Not Add Route', message: err.message, severity: 'high' });
    }
  };

  return (
    <div className="space-y-6">
      {/*Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-2xl font-bold text-white">API Projects & Routes</h1>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Manage connected API projects, registered routes, shadow API discovery, and OpenAPI specifications.
          </p>
        </div>

        <button
          onClick={fetchInventory}
          className="inline-flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-800 transition"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Connect a New Backend Project */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-bold text-white">
            Connect API Project
          </h2>
        </div>

        <form onSubmit={handleSyncSwaggerUrl} className="flex flex-wrap items-center gap-2.5">
          <input
            type="text"
            value={projectNameInput}
            onChange={(e) => setProjectNameInput(e.target.value)}
            placeholder="Project name (optional)"
            className="w-64 bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white"
          />
          <input
            type="text"
            required
            value={swaggerUrlInput}
            onChange={(e) => setSwaggerUrlInput(e.target.value)}
            placeholder="Backend URL (e.g. http://127.0.0.1:8001)"
            className="flex-1 min-w-[260px] bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white font-mono"
          />
          <button
            type="submit"
            disabled={syncingSwagger}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${syncingSwagger ? 'animate-spin' : ''}`} />
            {syncingSwagger ? 'Connecting...' : 'Connect Project'}
          </button>
        </form>
      </div>

      {/* PROJECT TABS BAR */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
            <FolderKanban className="w-4 h-4 text-cyan-400" />
            <span>Projects ({upstreams.length})</span>
          </div>
        </div>

        <div className="flex flex-wrap gap-2.5 border-b border-slate-800 pb-3">
          {upstreams.map((u: any) => {
            const isSelected = u.id === currentProjectId;
            const countForProj = (data?.registered_routes || []).filter(
              (r: any) => r.upstream_id === u.id
            ).length;
            const totalHitsForProj = (data?.registered_routes || [])
              .filter((r: any) => r.upstream_id === u.id)
              .reduce((acc: number, r: any) => acc + (r.hit_count || 0), 0);
            const isDemo = u.id === 1;

            return (
              <div
                key={u.id}
                onClick={() => setSelectedProject(u.id, u.name, u.slug)}
                className={`group cursor-pointer rounded-xl px-4 py-3 border transition flex items-center gap-3 ${
                  isSelected
                    ? 'bg-cyan-500/15 border-cyan-400 text-white shadow-lg shadow-cyan-950/50'
                    : 'bg-slate-900/80 border-slate-800 text-slate-300 hover:bg-slate-900 hover:border-slate-700'
                }`}
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold">{u.name}</span>
                    {isDemo ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        BUILT-IN DEMO
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        YOUR PROJECT
                      </span>
                    )}
                    {u.enabled && (
                      <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        ACTIVE /gw/*
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-3 mt-1 text-[11px] font-mono text-slate-400">
                    <span>{u.base_url}</span>
                    <span>•</span>
                    <span className="text-slate-200">{countForProj} routes</span>
                    <span>•</span>
                    <span className="text-cyan-300 font-bold">{totalHitsForProj} requests</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Project Header Banner */}
      {currentProject && (
        <div className="p-4 rounded-xl bg-slate-900/95 border border-cyan-500/30 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white">{currentProject.name}</h3>
                {currentProject.enabled ? (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    DEFAULT GATEWAY TARGET (/gw/*)
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300">
                    SLUG ROUTE (/gw/{currentProject.slug}/*)
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Backend Server: <span className="text-slate-200">{currentProject.base_url}</span> ·{' '}
                <span className="text-cyan-300 font-bold">{projectRoutes.length}</span> routes
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {!currentProject.enabled && (
              <button
                onClick={() => handleActivateUpstream(currentProject.id, currentProject.name)}
                className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition"
              >
                Set as Default Active Target (/gw/*)
              </button>
            )}
            <a
              href={
                currentProject.enabled
                  ? 'http://127.0.0.1:8000/gw/docs'
                  : `http://127.0.0.1:8000/gw/${currentProject.slug}/docs`
              }
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition"
            >
              <ExternalLink className="w-3.5 h-3.5" />
              Open Protected Swagger UI for {currentProject.name}
            </a>
            {currentProject.id !== 1 && (
              <button
                onClick={() => handleDeleteUpstream(currentProject.id)}
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-xs font-medium"
                title="Delete this API project"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Delete Project
              </button>
            )}
          </div>
        </div>
      )}

      {/* Sub-Tabs for the Selected Project: Tracked Routes | Shadow Routes | Import OpenAPI */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex gap-2">
          <button
            onClick={() => setTab('routes')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold border transition ${
              tab === 'routes'
                ? 'bg-cyan-500/15 text-cyan-300 border-cyan-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
          >
            Registered Routes ({projectRoutes.length})
          </button>
          <button
            onClick={() => setTab('shadow')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 ${
              tab === 'shadow'
                ? 'bg-rose-500/15 text-rose-300 border-rose-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
            Shadow Routes ({projectShadowRoutes.length})
          </button>
          <button
            onClick={() => setTab('openapi')}
            className={`px-4 py-2 rounded-lg text-xs font-semibold border transition flex items-center gap-1.5 ${
              tab === 'openapi'
                ? 'bg-indigo-500/15 text-indigo-300 border-indigo-500/40'
                : 'bg-slate-900 text-slate-400 border-slate-800'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5 text-indigo-400" />
            Import OpenAPI Spec into {currentProject?.name}
          </button>
        </div>
      </div>

      {tab === 'routes' && (
        <div className="space-y-4">
          {canMutate(['admin', 'developer']) && (
            <form
              onSubmit={handleCreateRoute}
              className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex flex-wrap items-end gap-3 text-xs"
            >
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
                <label className="block text-slate-400 mb-1">Description</label>
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
                  <th className="py-3 px-4">Method & Gateway URL</th>
                  <th className="py-3 px-3">Who Can Access</th>
                  <th className="py-3 px-3">Active Protections</th>
                  <th className="py-3 px-3">Speed Limit</th>
                  <th className="py-3 px-3 text-right">Requests (Live)</th>
                  <th className="py-3 px-4 text-right">Quick Test</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {projectRoutes.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-12 text-center text-slate-400">
                      No routes registered yet for <strong className="text-white">{currentProject?.name}</strong>.
                      Add one above, paste an OpenAPI spec, or simply call{' '}
                      <span className="font-mono text-cyan-300">http://localhost:8000/gw/...</span> and SentinelGW will auto-discover it!
                    </td>
                  </tr>
                ) : (
                  projectRoutes.map((r: any) => {
                    const gwPrefix = currentProject?.enabled
                      ? '/gw'
                      : `/gw/${currentProject?.slug}`;
                    return (
                      <tr key={r.id} className="hover:bg-slate-800/40">
                        <td className="py-3 px-4">
                          <div className="flex items-center gap-2">
                            <MethodBadge method={r.method} />
                            <span className="font-mono font-bold text-white">
                              <span className="text-cyan-400">{gwPrefix}</span>
                              {r.path_pattern}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">{r.description}</div>
                        </td>
                        <td className="py-3 px-3 font-mono">
                          {r.auth_required ? (
                            <span className="text-amber-300">
                              JWT Required ({r.required_role || 'any user'})
                            </span>
                          ) : (
                            <span className="text-emerald-400">Public</span>
                          )}
                        </td>
                        <td className="py-3 px-3">
                          <div className="flex flex-wrap gap-1">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                              SQLi/SSRF Filter
                            </span>
                            {r.bola_check_enabled && (
                              <span className="px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 font-mono text-[10px]">
                                ID Ownership Check
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="py-3 px-3 font-mono text-slate-300">
                          {r.rate_limit_rpm} / min
                        </td>
                        <td className="py-3 px-3 text-right">
                          <span className="inline-flex items-center px-2.5 py-1 rounded-md bg-cyan-500/15 border border-cyan-500/30 font-mono text-sm font-bold text-cyan-300">
                            {r.hit_count}
                          </span>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            onClick={() => handleTestRouteCall(r)}
                            disabled={callingRouteId === r.id}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition disabled:opacity-50"
                          >
                            <Play className="w-3 h-3" />
                            {callingRouteId === r.id ? 'Calling...' : 'Test Route'}
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
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
                  Unknown / Undocumented Routes for {currentProject?.name}
                </h3>
                <p className="text-xs text-slate-400">
                  Someone tried calling these URLs on {currentProject?.name}, but they aren&apos;t in its official Route List. Approve or block them in 1 click.
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
                  <th className="py-2 px-3">Last Seen (IST)</th>
                  <th className="py-2 pl-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {projectShadowRoutes.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-10 text-center text-slate-400">
                      No unknown shadow routes detected for <strong className="text-white">{currentProject?.name}</strong>.
                    </td>
                  </tr>
                ) : (
                  projectShadowRoutes.map((sr: any) => (
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
                        {sr.last_seen_at ? formatTimeIST(sr.last_seen_at) : 'recently'}
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
                  ))
                )}
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
                Bulk Import Routes into <span className="text-cyan-400">{currentProject?.name}</span> (OpenAPI JSON / YAML)
              </h3>
              <p className="text-xs text-slate-400">
                Paste an OpenAPI/Swagger specification below.
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
                Import Routes into {currentProject?.name}
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
