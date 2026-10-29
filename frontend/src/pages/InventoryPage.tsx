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
  FolderKanban,
  Layers,
  Globe,
  Activity,
  Edit3,
  Check,
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
  const [projectSlugInput, setProjectSlugInput] = useState('');
  const [syncingSwagger, setSyncingSwagger] = useState(false);

  // Inline banner editing for slug and project details
  const [inlineEditing, setInlineEditing] = useState(false);
  const [inlineName, setInlineName] = useState('');
  const [inlineSlug, setInlineSlug] = useState('');
  const [inlineBaseUrl, setInlineBaseUrl] = useState('');
  const [savingInline, setSavingInline] = useState(false);

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
          slug: projectSlugInput.trim() || undefined,
          make_default: true,
        }),
      });
      const connectedUrl = res.upstream?.base_url || res.base_url || swaggerUrlInput.trim();
      const importedCount = res.imported_count ?? 0;
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
      setProjectSlugInput('');
      setTab('routes');
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Connection Failed', message: err.message, severity: 'high' });
    } finally {
      setSyncingSwagger(false);
    }
  };

  // Sync banner state with currentProject
  useEffect(() => {
    if (currentProject && !inlineEditing) {
      setInlineName(currentProject.name || '');
      setInlineSlug(currentProject.slug || '');
      setInlineBaseUrl(currentProject.base_url || '');
    }
  }, [currentProject?.id, currentProject?.slug, currentProject?.name, currentProject?.base_url, inlineEditing]);

  const handleQuickSaveSlug = async () => {
    if (!currentProject || !inlineSlug.trim()) return;
    setSavingInline(true);
    try {
      const cleanSlug = inlineSlug.trim().toLowerCase().replace(/\s+/g, '-');
      const updated = await apiFetch(`/inventory/upstreams/${currentProject.id}`, {
        method: 'PUT',
        body: JSON.stringify({ slug: cleanSlug }),
      });
      setSelectedProject(updated.id, updated.name, updated.slug);
      addToast({
        title: 'Project Slug Updated',
        message: `Project can now be reached at /gw/${updated.slug}/*`,
        severity: 'info',
      });
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Slug Update Failed', message: err.message, severity: 'high' });
    } finally {
      setSavingInline(false);
    }
  };

  const handleSaveInlineProject = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!currentProject) return;
    setSavingInline(true);
    try {
      const cleanSlug = inlineSlug.trim().toLowerCase().replace(/\s+/g, '-');
      const updated = await apiFetch(`/inventory/upstreams/${currentProject.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: inlineName.trim(),
          slug: cleanSlug,
          base_url: inlineBaseUrl.trim(),
        }),
      });
      setSelectedProject(updated.id, updated.name, updated.slug);
      addToast({
        title: 'Project Updated',
        message: `Successfully updated ${updated.name}`,
        severity: 'info',
      });
      setInlineEditing(false);
      await fetchInventory();
    } catch (err: any) {
      addToast({ title: 'Update Failed', message: err.message, severity: 'high' });
    } finally {
      setSavingInline(false);
    }
  };

  const handleImportOpenAPI = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await apiFetch('/inventory/import-openapi', {
        method: 'POST',
        body: JSON.stringify({
          spec_content: specContent,
          upstream_id: currentProjectId,
        }),
      });
      addToast({
        title: `OpenAPI Imported into ${currentProject?.name}`,
        message: `Imported ${res.imported_count ?? 0} routes into ${currentProject?.name}`,
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
            className="w-48 bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white"
          />
          <input
            type="text"
            value={projectSlugInput}
            onChange={(e) => setProjectSlugInput(e.target.value)}
            placeholder="Slug e.g. my-api (optional)"
            className="w-48 bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white font-mono"
          />
          <input
            type="text"
            required
            value={swaggerUrlInput}
            onChange={(e) => setSwaggerUrlInput(e.target.value)}
            placeholder="Backend URL (e.g. http://127.0.0.1:8001)"
            className="flex-1 min-w-[240px] bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-white font-mono"
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

      {/* PROJECT TABS / GRID */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400">
            <FolderKanban className="w-4 h-4 text-cyan-400" />
            <span>Projects ({upstreams.length})</span>
          </div>
          <span className="text-[11px] text-slate-500 hidden sm:inline">
            Click any project card to inspect and manage its routes
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 pb-1 items-stretch">
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
                className={`group cursor-pointer rounded-xl p-4 border transition-all duration-150 flex flex-col justify-between gap-3 text-left relative h-full ${
                  isSelected
                    ? 'bg-slate-900/95 border-cyan-400 text-white shadow-lg shadow-cyan-950/50 ring-1 ring-cyan-500/40'
                    : 'bg-slate-900/70 border-slate-800 text-slate-300 hover:bg-slate-900 hover:border-slate-700 hover:shadow-md'
                }`}
              >
                <div className="space-y-2.5 flex-1 flex flex-col">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2 min-w-0 flex-1">
                      <Server
                        className={`w-4 h-4 shrink-0 ${
                          isSelected ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-400'
                        }`}
                      />
                      <span className="text-sm font-bold truncate text-white" title={u.name}>
                        {u.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {isSelected ? (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
                          <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                          Selected
                        </span>
                      ) : (
                        <span className="text-[10px] font-mono text-slate-500 group-hover:text-cyan-400 transition">
                          Select
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 min-h-[22px] overflow-hidden">
                    {isDemo ? (
                      <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-300 border border-amber-500/30">
                        BUILT-IN DEMO
                      </span>
                    ) : (
                      <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                        YOUR PROJECT
                      </span>
                    )}
                    {u.enabled && (
                      <span className="shrink-0 px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        ACTIVE /gw/*
                      </span>
                    )}
                    <span className="truncate px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-cyan-300 border border-slate-700/60" title={`Route Slug: /gw/${u.slug}/*`}>
                      /gw/{u.slug}/*
                    </span>
                  </div>

                  <div className="bg-slate-950/70 border border-slate-800/80 rounded-lg px-2.5 py-1.5 flex items-center gap-2 text-xs font-mono text-slate-300 mt-auto">
                    <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span className="truncate text-[11px] flex-1" title={u.base_url}>
                      {u.base_url}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs pt-2.5 border-t border-slate-800/80 font-mono shrink-0">
                  <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                    <Layers className="w-3.5 h-3.5 text-slate-500" />
                    <span>
                      <strong className="text-slate-200 font-semibold">{countForProj}</strong> routes
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
                    <Activity className="w-3.5 h-3.5 text-slate-500" />
                    <span>
                      <strong className="text-cyan-300 font-semibold">{totalHitsForProj}</strong> requests
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Project Header Banner */}
      {currentProject && (
        <div className="p-4 rounded-xl bg-slate-900/95 border border-cyan-500/30 space-y-3.5">
          {/* Top Row: Project Info & Primary Actions */}
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0 flex-1">
              <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 shrink-0">
                <Layers className="w-5 h-5" />
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-base font-bold text-white truncate max-w-sm" title={currentProject.name}>
                    {currentProject.name}
                  </h3>
                  {currentProject.enabled ? (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 shrink-0">
                      DEFAULT GATEWAY TARGET (/gw/*)
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700 shrink-0">
                      SLUG ROUTE (/gw/{currentProject.slug}/*)
                    </span>
                  )}
                </div>
                <div className="text-xs text-slate-400 mt-1 font-mono flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-slate-500">Backend Server:</span>
                  <span className="text-slate-200 truncate max-w-md" title={currentProject.base_url}>
                    {currentProject.base_url}
                  </span>
                  <span className="text-slate-600">·</span>
                  <span className="text-cyan-300 font-bold">{projectRoutes.length} routes</span>
                </div>
              </div>
            </div>

            <div className="flex items-center flex-wrap gap-2 shrink-0">
              {!currentProject.enabled && (
                <button
                  onClick={() => handleActivateUpstream(currentProject.id, currentProject.name)}
                  className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition shrink-0"
                >
                  Set as Default Active Target (/gw/*)
                </button>
              )}
              <a
                href={
                  currentProject.enabled
                    ? '/gw/docs'
                    : `/gw/${currentProject.slug}/docs`
                }
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-xs transition shrink-0"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Swagger Docs</span>
              </a>
              {currentProject.id !== 1 && (
                <button
                  onClick={() => handleDeleteUpstream(currentProject.id)}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-300 border border-rose-500/30 text-xs font-medium shrink-0 transition"
                  title="Delete this API project"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  <span>Delete</span>
                </button>
              )}
            </div>
          </div>

          {/* Bottom Area: Editable Slug & Project Settings */}
          <div className="pt-3 border-t border-slate-800/80">
            {inlineEditing ? (
              <form onSubmit={handleSaveInlineProject} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Project Title</label>
                    <input
                      type="text"
                      required
                      value={inlineName}
                      onChange={(e) => setInlineName(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg px-3 py-1.5 text-white text-xs focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">
                      Route Slug <span className="text-cyan-400 font-mono text-[11px]">(/gw/{inlineSlug || 'slug'}/*)</span>
                    </label>
                    <div className="flex items-center bg-slate-950 border border-cyan-500/50 rounded-lg px-2.5 py-1 focus-within:ring-1 focus-within:ring-cyan-400">
                      <span className="text-slate-500 font-mono text-xs">/gw/</span>
                      <input
                        type="text"
                        required
                        value={inlineSlug}
                        onChange={(e) => setInlineSlug(e.target.value.toLowerCase().replace(/\s+/g, '-'))}
                        className="flex-1 bg-transparent text-cyan-300 font-mono text-xs focus:outline-none px-1"
                      />
                      <span className="text-slate-500 font-mono text-xs">/*</span>
                    </div>
                  </div>
                  <div>
                    <label className="block text-slate-400 mb-1 font-medium">Backend Server URL</label>
                    <input
                      type="text"
                      required
                      value={inlineBaseUrl}
                      onChange={(e) => setInlineBaseUrl(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-400 rounded-lg px-3 py-1.5 text-white font-mono text-xs focus:outline-none"
                    />
                  </div>
                </div>
                <div className="flex items-center justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setInlineName(currentProject.name || '');
                      setInlineSlug(currentProject.slug || '');
                      setInlineBaseUrl(currentProject.base_url || '');
                      setInlineEditing(false);
                    }}
                    className="px-3 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition font-medium"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={savingInline}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs transition disabled:opacity-50"
                  >
                    <Check className="w-3.5 h-3.5" />
                    {savingInline ? 'Saving...' : 'Save Changes'}
                  </button>
                </div>
              </form>
            ) : (
              <div className="flex flex-wrap items-center justify-between gap-3 text-xs">
                <div className="flex flex-wrap items-center gap-2 font-mono">
                  <span className="text-slate-400 font-sans font-medium">Project Route Slug:</span>
                  <div className="inline-flex items-center gap-1 bg-slate-950 border border-slate-700 hover:border-cyan-500/50 rounded-lg px-2.5 py-1 text-xs font-mono transition">
                    <span className="text-slate-500">/gw/</span>
                    <input
                      type="text"
                      value={inlineSlug}
                      onChange={(e) => setInlineSlug(e.target.value.toLowerCase().replace(/\s+/g, '-'))}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleQuickSaveSlug();
                      }}
                      placeholder="slug"
                      title="Edit project slug"
                      className="bg-slate-900 border border-slate-700 focus:border-cyan-400 text-cyan-300 font-bold focus:outline-none rounded px-2 py-0.5 min-w-[90px] max-w-[180px] text-xs font-mono"
                    />
                    <span className="text-slate-500">/*</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleQuickSaveSlug}
                    disabled={savingInline || inlineSlug === currentProject.slug || !inlineSlug.trim()}
                    className="px-2.5 py-1 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 font-sans font-semibold text-xs transition disabled:opacity-40 disabled:pointer-events-none"
                  >
                    {savingInline ? 'Saving...' : 'Save Slug'}
                  </button>
                </div>

                {canMutate(['admin', 'developer']) && (
                  <button
                    type="button"
                    onClick={() => setInlineEditing(true)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-medium transition"
                  >
                    <Edit3 className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Edit Title & Backend URL</span>
                  </button>
                )}
              </div>
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
