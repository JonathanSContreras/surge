'use client';

import React, { useEffect, useRef, useState } from 'react';
import { Play, MoreVertical, Square, Pencil, Trash2 } from 'lucide-react';
import {
  getScans,
  createScan,
  stopScan,
  renameScan,
  deleteScan,
  scanWebSocket,
  formatDuration,
  type ScanRecord,
  type ScanProgressEvent,
} from '@/lib/api';

type FilterType = 'All' | 'Running' | 'Completed' | 'Failed';

const statusColors = {
  running:   'bg-[#FFB300]/10 text-[#FFB300]',
  completed: 'bg-[#00E676]/10 text-[#00E676]',
  failed:    'bg-[#FF1744]/10 text-[#FF1744]',
};

const statusLabel = {
  running:   'Running',
  completed: 'Completed',
  failed:    'Failed',
};

export function Scans() {
  const [scans, setScans]           = useState<ScanRecord[]>([]);
  const [name, setName]             = useState('');
  const [target, setTarget]         = useState('');
  const [filter, setFilter]         = useState<FilterType>('All');
  const [expandedScan, setExpandedScan] = useState<string | null>(null);
  const [page, setPage]                 = useState(0);
  const [launching, setLaunching]   = useState(false);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [progress, setProgress]     = useState<Record<string, number>>({});
  const [elapsed, setElapsed]       = useState<Record<string, number>>({});
  const [menuOpenId, setMenuOpenId]         = useState<string | null>(null);
  const [editingId, setEditingId]           = useState<string | null>(null);
  const [editName, setEditName]             = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  // Load defaults from Settings preferences
  useEffect(() => {
    try {
      const savedTarget = localStorage.getItem('surge:defaultTarget');
      if (savedTarget) setTarget(JSON.parse(savedTarget) as string);
    } catch { /* ignore */ }
  }, []);

  // Initial load
  useEffect(() => {
    getScans().then(setScans).catch(console.error);
  }, []);

  // Poll for status updates while any scan is running
  useEffect(() => {
    const hasRunning = scans.some((s) => s.status === 'running');
    if (!hasRunning) return;
    const interval = setInterval(() => {
      getScans().then(setScans).catch(console.error);
    }, 8000);
    return () => clearInterval(interval);
  }, [scans]);

  // Tick elapsed time every second for running scans
  useEffect(() => {
    const running = scans.filter((s) => s.status === 'running');
    if (running.length === 0) return;
    const interval = setInterval(() => {
      const now = Date.now();
      setElapsed(
        Object.fromEntries(
          running.map((s) => [
            s.scan_id,
            Math.max(0, Math.floor((now - new Date(s.created_at + 'Z').getTime()) / 1000)),
          ])
        )
      );
    }, 1000);
    return () => clearInterval(interval);
  }, [scans]);

  // WebSocket for active scan progress
  useEffect(() => {
    if (!activeScanId) return;

    wsRef.current?.close();
    const ws = scanWebSocket(activeScanId);

    ws.onmessage = (e) => {
      const msg = JSON.parse(e.data) as ScanProgressEvent & { type?: string };
      if (msg.type === 'heartbeat') return;

      setProgress((prev) => ({ ...prev, [activeScanId]: msg.progress }));

      if (msg.status === 'completed' || msg.status === 'failed') {
        setActiveScanId(null);
        // Refresh scan list to pick up final counts
        getScans().then(setScans).catch(console.error);
      }
    };

    ws.onerror = () => ws.close();
    wsRef.current = ws;

    return () => ws.close();
  }, [activeScanId]);

  // Close context menu when clicking outside
  useEffect(() => {
    if (!menuOpenId) return;
    const close = () => setMenuOpenId(null);
    document.addEventListener('click', close);
    return () => document.removeEventListener('click', close);
  }, [menuOpenId]);

  async function handleRename(scanId: string) {
    const trimmed = editName.trim();
    setEditingId(null);
    if (!trimmed) return;
    try {
      const updated = await renameScan(scanId, trimmed);
      setScans((prev) => prev.map((s) => s.scan_id === scanId ? { ...s, name: updated.name } : s));
    } catch (err) {
      console.error('Failed to rename scan', err);
    }
  }

  async function handleDelete(scanId: string) {
    setConfirmDeleteId(null);
    try {
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch (err) {
      console.error('Failed to delete scan', err);
    }
  }

  async function handleLaunch() {
    setLaunching(true);
    try {
      const res = await createScan({
        name: name.trim() || undefined,
        target: target.trim() || undefined,
        agent_mode: 'autonomous',
      });
      setActiveScanId(res.scan_id);
      setProgress((prev) => ({ ...prev, [res.scan_id]: 0 }));
      // Optimistically add to list
      getScans().then(setScans).catch(console.error);
    } catch (err) {
      console.error('Failed to launch scan', err);
    } finally {
      setLaunching(false);
    }
  }

  const PAGE_SIZE = 10;

  const filtered = scans.filter(
    (s) => filter === 'All' || s.status === filter.toLowerCase()
  );

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paginated  = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  const activeCount = scans.filter((s) => s.status === 'running').length;

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      <div className="grid grid-cols-12 gap-6">
        {/* Left Control Panel */}
        <div className="col-span-4">
          <div className="bg-surface-1 rounded-lg p-6 mb-6">
            <h2 className="font-semibold text-foreground mb-4">New Scan</h2>

            {/* Name */}
            <div className="mb-4">
              <label className="block text-sm text-muted mb-2">Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Office Network, Home Lab…"
                className="w-full bg-background border border-border rounded px-3 py-2 text-foreground text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
            </div>

            {/* Target */}
            <div className="mb-4">
              <label className="block text-sm text-muted mb-2">Target</label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="192.168.1.0/24"
                className="w-full bg-background border border-border rounded px-3 py-2 text-foreground font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
            </div>

            {/* Launch Button */}
            <button
              onClick={handleLaunch}
              disabled={launching}
              className="w-full bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-50 disabled:cursor-not-allowed text-[#0F1117] font-semibold py-3 rounded-lg flex items-center justify-center gap-2 transition-colors"
            >
              <Play className="w-4 h-4" fill="currentColor" />
              {launching ? 'Launching…' : 'Launch Scan'}
            </button>
          </div>
        </div>

        {/* Right Results Area */}
        <div className="col-span-8">
          <div className="bg-surface-1 rounded-lg overflow-hidden">
            {/* Header */}
            <div className="p-6 border-b border-border">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-semibold text-foreground">Scan History</h2>
                <div className="flex items-center gap-2">
                  {activeCount > 0 && (
                    <div className="w-2 h-2 bg-[var(--accent)] rounded-full animate-pulse" />
                  )}
                  <span className="text-sm text-muted">
                    Agents Active: {activeCount}
                  </span>
                </div>
              </div>

              {/* Filters */}
              <div className="flex items-center gap-2">
                {(['All', 'Running', 'Completed', 'Failed'] as FilterType[]).map((f) => (
                  <button
                    key={f}
                    onClick={() => { setFilter(f); setPage(0); }}
                    className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                      filter === f
                        ? 'bg-surface-2 text-foreground'
                        : 'text-muted hover:text-foreground hover:bg-surface-2/50'
                    }`}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            {/* Scans Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left text-xs text-muted font-medium px-6 py-3">Name</th>
                    <th className="text-left text-xs text-muted font-medium px-6 py-3">Target Range</th>
                    <th className="text-left text-xs text-muted font-medium px-6 py-3">Status</th>
                    <th className="text-right text-xs text-muted font-medium px-6 py-3">Devices</th>
                    <th className="text-right text-xs text-muted font-medium px-6 py-3">Vulns</th>
                    <th className="text-right text-xs text-muted font-medium px-6 py-3">Duration</th>
                    <th className="text-right text-xs text-muted font-medium px-6 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {paginated.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-6 py-8 text-center text-sm text-muted">
                        No scans yet.
                      </td>
                    </tr>
                  )}
                  {paginated.map((scan) => {
                    const scanProgress = progress[scan.scan_id];
                    const isEditing    = editingId === scan.scan_id;
                    const menuOpen     = menuOpenId === scan.scan_id;
                    const confirmDel   = confirmDeleteId === scan.scan_id;
                    return (
                      <React.Fragment key={scan.scan_id}>
                        <tr
                          className="border-b border-border hover:bg-surface-2 transition-colors cursor-pointer"
                          onClick={() => {
                            if (isEditing) return;
                            setExpandedScan(expandedScan === scan.scan_id ? null : scan.scan_id);
                          }}
                        >
                          {/* Name cell — inline edit when renaming */}
                          <td className="px-6 py-4" onClick={(e) => isEditing && e.stopPropagation()}>
                            {isEditing ? (
                              <input
                                autoFocus
                                value={editName}
                                onChange={(e) => setEditName(e.target.value)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter')  handleRename(scan.scan_id);
                                  if (e.key === 'Escape') setEditingId(null);
                                }}
                                onBlur={() => handleRename(scan.scan_id)}
                                className="w-full bg-background border border-[var(--accent)] rounded px-2 py-1 text-sm text-foreground focus:outline-none"
                              />
                            ) : (
                              <>
                                <span className="text-sm text-foreground block leading-tight">
                                  {scan.name ?? `${scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} Scan`}
                                </span>
                                <code className="text-xs text-[#4B5563] font-mono">
                                  {scan.scan_id.slice(0, 8).toUpperCase()}
                                </code>
                              </>
                            )}
                          </td>
                          <td className="px-6 py-4">
                            <code className="text-sm text-muted font-mono">{scan.target_range}</code>
                          </td>
                          <td className="px-6 py-4">
                            <div>
                              <span className={`text-xs px-2 py-1 rounded inline-flex items-center gap-1.5 ${statusColors[scan.status]}`}>
                                {scan.status === 'running' && (
                                  <div className="w-1.5 h-1.5 bg-[#FFB300] rounded-full animate-pulse" />
                                )}
                                {statusLabel[scan.status]}
                              </span>
                              {scan.status === 'running' && scanProgress !== undefined && (
                                <div className="mt-2 h-1 bg-border rounded-full overflow-hidden w-24">
                                  <div className="h-full bg-[#FFB300]" style={{ width: `${scanProgress}%` }} />
                                </div>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <span className="text-sm text-foreground">{scan.devices_count}</span>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <span className="text-sm text-foreground">{scan.vulns_count}</span>
                          </td>
                          <td className="px-6 py-4 text-right">
                            <span className="text-sm text-muted font-mono">
                              {scan.status === 'running'
                                ? formatDuration(elapsed[scan.scan_id] ?? Math.max(0, Math.floor((Date.now() - new Date(scan.created_at + 'Z').getTime()) / 1000)))
                                : formatDuration(scan.duration_s)}
                            </span>
                          </td>
                          {/* Actions cell */}
                          <td className="px-6 py-4 text-right" onClick={(e) => e.stopPropagation()}>
                            {scan.status === 'running' ? (
                              <button
                                onClick={async (e) => {
                                  e.stopPropagation();
                                  await stopScan(scan.scan_id).catch(console.error);
                                  getScans().then(setScans).catch(console.error);
                                }}
                                className="text-[#FF1744] hover:text-[#FF1744]/70 transition-colors"
                                title="Stop scan"
                              >
                                <Square className="w-4 h-4" fill="currentColor" />
                              </button>
                            ) : (
                              <div className="relative inline-block">
                                <button
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    setMenuOpenId(menuOpen ? null : scan.scan_id);
                                  }}
                                  className="text-muted hover:text-foreground transition-colors"
                                >
                                  <MoreVertical className="w-4 h-4" />
                                </button>
                                {menuOpen && (
                                  <div className="absolute right-0 top-6 z-20 w-36 bg-surface-1 border border-border rounded-lg shadow-lg py-1 text-sm">
                                    <button
                                      className="w-full flex items-center gap-2 px-3 py-2 text-left text-foreground hover:bg-surface-2 transition-colors"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setEditName(scan.name ?? '');
                                        setEditingId(scan.scan_id);
                                        setMenuOpenId(null);
                                      }}
                                    >
                                      <Pencil className="w-3.5 h-3.5" />
                                      Rename
                                    </button>
                                    <button
                                      className="w-full flex items-center gap-2 px-3 py-2 text-left text-[#FF1744] hover:bg-surface-2 transition-colors"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setConfirmDeleteId(scan.scan_id);
                                        setMenuOpenId(null);
                                      }}
                                    >
                                      <Trash2 className="w-3.5 h-3.5" />
                                      Delete
                                    </button>
                                  </div>
                                )}
                              </div>
                            )}
                          </td>
                        </tr>
                        {/* Expanded detail row */}
                        {expandedScan === scan.scan_id && (
                          <tr>
                            <td colSpan={7} className="bg-background px-6 py-4">
                              <div className="text-sm text-muted space-y-1">
                                <div><span className="text-foreground">Scan ID:</span> {scan.scan_id}</div>
                                <div><span className="text-foreground">Created:</span> {new Date(scan.created_at).toLocaleString()}</div>
                                {scan.completed_at && (
                                  <div><span className="text-foreground">Completed:</span> {new Date(scan.completed_at).toLocaleString()}</div>
                                )}
                                {scan.avg_cvss != null && (
                                  <div><span className="text-foreground">Avg CVSS:</span> {scan.avg_cvss.toFixed(2)}</div>
                                )}
                              </div>
                            </td>
                          </tr>
                        )}
                        {/* Delete confirmation row */}
                        {confirmDel && (
                          <tr>
                            <td colSpan={7} className="bg-[#FF1744]/5 border-b border-[#FF1744]/20 px-6 py-3">
                              <div className="flex items-center justify-between">
                                <span className="text-sm text-foreground">
                                  Delete this scan? All devices, vulnerabilities, and reports will be removed.
                                </span>
                                <div className="flex items-center gap-2 ml-4 shrink-0">
                                  <button
                                    onClick={() => setConfirmDeleteId(null)}
                                    className="px-3 py-1 rounded text-xs font-medium text-muted hover:text-foreground hover:bg-surface-2 transition-all"
                                  >
                                    Cancel
                                  </button>
                                  <button
                                    onClick={() => handleDelete(scan.scan_id)}
                                    className="px-3 py-1 rounded text-xs font-medium bg-[#FF1744] text-white hover:bg-[#FF1744]/80 transition-all"
                                  >
                                    Delete
                                  </button>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-6 py-3 border-t border-border">
                <span className="text-xs text-muted">
                  Page {page + 1} of {totalPages} &middot; {filtered.length} scans
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setPage((p) => Math.max(0, p - 1))}
                    disabled={page === 0}
                    className="px-3 py-1 rounded text-xs font-medium text-muted hover:text-foreground hover:bg-surface-2 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                  >
                    Prev
                  </button>
                  <button
                    onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                    disabled={page >= totalPages - 1}
                    className="px-3 py-1 rounded text-xs font-medium text-muted hover:text-foreground hover:bg-surface-2 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
