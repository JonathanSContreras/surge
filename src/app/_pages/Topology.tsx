'use client';

import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { ChevronDown } from 'lucide-react';
import { NetworkGraphForce } from '../_components/NetworkGraphForce';
import rawData from '../_components/data/rawData.json';
import { fromRawScan } from '../_components/data/raw-scan-parser';
import {
  getTopology,
  getScans,
  getVulnerabilities,
  type RawTopologyPayload,
  type ScanRecord,
  type VulnRecord,
} from '@/lib/api';
import { type NetworkTopology, SEVERITY_COLORS, type Severity } from '../_components/types/network-topology';

const FALLBACK_TOPOLOGY: NetworkTopology = fromRawScan(rawData, 'HCU Network Scan');
const EMPTY_TOPOLOGY: NetworkTopology = { devices: [], connections: [], networkName: 'Live Network Scan' };
const SEV_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];

type ViewMode = 'live' | 'latest' | 'scan';

export function Topology() {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [topology, setTopology] = useState<NetworkTopology>(FALLBACK_TOPOLOGY);
  const [vulns, setVulns] = useState<VulnRecord[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('live');
  const [selectedScanId, setSelectedScanId] = useState<string | undefined>(undefined);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [activeScans, setActiveScans] = useState(0);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const effectiveScanId =
    viewMode === 'live'   ? undefined :
    viewMode === 'latest' ? scans[0]?.scan_id :
    selectedScanId;

  const effectiveScan = scans.find((s) => s.scan_id === effectiveScanId);

  // Load completed scans once
  useEffect(() => {
    getScans()
      .then((all) => {
        const completed = all.filter((s) => s.status === 'completed');
        setScans(completed);
        const active = all.filter((s) => s.status === 'running').length;
        setActiveScans(active);
      })
      .catch(console.error);
  }, []);

  // Fetch topology (polling in live mode)
  useEffect(() => {
    function load() {
      getTopology(effectiveScanId)
        .then((raw: RawTopologyPayload) => {
          if (raw.topology.nodes.length > 0) {
            const label = effectiveScan
              ? `Scan ${effectiveScan.scan_id.slice(0, 8).toUpperCase()}`
              : 'Live Network Scan';
            setTopology(fromRawScan(raw, label));
          } else {
            setTopology(activeScans > 0 ? EMPTY_TOPOLOGY : FALLBACK_TOPOLOGY);
          }
        })
        .catch(console.error);
    }
    load();
    if (viewMode !== 'live') return;
    const interval = setInterval(load, 5000);
    return () => clearInterval(interval);
  }, [effectiveScanId, viewMode, activeScans]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch vulns for severity recoloring
  useEffect(() => {
    getVulnerabilities(effectiveScanId).then(setVulns).catch(() => setVulns([]));
  }, [effectiveScanId]);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  // Recolor nodes using max CVE severity per IP (same logic as Dashboard)
  const coloredTopology = useMemo(() => {
    if (vulns.length === 0) return topology;
    const maxSevByIp = new Map<string, Severity>();
    for (const v of vulns) {
      const sev = (v.severity?.toLowerCase() ?? 'low') as Severity;
      const ip = v.affected_device_ip;
      const curr = maxSevByIp.get(ip);
      if (!curr || SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(curr)) {
        maxSevByIp.set(ip, sev);
      }
    }
    return {
      ...topology,
      devices: topology.devices.map((d) => ({
        ...d,
        severity: maxSevByIp.get(d.ip) ?? d.severity,
      })),
    };
  }, [topology, vulns]);

  // CVE panel state
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null);

  const handleNodeClick = useCallback((nodeId: string) => {
    const device = coloredTopology.devices.find((d) => d.id === nodeId);
    if (device?.deviceType === 'subnet') return;
    const ip = device?.ip ?? null;
    setSelectedNodeIp((prev) => (prev === ip ? null : ip));
  }, [coloredTopology]);

  const selectedDevice = coloredTopology.devices.find((d) => d.ip === selectedNodeIp);
  const selectedVulns = selectedNodeIp
    ? vulns.filter((v) => v.affected_device_ip === selectedNodeIp)
    : [];

  // Severity counts for legend — exclude scanner and subnet nodes
  const sevCounts = useMemo(() => {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const d of coloredTopology.devices) {
      const nodeType = (d.metadata as Record<string, unknown>)?.nodeType as string;
      if (nodeType === 'scanner' || nodeType === 'subnet') continue;
      counts[d.severity] = (counts[d.severity] ?? 0) + 1;
    }
    return counts;
  }, [coloredTopology]);

  const selectedScan = scans.find((s) => s.scan_id === selectedScanId);

  return (
    <div className="max-w-[1800px] mx-auto p-6 flex flex-col" style={{ height: 'calc(100vh - 64px)' }}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4 flex-shrink-0">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Network Topology</h1>
          <p className="text-sm text-muted mt-0.5">
            {coloredTopology.networkName ?? 'Live Network Scan'}
            {effectiveScan && (
              <span className="ml-2 text-[#374151]">·</span>
            )}
            {effectiveScan && (
              <span className="ml-2">
                {effectiveScan.devices_count}d · {effectiveScan.vulns_count}v
                {effectiveScan.avg_cvss != null ? ` · CVSS ${effectiveScan.avg_cvss.toFixed(1)}` : ''}
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* Severity legend */}
          <div className="flex items-center gap-3">
            {(Object.entries(SEVERITY_COLORS) as [Severity, string][])
              .sort((a, b) => SEV_ORDER.indexOf(b[0]) - SEV_ORDER.indexOf(a[0]))
              .map(([sev, color]) => (
                <div key={sev} className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                  <span className="text-xs text-muted capitalize">{sev}</span>
                  <span className="text-xs font-mono text-[#374151]">{sevCounts[sev]}</span>
                </div>
              ))}
          </div>

          {/* View mode selector */}
          <div className="flex items-center bg-surface-1 border border-border rounded-lg p-1 gap-1">
            {/* Live */}
            <button
              onClick={() => { setViewMode('live'); setSelectedNodeIp(null); }}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                viewMode === 'live' ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'
              }`}
            >
              <span className={`relative flex h-2 w-2 ${viewMode === 'live' ? 'opacity-100' : 'opacity-40'}`}>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent)] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--accent)]" />
              </span>
              Live
            </button>

            {/* Latest */}
            <button
              onClick={() => { setViewMode('latest'); setSelectedNodeIp(null); }}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                viewMode === 'latest' ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'
              }`}
            >
              Latest
            </button>

            {/* Scan picker dropdown */}
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => { setViewMode('scan'); setDropdownOpen((o) => !o); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  viewMode === 'scan' ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'
                }`}
              >
                {viewMode === 'scan' && selectedScan
                  ? selectedScan.scan_id.slice(0, 8).toUpperCase()
                  : 'History'}
                <ChevronDown className={`w-3 h-3 transition-transform ${dropdownOpen && viewMode === 'scan' ? 'rotate-180' : ''}`} />
              </button>

              {dropdownOpen && viewMode === 'scan' && (
                <div className="absolute right-0 mt-1 w-80 bg-surface-1 border border-border rounded-lg shadow-xl z-50 overflow-hidden">
                  {scans.length === 0 ? (
                    <p className="px-4 py-3 text-sm text-muted">No completed scans yet.</p>
                  ) : (
                    <div className="max-h-64 overflow-y-auto">
                      {scans.map((scan) => (
                        <button
                          key={scan.scan_id}
                          onClick={() => {
                            setSelectedScanId(scan.scan_id);
                            setDropdownOpen(false);
                            setSelectedNodeIp(null);
                          }}
                          className={`w-full text-left px-4 py-3 text-sm transition-colors border-b border-border last:border-0 ${
                            selectedScanId === scan.scan_id
                              ? 'text-[var(--accent)] bg-surface-2'
                              : 'text-muted hover:text-foreground hover:bg-surface-2'
                          }`}
                        >
                          <div className="font-mono text-xs text-foreground mb-0.5">
                            {scan.scan_id.slice(0, 8).toUpperCase()}
                          </div>
                          <div className="text-xs text-muted">
                            {new Date(scan.created_at + 'Z').toLocaleString([], {
                              month: 'short', day: 'numeric',
                              hour: '2-digit', minute: '2-digit',
                            })}
                            {' · '}
                            {scan.scan_type} · {scan.devices_count}d · {scan.vulns_count}v
                            {scan.avg_cvss != null ? ` · CVSS ${scan.avg_cvss.toFixed(1)}` : ''}
                          </div>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Graph — fills remaining height */}
      <div className="flex-1 min-h-0">
        <NetworkGraphForce
          topology={coloredTopology}
          onNodeClick={handleNodeClick}
        />
      </div>

      {/* CVE detail panel */}
      {selectedNodeIp && (
        <div className="flex-shrink-0 mt-4 bg-surface-1 rounded-lg p-4 border border-border">
          <div className="flex items-center justify-between mb-3">
            <div>
              <span className="font-semibold text-foreground text-sm font-mono">{selectedNodeIp}</span>
              {selectedDevice?.hostname && selectedDevice.hostname !== selectedNodeIp && (
                <span className="text-muted text-xs ml-2">({selectedDevice.hostname})</span>
              )}
              <span className="text-xs text-muted ml-3">{selectedVulns.length} CVE{selectedVulns.length !== 1 ? 's' : ''}</span>
            </div>
            <button
              onClick={() => setSelectedNodeIp(null)}
              className="text-muted hover:text-foreground transition-colors text-xs px-2 py-1 rounded border border-border hover:border-[#374151]"
            >
              Close
            </button>
          </div>

          {selectedVulns.length === 0 ? (
            <p className="text-xs text-muted">No CVEs recorded for this host.</p>
          ) : (
            <div className="flex gap-2 flex-wrap max-h-32 overflow-y-auto">
              {selectedVulns.map((v) => {
                const sev = (v.severity?.toLowerCase() ?? 'low') as Severity;
                const color = SEVERITY_COLORS[sev] ?? '#9CA3AF';
                const score = v.cvss_score_predicted ?? v.cvss_score_raw;
                return (
                  <div
                    key={v.id}
                    className="flex items-center gap-2 px-3 py-2 bg-surface-2 rounded-lg border border-border min-w-0"
                    style={{ borderLeftColor: color, borderLeftWidth: 2 }}
                  >
                    <span className="text-xs font-mono text-foreground shrink-0">{v.cve_id}</span>
                    <span
                      className="text-xs font-semibold px-1 py-0.5 rounded capitalize shrink-0"
                      style={{ backgroundColor: `${color}20`, color }}
                    >
                      {v.severity}
                    </span>
                    {score != null && (
                      <span className="text-xs text-muted shrink-0">{score.toFixed(1)}</span>
                    )}
                    {v.summary && (
                      <span className="text-xs text-muted truncate max-w-xs">{v.summary}</span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
