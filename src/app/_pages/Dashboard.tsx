'use client';

import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { Play, ChevronDown, Info, X } from 'lucide-react';
import { DeviceList } from '../_components/DeviceList';
import { NetworkGraphForce } from '../_components/NetworkGraphForce';
import rawData from '../_components/data/rawData.json';
import { fromRawScan } from '../_components/data/raw-scan-parser';
import { ActivityFeed } from '../_components/ActivityFeed';
import { StatCards } from '../_components/StatCards';
import { VulnerabilityChart } from '../_components/VulnerabilityChart';
import { ExploitQueue } from '../_components/ExploitQueue';
import {
  getDashboardStats,
  getTopology,
  getScans,
  getVulnerabilities,
  formatDuration,
  type DashboardStats,
  type RawTopologyPayload,
  type RawTopologyHost,
  type RawTopologyVuln,
  type ScanRecord,
  type VulnRecord,
} from '@/lib/api';
import { type NetworkTopology, SEVERITY_COLORS, type Severity } from '../_components/types/network-topology';

const FALLBACK_TOPOLOGY: NetworkTopology = fromRawScan(rawData, 'HCU Network Scan');

const EMPTY_TOPOLOGY: NetworkTopology = {
  devices:     [],
  connections: [],
  networkName: 'Live Network Scan',
};

const DEFAULT_STATS: DashboardStats = {
  devices_scanned:       0,
  vulnerabilities_found: 0,
  avg_cvss:              null,
  active_scans:          0,
};

type ViewMode = 'live' | 'latest' | 'history';

export function Dashboard() {
  const router = useRouter();
  const [hoveredDeviceId, setHoveredDeviceId] = useState<string | null>(null);
  const [stats,      setStats]      = useState<DashboardStats>(DEFAULT_STATS);
  const [topology,   setTopology]   = useState<NetworkTopology>(FALLBACK_TOPOLOGY);
  const [scans,      setScans]      = useState<ScanRecord[]>([]);
  const [runningScan, setRunningScan] = useState<ScanRecord | null>(null);
  const [scanElapsed, setScanElapsed] = useState(0);
  const [vulns,      setVulns]      = useState<VulnRecord[]>([]);
  const [liveHosts,  setLiveHosts]  = useState<RawTopologyHost[]>([]);
  const [liveVulns,  setLiveVulns]  = useState<RawTopologyVuln[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('latest');
  const [historyScanId, setHistoryScanId] = useState<string | undefined>(undefined);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const [selectedNodeIp, setSelectedNodeIp] = useState<string | null>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const hasAutoSelectedMode = useRef(false);
  const prevActiveScansRef = useRef(0);

  // The scan ID passed to data-fetching calls
  const latestScanId = scans[0]?.scan_id;
  const effectiveScanId =
    viewMode === 'live'    ? undefined :
    viewMode === 'latest'  ? latestScanId :
    historyScanId;

  const effectiveScan = scans.find((s) => s.scan_id === effectiveScanId);

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

  // Load scan list and aggregate stats; in live mode, refresh every 5s.
  // On first load: auto-select live mode only if a scan is actively running.
  useEffect(() => {
    function refresh() {
      getDashboardStats()
        .then((s) => {
          const prev = prevActiveScansRef.current;
          prevActiveScansRef.current = s.active_scans;
          setStats(s);
          if (!hasAutoSelectedMode.current) {
            hasAutoSelectedMode.current = true;
            if (s.active_scans > 0) setViewMode('live');
          } else if (viewMode === 'live' && prev > 0 && s.active_scans === 0) {
            // Scan just finished — flip to latest so data appears automatically
            setViewMode('latest');
          }
        })
        .catch(console.error);
      getScans()
        .then((all) => {
          setScans(all.filter((s) => s.status === 'completed'));
          setRunningScan(all.find((s) => s.status === 'running') ?? null);
        })
        .catch(console.error);
    }
    refresh();
    if (viewMode !== 'live') return;
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [viewMode]);

  // Fetch vulnerabilities whenever the effective scan changes
  useEffect(() => {
    if (viewMode === 'live') { setVulns([]); return; }
    // Clear live data when switching away from live mode
    setLiveHosts([]);
    setLiveVulns([]);
    getVulnerabilities(effectiveScanId).then(setVulns).catch(() => setVulns([]));
  }, [effectiveScanId, viewMode]);

  // Fetch topology whenever the effective scan ID or view mode changes
  useEffect(() => {
    function loadTopology() {
      getTopology(effectiveScanId)
        .then((raw: RawTopologyPayload) => {
          if (raw.topology.nodes.length > 0) {
            const label = effectiveScan
              ? `Scan ${effectiveScan.scan_id.slice(0, 8).toUpperCase()}`
              : 'Live Network Scan';
            setTopology(fromRawScan(raw, label));
          } else {
            // Active scan running but no data yet → blank slate.
            // No active scan and no data → show sample fallback.
            setTopology(stats.active_scans > 0 ? EMPTY_TOPOLOGY : FALLBACK_TOPOLOGY);
          }
          // Store raw hosts/vulns for live-mode progressive fill
          if (viewMode === 'live') {
            setLiveHosts(raw.hosts ?? []);
            setLiveVulns(raw.vulns ?? []);
          }
        })
        .catch(console.error);
    }
    loadTopology();
    if (viewMode !== 'live') return;
    const interval = setInterval(loadTopology, 5000);
    return () => clearInterval(interval);
  }, [effectiveScanId, viewMode, stats.active_scans]); // eslint-disable-line react-hooks/exhaustive-deps

  // Tick elapsed time for the active running scan
  useEffect(() => {
    if (!runningScan) return;
    const start = new Date(runningScan.created_at + 'Z').getTime();
    setScanElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    const interval = setInterval(() => {
      setScanElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    }, 1000);
    return () => clearInterval(interval);
  }, [runningScan]);

  // Stat card values
  const liveAvgCvss = useMemo(() => {
    const scores = liveHosts.map((h) => h.cvss).filter((c) => c > 0);
    return scores.length > 0 ? scores.reduce((a, b) => a + b, 0) / scores.length : null;
  }, [liveHosts]);

  const displayStats =
    viewMode === 'live'
      ? {
          devices_scanned:       liveHosts.length,
          vulnerabilities_found: liveVulns.length,
          avg_cvss:              liveAvgCvss,
          active_scans:          stats.active_scans,
        }
      : effectiveScan
        ? {
            devices_scanned:       effectiveScan.devices_count,
            vulnerabilities_found: effectiveScan.vulns_count,
            avg_cvss:              effectiveScan.avg_cvss,
            active_scans:          stats.active_scans,
          }
        : stats;

  const historySelectedScan = scans.find((s) => s.scan_id === historyScanId);

  // Recolor topology nodes using max CVE severity per IP so the graph matches the vuln chart
  const SEV_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];
  const coloredTopology = useMemo(() => {
    const maxSevByIp = new Map<string, Severity>();
    // Completed scan data
    for (const v of vulns) {
      const sev = (v.severity?.toLowerCase() ?? 'low') as Severity;
      const ip = v.affected_device_ip;
      const curr = maxSevByIp.get(ip);
      if (!curr || SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(curr)) {
        maxSevByIp.set(ip, sev);
      }
    }
    // Live scan data (uses ip or host field)
    for (const v of liveVulns) {
      const sev = (v.severity?.toLowerCase() ?? 'low') as Severity;
      const ip = v.ip ?? v.host;
      if (!ip) continue;
      const curr = maxSevByIp.get(ip);
      if (!curr || SEV_ORDER.indexOf(sev) > SEV_ORDER.indexOf(curr)) {
        maxSevByIp.set(ip, sev);
      }
    }
    if (maxSevByIp.size === 0) return topology;
    return {
      ...topology,
      devices: topology.devices.map((d) => ({
        ...d,
        severity: maxSevByIp.get(d.ip) ?? d.severity,
      })),
    };
  }, [topology, vulns, liveVulns]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleNodeClick = useCallback((nodeId: string) => {
    const device = coloredTopology.devices.find((d) => d.id === nodeId);
    const ip = device?.ip ?? null;
    setSelectedNodeIp((prev) => (prev === ip ? null : ip));
  }, [coloredTopology]);

  const selectedDevice = coloredTopology.devices.find((d) => d.ip === selectedNodeIp);
  const selectedVulns = selectedNodeIp
    ? vulns.filter((v) => v.affected_device_ip === selectedNodeIp)
    : [];

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      {/* Page header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Network Overview</h1>
          <p className="text-sm text-muted mt-0.5">
            {stats.active_scans > 0
              ? `${stats.active_scans} active scan${stats.active_scans > 1 ? 's' : ''} running`
              : 'No active scans'}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {/* View mode segmented control */}
          <div className="flex items-center bg-surface-1 border border-border rounded-lg p-1 gap-1">
            {/* Live */}
            <button
              onClick={() => setViewMode('live')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                viewMode === 'live'
                  ? 'bg-surface-2 text-foreground'
                  : 'text-muted hover:text-foreground'
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
              onClick={() => setViewMode('latest')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                viewMode === 'latest'
                  ? 'bg-surface-2 text-foreground'
                  : 'text-muted hover:text-foreground'
              }`}
            >
              Latest
            </button>

            {/* History dropdown trigger */}
            <div className="relative" ref={dropdownRef}>
              <button
                onClick={() => { setViewMode('history'); setDropdownOpen((o) => !o); }}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                  viewMode === 'history'
                    ? 'bg-surface-2 text-foreground'
                    : 'text-muted hover:text-foreground'
                }`}
              >
                {viewMode === 'history' && historySelectedScan
                  ? (historySelectedScan.name ?? historySelectedScan.scan_id.slice(0, 8).toUpperCase())
                  : 'History'}
                <ChevronDown className={`w-3 h-3 transition-transform ${dropdownOpen && viewMode === 'history' ? 'rotate-180' : ''}`} />
              </button>

              {dropdownOpen && viewMode === 'history' && (
                <div className="absolute right-0 mt-1 w-80 bg-surface-1 border border-border rounded-lg shadow-xl z-50 overflow-hidden">
                  {scans.length === 0 ? (
                    <p className="px-4 py-3 text-sm text-muted">No completed scans yet.</p>
                  ) : (
                    <div className="max-h-64 overflow-y-auto">
                      {scans.map((scan) => (
                        <button
                          key={scan.scan_id}
                          onClick={() => { setHistoryScanId(scan.scan_id); setDropdownOpen(false); }}
                          className={`w-full text-left px-4 py-3 text-sm transition-colors border-b border-border last:border-0 ${
                            historyScanId === scan.scan_id
                              ? 'text-[var(--accent)] bg-surface-2'
                              : 'text-muted hover:text-foreground hover:bg-surface-2'
                          }`}
                        >
                          <div className="text-xs text-foreground mb-0.5 font-medium">
                            {scan.name ?? `${scan.scan_type.charAt(0).toUpperCase() + scan.scan_type.slice(1)} Scan`}
                          </div>
                          <div className="text-xs text-[#4B5563] font-mono mb-0.5">
                            {scan.scan_id.slice(0, 8).toUpperCase()}
                          </div>
                          <div className="text-xs text-muted">
                            {new Date(scan.created_at + 'Z').toLocaleString([], {
                              month: 'short', day: 'numeric',
                              hour: '2-digit', minute: '2-digit',
                            })}
                            {' · '}
                            {scan.devices_count}d · {scan.vulns_count}v
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

          <button
            onClick={() => router.push('/scans')}
            className="flex items-center gap-2 px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-[#0F1117] text-sm font-semibold rounded-lg transition-colors"
          >
            <Play className="w-4 h-4" fill="currentColor" />
            New Scan
          </button>
        </div>
      </div>

      {/* In-progress banner — Live view while a scan is running */}
      {viewMode === 'live' && stats.active_scans > 0 && (
        <div className="flex items-start gap-3 px-4 py-3 mb-6 bg-surface-1 border border-border rounded-lg text-sm text-muted">
          <span className="relative flex h-2 w-2 mt-1.5 flex-shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent)] opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--accent)]" />
          </span>
          <span className="flex-1">
            Scan in progress — the network graph, device inventory, and vulnerability data will populate as the scan moves through each stage. Check the Agent Activity feed on the right for live updates.
          </span>
          {scanElapsed > 0 && (
            <span className="font-mono text-xs text-[#4B5563] flex-shrink-0 mt-0.5">
              {formatDuration(scanElapsed)}
            </span>
          )}
        </div>
      )}

      {/* Shallow-scan disclaimer — shown when the viewed scan found no devices */}
      {!(viewMode === 'live' && stats.active_scans > 0) && (() => {
        const referenceScan = effectiveScan ?? scans[0];
        if (!referenceScan || referenceScan.devices_count > 0) return null;
        const isQuick = referenceScan.scan_type === 'quick';
        return (
          <div className="flex items-start gap-3 px-4 py-3 mb-6 bg-surface-1 border border-border rounded-lg text-sm text-muted">
            <Info className="w-4 h-4 mt-0.5 flex-shrink-0 text-[#FFB300]" />
            <span>
              {isQuick
                ? 'This was a Quick scan — it uses a lighter probe intensity that may not detect open ports behind firewalls or on hardened hosts. Try a Deep scan for full service and vulnerability coverage.'
                : 'No devices were detected in this scan. Hosts may be behind a firewall, blocking port probes, or unreachable at scan time. A Deep scan may surface more results.'}
              {' '}
              <button
                onClick={() => router.push('/scans')}
                className="text-[var(--accent)] hover:underline"
              >
                Run a new scan →
              </button>
            </span>
          </div>
        );
      })()}

      {/* Three-column main grid */}
      <div className="grid grid-cols-12 gap-6 mb-6 h-[640px]">
        <div className="col-span-3 min-h-0 overflow-hidden">
          <DeviceList
            onDeviceHover={setHoveredDeviceId}
            scanId={effectiveScanId}
            isLiveMode={viewMode === 'live'}
            liveHosts={liveHosts}
          />
        </div>
        <div className="col-span-6 min-h-0 overflow-hidden">
          <NetworkGraphForce
            topology={coloredTopology}
            hoveredDeviceId={hoveredDeviceId}
            onNodeClick={handleNodeClick}
            pendingColors={viewMode === 'live' && vulns.length === 0 && liveVulns.length === 0}
          />
        </div>
        <div className="col-span-3 min-h-0 overflow-hidden">
          <ActivityFeed />
        </div>
      </div>

      {/* Stat Cards */}
      <div className="mb-6">
        <StatCards
          devicesScanned={displayStats.devices_scanned}
          vulnerabilitiesFound={displayStats.vulnerabilities_found}
          avgCvss={displayStats.avg_cvss}
          activeScans={displayStats.active_scans}
        />
      </div>

      {/* CVE detail panel — shown when a topology node is selected */}
      {selectedNodeIp && (
        <div className="mb-6 bg-surface-1 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="font-semibold text-foreground">
                CVEs — <span className="font-mono">{selectedNodeIp}</span>
                {selectedDevice?.hostname && selectedDevice.hostname !== selectedNodeIp && (
                  <span className="text-muted font-normal text-sm ml-2">({selectedDevice.hostname})</span>
                )}
              </h2>
              <span className="text-xs text-muted">{selectedVulns.length} vulnerabilit{selectedVulns.length === 1 ? 'y' : 'ies'}</span>
            </div>
            <button
              onClick={() => setSelectedNodeIp(null)}
              className="text-muted hover:text-foreground transition-colors"
              aria-label="Close CVE panel"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {selectedVulns.length === 0 ? (
            <p className="text-sm text-muted">No CVEs recorded for this host.</p>
          ) : (
            <div className="grid grid-cols-1 gap-2 max-h-64 overflow-y-auto pr-1">
              {selectedVulns.map((v) => {
                const sev = (v.severity?.toLowerCase() ?? 'low') as Severity;
                const color = SEVERITY_COLORS[sev] ?? '#9CA3AF';
                const score = v.cvss_score_predicted ?? v.cvss_score_raw;
                return (
                  <div key={v.id} className="flex items-start gap-3 p-3 bg-surface-2 rounded-lg">
                    <span className="text-xs font-mono text-muted-foreground mt-0.5 shrink-0 w-36">{v.cve_id}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className="text-xs font-semibold px-1.5 py-0.5 rounded capitalize"
                          style={{ backgroundColor: `${color}20`, color }}
                        >
                          {v.severity ?? 'unknown'}
                        </span>
                        {score != null && (
                          <span className="text-xs text-muted">CVSS {score.toFixed(1)}</span>
                        )}
                        {v.product && (
                          <span className="text-xs text-muted truncate">{v.product}{v.version ? ` ${v.version}` : ''}</span>
                        )}
                      </div>
                      {v.summary && (
                        <p className="text-xs text-muted-foreground line-clamp-2">{v.summary}</p>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Bottom row */}
      <div className="grid grid-cols-2 gap-6">
        <VulnerabilityChart
          scanId={effectiveScanId}
          isLiveMode={viewMode === 'live'}
          liveVulns={liveVulns}
        />
        <ExploitQueue vulns={vulns} isLiveMode={viewMode === 'live'} liveVulns={liveVulns} />
      </div>
    </div>
  );
}
