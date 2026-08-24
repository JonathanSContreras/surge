'use client';

import { useEffect, useRef, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Radar, FileSearch, Cpu, GitMerge, Bug, ListFilter, TrendingUp, FileText,
  CheckCircle, Play, ChevronRight,
} from 'lucide-react';
import { motion } from 'motion/react';
import {
  getActivityFeed,
  getDashboardStats,
  getScans,
  formatDuration,
  type ActivityEventRecord,
  type DashboardStats,
  type ScanRecord,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Agent definitions
// ---------------------------------------------------------------------------

type AgentStatus = 'idle' | 'active' | 'completed';

interface AgentDef {
  id: string;
  name: string;
  shortName: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  icon: React.ComponentType<any>;
  stage: number;
  color: string;
  what: string;
  why: string;
  outputs: string[];
}

const AGENTS: AgentDef[] = [
  {
    id: 'recon',
    name: 'Recon Agent',
    shortName: 'Recon',
    icon: Radar,
    stage: 1,
    color: '#3B82F6',
    what: 'Runs progressive Nmap scans across the target range, discovering hosts, open ports, and running services. Iterates until the network is fully mapped.',
    why: "You can't secure what you can't see. Recon builds the complete attack surface map before any analysis begins.",
    outputs: ['Host list', 'Open ports', 'Service banners', 'Network topology'],
  },
  {
    id: 'os_finder',
    name: 'OS Fingerprinter',
    shortName: 'OS Finder',
    icon: Cpu,
    stage: 2,
    color: '#EC4899',
    what: 'Runs aggressive OS detection via Nmap on each discovered host, extracting OS family, version hints, accuracy scores, and CPE identifiers.',
    why: 'OS identity is critical for CVE matching. Linux 5.4 and Windows Server 2019 have entirely different vulnerability profiles.',
    outputs: ['OS family per host', 'Version hints', 'CPE strings', 'Confidence scores'],
  },
  {
    id: 'recon_analyzer',
    name: 'Recon Analyzer',
    shortName: 'Analyzer',
    icon: FileSearch,
    stage: 2,
    color: '#8B5CF6',
    what: 'Uses an LLM to parse raw Nmap output, extracting structured host data, identifying device roles, and surfacing anomalies in the network layout.',
    why: 'Raw Nmap XML is noisy. This agent distills it into actionable intelligence — servers, routers, and endpoints clearly separated.',
    outputs: ['Structured host data', 'Device roles', 'Network anomalies'],
  },
  {
    id: 'os_analyzer',
    name: 'OS Analyzer',
    shortName: 'OS Analyzer',
    icon: GitMerge,
    stage: 3,
    color: '#F59E0B',
    what: 'Merges recon analysis with OS fingerprint data to build complete per-host profiles. Acts as the fan-in node after the two parallel discovery branches.',
    why: 'Combining network context with OS identity enables precise vulnerability matching — the same service on Linux vs. Windows maps to different CVEs.',
    outputs: ['Full host profiles', 'Normalized CPE strings', 'Combined context'],
  },
  {
    id: 'vulnerability',
    name: 'Vulnerability Agent',
    shortName: 'Vuln Agent',
    icon: Bug,
    stage: 4,
    color: '#EF4444',
    what: 'Queries the NVD CVE database for each service and OS combination. Matches CPE strings against known vulnerabilities and filters by relevance.',
    why: 'This is the core intelligence step — mapping real, exploitable CVEs to every service on every host in the network.',
    outputs: ['CVE list per host', 'Affected products', 'Exploit availability'],
  },
  {
    id: 'cvss_data_formatter',
    name: 'CVSS Formatter',
    shortName: 'Formatter',
    icon: ListFilter,
    stage: 5,
    color: '#10B981',
    what: 'Normalizes raw vulnerability data from the CVE lookup step, deduplicating entries and preparing uniform feature vectors for the ML scoring model.',
    why: 'Raw CVE data is inconsistent across vendors and versions. Clean, uniform features are essential for accurate ML predictions.',
    outputs: ['Normalized CVE records', 'Feature vectors', 'Deduplicated entries'],
  },
  {
    id: 'cvss_scoring',
    name: 'CVSS Scorer',
    shortName: 'Scorer',
    icon: TrendingUp,
    stage: 6,
    color: '#F97316',
    what: 'Runs a trained XGBoost regression model to predict CVSS scores for CVEs that lack official scores, using service context and CPE data as features.',
    why: 'Many CVEs in the wild lack official CVSS scores. The ML model fills that gap so every vulnerability gets a risk score for prioritization.',
    outputs: ['Predicted CVSS scores', 'Severity labels', 'Risk ranking'],
  },
  {
    id: 'reporter',
    name: 'Reporter',
    shortName: 'Reporter',
    icon: FileText,
    stage: 7,
    color: 'var(--accent)',
    what: 'Aggregates all findings into a structured Network Security Assessment — host summaries, CVE details, severity breakdowns, and remediation steps.',
    why: "Raw data isn't actionable. The reporter synthesizes everything into a format security teams and executives can act on immediately.",
    outputs: ['Scan summary', 'CVE report', 'Remediation steps', 'Dashboard data'],
  },
];

const AGENT_BY_ID = Object.fromEntries(AGENTS.map((a) => [a.id, a]));

// ---------------------------------------------------------------------------
// Status derivation
// ---------------------------------------------------------------------------

function deriveStatuses(
  events: ActivityEventRecord[],
  activeScanCount: number,
): Record<string, AgentStatus> {
  const allIdle = Object.fromEntries(
    AGENTS.map((a) => [a.id, 'idle' as AgentStatus]),
  );

  // Only consider events that carry both a scan_id and an agent_node.
  // Events are newest-first, so the first matching scan_id is the current scan.
  const agentEvents = events.filter((e) => e.agent_node && e.scan_id);
  if (agentEvents.length === 0) return allIdle;

  const currentScanId = agentEvents[0].scan_id;
  const currentEvents = agentEvents.filter((e) => e.scan_id === currentScanId);

  const seenNodes = new Set(currentEvents.map((e) => e.agent_node as string));
  const maxStage = AGENTS.filter((a) => seenNodes.has(a.id)).reduce(
    (max, a) => Math.max(max, a.stage),
    0,
  );

  const result: Record<string, AgentStatus> = {};
  for (const agent of AGENTS) {
    if (!seenNodes.has(agent.id)) {
      result[agent.id] = 'idle';
    } else if (activeScanCount > 0 && agent.stage === maxStage) {
      result[agent.id] = 'active';
    } else {
      result[agent.id] = 'completed';
    }
  }
  return result;
}

function currentStageLabel(statuses: Record<string, AgentStatus>): string | null {
  const active = AGENTS.find((a) => statuses[a.id] === 'active');
  if (active) return `Stage ${active.stage} of 7 — ${active.name}`;
  const allDone = AGENTS.every((a) => statuses[a.id] === 'completed');
  if (allDone) return 'All stages complete';
  return null;
}

// ---------------------------------------------------------------------------
// Layout constants — all SVG math derives from these
// ---------------------------------------------------------------------------

const N_W = 136;   // node card width
const N_H = 116;   // node card height
const P_GAP = 20;  // vertical gap between parallel rows
const PAR_H = N_H * 2 + P_GAP;       // = 252, total height of parallel section
const ARM_T = N_H / 2;                // = 58, Y of top row center
const ARM_B = N_H + P_GAP + N_H / 2; // = 194, Y of bottom row center
const STEM_Y = PAR_H / 2;             // = 126, Y of stem (aligns with single nodes)
const F_W = 58;    // fork/join connector horizontal width
const ARR_W = 44;  // sequential arrow width

// Second fork: top row = vulnerability → formatter → scorer
const CHAIN_W = 3 * N_W + 2 * ARR_W;  // = 496px, width of the vuln chain

// ---------------------------------------------------------------------------
// Pipeline node card
// ---------------------------------------------------------------------------

interface PipelineNodeProps {
  agent: AgentDef;
  status: AgentStatus;
  isHovered: boolean;
  onHover: (id: string | null) => void;
}

function PipelineNode({ agent, status, isHovered, onHover }: PipelineNodeProps) {
  const Icon = agent.icon;
  const isIdle = status === 'idle';
  const isActive = status === 'active';
  const isDone = status === 'completed';
  const hideTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function cancelHide() {
    if (hideTimer.current) { clearTimeout(hideTimer.current); hideTimer.current = null; }
  }
  function scheduleHide() {
    cancelHide();
    hideTimer.current = setTimeout(() => onHover(null), 180);
  }

  return (
    <div
      className="relative flex-shrink-0"
      style={{ width: N_W, height: N_H }}
      onMouseEnter={() => { cancelHide(); onHover(agent.id); }}
      onMouseLeave={scheduleHide}
    >
      {/* Card */}
      <div
        className="w-full h-full rounded-2xl border-2 flex flex-col items-center justify-center gap-2 cursor-default transition-all duration-500 select-none"
        style={{
          backgroundColor: 'var(--surface-1)',
          borderColor: isIdle ? 'var(--border)' : isActive ? agent.color : `${agent.color}55`,
          opacity: isIdle ? 0.28 : 1,
          boxShadow: isActive
            ? `0 0 28px ${agent.color}50, 0 0 10px ${agent.color}30`
            : isDone
            ? `0 0 12px ${agent.color}20`
            : 'none',
        }}
      >
        {/* Icon */}
        <div className="relative">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center"
            style={{ backgroundColor: isIdle ? 'var(--surface-2)' : `${agent.color}22` }}
          >
            <Icon
              className="w-5 h-5"
              style={{ color: isIdle ? 'var(--muted)' : agent.color }}
            />
          </div>
          {isActive && (
            <span
              className="absolute inset-0 rounded-xl animate-ping opacity-25"
              style={{ backgroundColor: agent.color }}
            />
          )}
        </div>

        {/* Name */}
        <span
          className="text-[10px] font-semibold text-center leading-tight px-2"
          style={{ color: isIdle ? 'var(--muted)' : isActive ? 'var(--foreground)' : 'var(--muted-foreground)' }}
        >
          {agent.shortName}
        </span>
      </div>

      {/* Completed checkmark */}
      {isDone && (
        <CheckCircle className="absolute top-1.5 right-1.5 w-3.5 h-3.5 text-[var(--accent)]" />
      )}

      {/* Active pulse dot */}
      {isActive && (
        <span
          className="absolute top-2 right-2 w-2 h-2 rounded-full animate-pulse"
          style={{ backgroundColor: agent.color }}
        />
      )}

      {/* Hover modal — appears above the card */}
      {isHovered && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.15 }}
          className="absolute bottom-full mb-4 z-50 w-[420px] rounded-2xl border border-border shadow-2xl"
          style={{
            backgroundColor: 'var(--surface-1)',
            left: '50%',
            transform: 'translateX(-50%)',
          }}
          onMouseEnter={cancelHide}
          onMouseLeave={scheduleHide}
        >
          <div className="h-1.5 w-full rounded-t-2xl" style={{ backgroundColor: agent.color }} />
          <div className="p-6">
            <div className="flex items-center gap-4 mb-4">
              <div
                className="w-11 h-11 rounded-xl flex items-center justify-center flex-shrink-0"
                style={{ backgroundColor: `${agent.color}22` }}
              >
                <Icon className="w-6 h-6" style={{ color: agent.color }} />
              </div>
              <div>
                <p className="font-semibold text-foreground text-base leading-tight">{agent.name}</p>
                <p className="text-xs text-muted mt-0.5">Stage {agent.stage}</p>
              </div>
            </div>

            <p className="text-sm text-muted-foreground leading-relaxed mb-4">{agent.what}</p>

            <div className="mb-4">
              <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-1.5">
                Why it matters
              </p>
              <p className="text-sm text-muted leading-relaxed">{agent.why}</p>
            </div>

            <div>
              <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2">
                Outputs
              </p>
              <div className="flex flex-wrap gap-1.5">
                {agent.outputs.map((o) => (
                  <span
                    key={o}
                    className="text-xs px-2.5 py-1 rounded-full font-medium"
                    style={{ backgroundColor: `${agent.color}18`, color: agent.color }}
                  >
                    {o}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sequential arrow connector
// ---------------------------------------------------------------------------

function Arrow({ color }: { color: string }) {
  return (
    <div className="flex items-center flex-shrink-0" style={{ width: ARR_W }}>
      <div className="flex-1 h-px" style={{ backgroundColor: color }} />
      <ChevronRight className="w-3.5 h-3.5 -ml-1" style={{ color }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Fork connector: single input → two outputs (top + bottom rows)
// Width=F_W, Height=PAR_H; stem at STEM_Y, arms at ARM_T and ARM_B
// ---------------------------------------------------------------------------

function ForkConn({ color }: { color: string }) {
  return (
    <svg width={F_W} height={PAR_H} className="flex-shrink-0" style={{ display: 'block' }}>
      <line x1={0} y1={STEM_Y} x2={F_W / 2} y2={STEM_Y} style={{ stroke: color }} strokeWidth={1.5} />
      <line x1={F_W / 2} y1={ARM_T} x2={F_W / 2} y2={ARM_B} style={{ stroke: color }} strokeWidth={1.5} />
      <line x1={F_W / 2} y1={ARM_T} x2={F_W - 8} y2={ARM_T} style={{ stroke: color }} strokeWidth={1.5} />
      <polygon points={`${F_W - 8},${ARM_T - 4} ${F_W},${ARM_T} ${F_W - 8},${ARM_T + 4}`} style={{ fill: color }} />
      <line x1={F_W / 2} y1={ARM_B} x2={F_W - 8} y2={ARM_B} style={{ stroke: color }} strokeWidth={1.5} />
      <polygon points={`${F_W - 8},${ARM_B - 4} ${F_W},${ARM_B} ${F_W - 8},${ARM_B + 4}`} style={{ fill: color }} />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Join connector: two inputs (top + bottom) → single output
// ---------------------------------------------------------------------------

function JoinConn({ topColor, botColor }: { topColor: string; botColor: string }) {
  const stemColor = topColor;
  return (
    <svg width={F_W} height={PAR_H} className="flex-shrink-0" style={{ display: 'block' }}>
      <line x1={0} y1={ARM_T} x2={F_W / 2} y2={ARM_T} style={{ stroke: topColor }} strokeWidth={1.5} />
      <line x1={0} y1={ARM_B} x2={F_W / 2} y2={ARM_B} style={{ stroke: botColor }} strokeWidth={1.5} />
      <line x1={F_W / 2} y1={ARM_T} x2={F_W / 2} y2={ARM_B} style={{ stroke: stemColor }} strokeWidth={1.5} />
      <line x1={F_W / 2} y1={STEM_Y} x2={F_W - 8} y2={STEM_Y} style={{ stroke: stemColor }} strokeWidth={1.5} />
      <polygon
        points={`${F_W - 8},${STEM_Y - 4} ${F_W},${STEM_Y} ${F_W - 8},${STEM_Y + 4}`}
        style={{ fill: stemColor }}
      />
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Bypass row: dashed horizontal line (direct os_analyzer → reporter path)
// Rendered as the "bottom row" of the second fork section
// Width = CHAIN_W, Height = N_H (same as a node card, so SVG math holds)
// ---------------------------------------------------------------------------

function BypassRow({ color }: { color: string }) {
  const cy = N_H / 2;
  return (
    <svg
      width={CHAIN_W}
      height={N_H}
      className="flex-shrink-0"
      style={{ display: 'block' }}
    >
      <line
        x1={0} y1={cy} x2={CHAIN_W} y2={cy}
        style={{ stroke: color }} strokeWidth={1.5} strokeDasharray="7 5"
      />
      <text
        x={CHAIN_W / 2} y={cy - 10}
        textAnchor="middle"
        style={{ fontSize: '9px', fill: 'var(--muted)', fontFamily: 'inherit', letterSpacing: '0.05em' }}
      >
        DIRECT PATH
      </text>
    </svg>
  );
}

// ---------------------------------------------------------------------------
// Start / End pill nodes
// ---------------------------------------------------------------------------

function StartPill() {
  return (
    <div className="flex-shrink-0 px-4 py-1.5 rounded-full border border-border bg-surface-2 text-[11px] font-mono text-muted">
      __start__
    </div>
  );
}

function EndPill({ lit }: { lit: boolean }) {
  return (
    <div
      className="flex-shrink-0 px-4 py-1.5 rounded-full border text-[11px] font-mono transition-all duration-500"
      style={{
        borderColor: lit ? 'color-mix(in srgb, var(--accent) 25%, transparent)' : 'var(--border-light)',
        backgroundColor: lit ? 'color-mix(in srgb, var(--accent) 7%, transparent)' : 'var(--surface-2)',
        color: lit ? 'var(--accent)' : '#4B5563',
      }}
    >
      __end__
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

const DEFAULT_STATS: DashboardStats = {
  devices_scanned: 0,
  vulnerabilities_found: 0,
  avg_cvss: null,
  active_scans: 0,
};

export function Agents() {
  const router = useRouter();
  const [events, setEvents] = useState<ActivityEventRecord[]>([]);
  const [stats, setStats]   = useState<DashboardStats>(DEFAULT_STATS);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [runningScan, setRunningScan] = useState<ScanRecord | null>(null);
  const [scanElapsed, setScanElapsed] = useState(0);

  useEffect(() => {
    const refresh = () =>
      Promise.all([
        getActivityFeed(200).then(setEvents),
        getDashboardStats().then(setStats),
        getScans().then((all) => {
          setRunningScan(all.find((s) => s.status === 'running') ?? null);
        }),
      ]).catch(console.error);

    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!runningScan) return;
    const start = new Date(runningScan.created_at + 'Z').getTime();
    setScanElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    const interval = setInterval(() => {
      setScanElapsed(Math.max(0, Math.floor((Date.now() - start) / 1000)));
    }, 1000);
    return () => clearInterval(interval);
  }, [runningScan]);

  const statuses = deriveStatuses(events, stats.active_scans);
  const stageLabel = currentStageLabel(statuses);
  const anyActive = AGENTS.some((a) => statuses[a.id] === 'active');
  const anyStarted = AGENTS.some((a) => statuses[a.id] !== 'idle');
  const allDone = AGENTS.every((a) => statuses[a.id] === 'completed');
  const isIdle = !anyStarted;

  // Connector color: lit when upstream node is completed, else dim
  const cc = (id: string) =>
    statuses[id] === 'completed' ? 'var(--muted)' : statuses[id] === 'active' ? 'var(--border-light)' : 'var(--border)';

  // Fork 1 (after recon): both arms light when recon completes
  const fork1Color = cc('recon');
  // Join 1 (into os_analyzer): top = os_finder done, bot = recon_analyzer done
  const join1Top = cc('os_finder');
  const join1Bot = cc('recon_analyzer');
  // Fork 2 (after os_analyzer): both arms light when os_analyzer completes
  const fork2Color = cc('os_analyzer');
  // Join 2 (into reporter): top = cvss_scoring done, bot = os_analyzer done (bypass)
  const join2Top = cc('cvss_scoring');
  const join2Bot = cc('os_analyzer');

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      {/* Page header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Agent Pipeline</h1>
          <p className="text-sm text-muted mt-0.5">
            8 specialized AI agents work in sequence to deliver a complete network security assessment.
          </p>
        </div>
        {stageLabel && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-surface-1 border border-border rounded-lg">
            {anyActive ? (
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--accent)] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[var(--accent)]" />
              </span>
            ) : (
              <CheckCircle className="w-3.5 h-3.5 text-[var(--accent)]" />
            )}
            <span className="text-sm text-foreground font-medium">{stageLabel}</span>
            {anyActive && scanElapsed > 0 && (
              <span className="text-xs font-mono text-[#4B5563] border-l border-border pl-2">
                {formatDuration(scanElapsed)}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Idle banner */}
      {isIdle && (
        <div className="flex items-center justify-between gap-4 px-5 py-3.5 mb-6 bg-surface-1 border border-border rounded-xl text-sm text-muted">
          <span>Agents are standing by. Run a scan to see the pipeline in action.</span>
          <button
            onClick={() => router.push('/scans')}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-[#0F1117] text-xs font-semibold rounded-lg transition-colors flex-shrink-0"
          >
            <Play className="w-3 h-3" fill="currentColor" />
            New Scan
          </button>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Pipeline visualization — fills viewport, centered both axes        */}
      {/* ------------------------------------------------------------------ */}
      <div
        className="bg-surface-1 rounded-2xl border border-border flex items-center justify-center"
        style={{ minHeight: 'calc(100vh - 230px)' }}
      >
        <div className="flex items-center flex-shrink-0">

            {/* __start__ */}
            <StartPill />

            {/* start → recon */}
            <Arrow color={cc('recon')} />

            {/* Recon */}
            <PipelineNode
              agent={AGENT_BY_ID['recon']}
              status={statuses['recon']}
              isHovered={hoveredNode === 'recon'}
              onHover={setHoveredNode}
            />

            {/* Fork 1: recon → os_finder (top) + recon_analyzer (bottom) */}
            <ForkConn color={fork1Color} />

            {/* Parallel section 1: os_finder (top row) + recon_analyzer (bottom row) */}
            <div className="flex flex-col flex-shrink-0" style={{ gap: P_GAP }}>
              <PipelineNode
                agent={AGENT_BY_ID['os_finder']}
                status={statuses['os_finder']}
                isHovered={hoveredNode === 'os_finder'}
                onHover={setHoveredNode}
              />
              <PipelineNode
                agent={AGENT_BY_ID['recon_analyzer']}
                status={statuses['recon_analyzer']}
                isHovered={hoveredNode === 'recon_analyzer'}
                onHover={setHoveredNode}
              />
            </div>

            {/* Join 1: os_finder + recon_analyzer → os_analyzer */}
            <JoinConn topColor={join1Top} botColor={join1Bot} />

            {/* OS Analyzer */}
            <PipelineNode
              agent={AGENT_BY_ID['os_analyzer']}
              status={statuses['os_analyzer']}
              isHovered={hoveredNode === 'os_analyzer'}
              onHover={setHoveredNode}
            />

            {/* Fork 2: os_analyzer → vuln chain (top) + direct bypass (bottom) */}
            <ForkConn color={fork2Color} />

            {/* Parallel section 2: vuln chain (top) + bypass line (bottom) */}
            <div className="flex flex-col flex-shrink-0" style={{ gap: P_GAP }}>
              {/* Top row: vulnerability → cvss_formatter → cvss_scoring */}
              <div className="flex items-center flex-shrink-0">
                <PipelineNode
                  agent={AGENT_BY_ID['vulnerability']}
                  status={statuses['vulnerability']}
                  isHovered={hoveredNode === 'vulnerability'}
                  onHover={setHoveredNode}
                />
                <Arrow color={cc('vulnerability')} />
                <PipelineNode
                  agent={AGENT_BY_ID['cvss_data_formatter']}
                  status={statuses['cvss_data_formatter']}
                  isHovered={hoveredNode === 'cvss_data_formatter'}
                  onHover={setHoveredNode}
                />
                <Arrow color={cc('cvss_data_formatter')} />
                <PipelineNode
                  agent={AGENT_BY_ID['cvss_scoring']}
                  status={statuses['cvss_scoring']}
                  isHovered={hoveredNode === 'cvss_scoring'}
                  onHover={setHoveredNode}
                />
              </div>

              {/* Bottom row: bypass dashed line (direct os_analyzer → reporter) */}
              <BypassRow color={fork2Color} />
            </div>

            {/* Join 2: vuln chain + bypass → reporter */}
            <JoinConn topColor={join2Top} botColor={join2Bot} />

            {/* Reporter */}
            <PipelineNode
              agent={AGENT_BY_ID['reporter']}
              status={statuses['reporter']}
              isHovered={hoveredNode === 'reporter'}
              onHover={setHoveredNode}
            />

            {/* reporter → __end__ */}
            <Arrow color={cc('reporter')} />

            {/* __end__ */}
            <EndPill lit={allDone} />

          </div>
      </div>
    </div>
  );
}

