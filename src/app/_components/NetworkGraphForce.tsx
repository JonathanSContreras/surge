'use client';

import { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import { NetworkTopology, ForceNode, ForceEdge, SEVERITY_COLORS } from './types/network-topology';
import { createForceSimulation, transformTopologyData } from './utils/force-layout';
import { getDeviceIcon } from './utils/device-icons';

interface NetworkGraphForceProps {
  topology: NetworkTopology;
  hoveredDeviceId?: string | null;
  onNodeClick?: (deviceId: string) => void;
  onNodeHover?: (deviceId: string | null) => void;
}

export function NetworkGraphForce({
  topology,
  hoveredDeviceId,
  onNodeClick,
  onNodeHover,
}: NetworkGraphForceProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [mode, setMode] = useState<'Live' | 'Demo'>('Live');
  const [progress, setProgress] = useState(67);
  const [elapsed, setElapsed] = useState(142);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [nodes, setNodes] = useState<ForceNode[]>([]);
  const [edges, setEdges] = useState<ForceEdge[]>([]);
  const [simulationActive, setSimulationActive] = useState(false);

  // Progress bar effect
  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => (prev >= 100 ? 0 : prev + 1));
      setElapsed((prev) => prev + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  // Initialize force simulation
  useEffect(() => {
    if (!svgRef.current) return;

    const { width, height } = svgRef.current.getBoundingClientRect();
    const { nodes: initialNodes, edges: initialEdges } = transformTopologyData(topology);

    setNodes(initialNodes);
    setEdges(initialEdges);
    setSimulationActive(true);

    const simulation = createForceSimulation(initialNodes, initialEdges, width, height);

    // Throttle updates to ~30fps for better performance
    let lastUpdate = 0;
    const throttleDelay = 33; // ~30fps

    simulation.on('tick', () => {
      const now = Date.now();
      if (now - lastUpdate > throttleDelay) {
        setNodes([...simulation.nodes() as ForceNode[]]);
        lastUpdate = now;
      }
    });

    simulation.on('end', () => {
      setSimulationActive(false);
      setNodes([...simulation.nodes() as ForceNode[]]);
    });

    return () => {
      simulation.stop();
    };
  }, [topology]);

  const getNodePosition = (id: string) => {
    return nodes.find((n) => n.id === id);
  };

  const getCurvedPath = (edge: ForceEdge) => {
    const fromNode = typeof edge.source === 'object' ? edge.source : getNodePosition(edge.source);
    const toNode = typeof edge.target === 'object' ? edge.target : getNodePosition(edge.target);

    if (!fromNode || !toNode || fromNode.x === undefined || fromNode.y === undefined ||
        toNode.x === undefined || toNode.y === undefined) {
      return '';
    }

    const dx = toNode.x - fromNode.x;
    const dy = toNode.y - fromNode.y;
    const dr = Math.sqrt(dx * dx + dy * dy) * 0.3;

    return `M ${fromNode.x} ${fromNode.y} Q ${fromNode.x + dx / 2 + dr / 2} ${
      fromNode.y + dy / 2 - dr / 2
    } ${toNode.x} ${toNode.y}`;
  };

  const handleNodeHover = (nodeId: string | null) => {
    setHoveredNode(nodeId);
    if (onNodeHover) {
      onNodeHover(nodeId);
    }
  };

  const handleNodeClick = (nodeId: string) => {
    const newSelected = selectedNode === nodeId ? null : nodeId;
    setSelectedNode(newSelected);
    if (onNodeClick && newSelected) {
      onNodeClick(newSelected);
    }
  };

  // Check if an edge is connected to the hovered/selected node
  const isEdgeHighlighted = (edge: ForceEdge, activeNodeId: string | null) => {
    if (!activeNodeId) return false;

    const sourceId = typeof edge.source === 'object' ? edge.source.id : edge.source;
    const targetId = typeof edge.target === 'object' ? edge.target.id : edge.target;

    return sourceId === activeNodeId || targetId === activeNodeId;
  };

  return (
    <div className="bg-[#13151C] rounded-lg h-full flex flex-col">
      {/* Header with mode toggle */}
      <div className="p-4 flex items-center justify-between border-b border-[#1F2937]">
        <h2 className="font-semibold text-white">Network Topology</h2>
        <div className="flex items-center gap-0 bg-[#0F1117] rounded p-0.5">
          <button
            onClick={() => setMode('Live')}
            className={`px-3 py-1 rounded text-xs font-medium transition-all ${
              mode === 'Live' ? 'bg-[#16181F] text-white' : 'text-[#6B7280] hover:text-white'
            }`}
          >
            Live
          </button>
          <button
            onClick={() => setMode('Demo')}
            className={`px-3 py-1 rounded text-xs font-medium transition-all ${
              mode === 'Demo' ? 'bg-[#16181F] text-white' : 'text-[#6B7280] hover:text-white'
            }`}
          >
            Demo
          </button>
        </div>
      </div>

      {/* Graph */}
      <div className="flex-1 relative overflow-hidden">
        {/* Grid background */}
        <svg
          ref={svgRef}
          className="absolute inset-0 w-full h-full"
          style={{ background: 'transparent' }}
        >
          <defs>
            <pattern
              id="grid"
              width="40"
              height="40"
              patternUnits="userSpaceOnUse"
            >
              <path
                d="M 40 0 L 0 0 0 40"
                fill="none"
                stroke="#1F2937"
                strokeWidth="0.5"
                opacity="0.3"
              />
            </pattern>
            {/* Glow filters */}
            <filter id="glow-critical" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid)" />

          {/* Edges */}
          <g>
            {edges.map((edge, i) => {
              const activeNodeId = hoveredNode || selectedNode;
              const isHighlighted = isEdgeHighlighted(edge, activeNodeId);
              const hasAnyHover = hoveredNode !== null || selectedNode !== null;

              return (
                <motion.path
                  key={i}
                  d={getCurvedPath(edge)}
                  stroke={isHighlighted ? '#00E676' : '#2D3748'}
                  strokeWidth={isHighlighted ? '2.5' : '1.5'}
                  fill="none"
                  opacity={hasAnyHover ? (isHighlighted ? 1 : 0.2) : 0.6}
                  animate={{
                    stroke: isHighlighted ? '#00E676' : '#2D3748',
                    strokeWidth: isHighlighted ? 2.5 : 1.5,
                    opacity: hasAnyHover ? (isHighlighted ? 1 : 0.2) : 0.6,
                  }}
                  transition={{ duration: 0.2 }}
                  style={{ pointerEvents: 'none' }}
                />
              );
            })}
          </g>

          {/* Nodes */}
          <g>
            {nodes.map((node) => {
              if (node.x === undefined || node.y === undefined) return null;

              const isHovered = hoveredDeviceId === node.id || hoveredNode === node.id;
              const isSelected = selectedNode === node.id;
              const isCritical = node.severity === 'critical';
              const DeviceIcon = getDeviceIcon(node.deviceType);

              return (
                <g key={node.id}>
                  {/* Outer glow for critical */}
                  {isCritical && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r="24"
                      fill={SEVERITY_COLORS[node.severity]}
                      opacity="0.15"
                      filter="url(#glow-critical)"
                    />
                  )}
                  {/* Node circle */}
                  <motion.circle
                    cx={node.x}
                    cy={node.y}
                    r="16"
                    fill="#16181F"
                    stroke={SEVERITY_COLORS[node.severity]}
                    strokeWidth={isHovered || isSelected ? "3" : "2"}
                    animate={{
                      scale: isHovered || isSelected ? 1.15 : 1,
                    }}
                    transition={{ duration: 0.2 }}
                    style={{
                      transformOrigin: `${node.x}px ${node.y}px`,
                      cursor: 'pointer',
                    }}
                    onMouseEnter={() => handleNodeHover(node.id)}
                    onMouseLeave={() => handleNodeHover(null)}
                    onClick={() => handleNodeClick(node.id)}
                  />
                  {/* Device icon */}
                  <g transform={`translate(${node.x - 8}, ${node.y - 8})`}>
                    <DeviceIcon
                      size={16}
                      color={SEVERITY_COLORS[node.severity]}
                      style={{ pointerEvents: 'none' }}
                    />
                  </g>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Tooltip */}
        {(hoveredNode || selectedNode) && (() => {
          const activeNode = nodes.find(n => n.id === (hoveredNode || selectedNode));
          if (!activeNode || activeNode.x === undefined || activeNode.y === undefined) return null;

          return (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ duration: 0.15 }}
              className="absolute bg-[#1F2937] rounded-lg p-3 shadow-xl border border-[#374151] pointer-events-none z-10"
              style={{
                left: `${activeNode.x + 30}px`,
                top: `${activeNode.y - 20}px`,
              }}
            >
              <div className="flex flex-col gap-1.5 min-w-[150px]">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-[#9CA3AF] font-medium">IP Address</span>
                  <span className="text-sm text-white font-mono">{activeNode.ip}</span>
                </div>
                {activeNode.hostname && (
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-[#9CA3AF] font-medium">Hostname</span>
                    <span className="text-sm text-white font-mono">{activeNode.hostname}</span>
                  </div>
                )}
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-[#9CA3AF] font-medium">Device Type</span>
                  <span className="text-xs text-white capitalize">{activeNode.deviceType}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-[#9CA3AF] font-medium">Severity</span>
                  <span
                    className="text-xs font-semibold px-2 py-0.5 rounded capitalize"
                    style={{
                      backgroundColor: `${SEVERITY_COLORS[activeNode.severity]}20`,
                      color: SEVERITY_COLORS[activeNode.severity],
                    }}
                  >
                    {activeNode.severity}
                  </span>
                </div>
                {activeNode.description && (
                  <div className="mt-1 pt-1.5 border-t border-[#374151]">
                    <p className="text-xs text-[#9CA3AF]">{activeNode.description}</p>
                  </div>
                )}
              </div>
            </motion.div>
          );
        })()}
      </div>

      {/* Progress bar */}
      <div className="p-4 border-t border-[#1F2937]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#6B7280]">
            Active Scan Progress {simulationActive && '(Calculating layout...)'}
          </span>
          <div className="flex items-center gap-3">
            <span className="text-xs text-[#6B7280]">
              {Math.floor(elapsed / 60)}:{(elapsed % 60).toString().padStart(2, '0')} elapsed
            </span>
            <span className="text-xs font-semibold text-white">{progress}%</span>
          </div>
        </div>
        <div className="h-1 bg-[#1F2937] rounded-full overflow-hidden">
          <motion.div
            className="h-full bg-[#00E676]"
            initial={{ width: 0 }}
            animate={{ width: `${progress}%` }}
            transition={{ duration: 0.3 }}
          />
        </div>
      </div>
    </div>
  );
}
