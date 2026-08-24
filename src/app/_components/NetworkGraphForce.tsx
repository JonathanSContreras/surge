'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import { motion } from 'motion/react';
import { NetworkTopology, ForceNode, ForceEdge, SEVERITY_COLORS } from './types/network-topology';
import { createForceSimulation, transformTopologyData } from './utils/force-layout';
import { getDeviceIcon } from './utils/device-icons';

interface NetworkGraphForceProps {
  topology: NetworkTopology;
  hoveredDeviceId?: string | null;
  onNodeClick?: (deviceId: string) => void;
  onNodeHover?: (deviceId: string | null) => void;
  pendingColors?: boolean;  // when true, render all nodes neutral grey (scoring not yet confirmed)
}

const MIN_ZOOM = 0.2;
const MAX_ZOOM = 5;
const ZOOM_SENSITIVITY = 0.001;

const PENDING_NODE_COLOR = '#374151';  // neutral grey used when scoring not yet confirmed

export function NetworkGraphForce({
  topology,
  hoveredDeviceId,
  onNodeClick,
  onNodeHover,
  pendingColors = false,
}: NetworkGraphForceProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const [dimensions, setDimensions] = useState({ width: 600, height: 400 });
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [nodes, setNodes] = useState<ForceNode[]>([]);
  const [edges, setEdges] = useState<ForceEdge[]>([]);
  const [simulationActive, setSimulationActive] = useState(false);

  // Pan & zoom state
  const [viewBox, setViewBox] = useState({ x: 0, y: 0, w: 600, h: 400 });
  const zoomRef = useRef(1);
  const isPanningRef = useRef(false);
  const panStartRef = useRef({ x: 0, y: 0 });
  const viewBoxStartRef = useRef({ x: 0, y: 0 });
  const [zoomLevel, setZoomLevel] = useState(1);

  // Initialize viewBox when dimensions change
  useEffect(() => {
    setViewBox({ x: 0, y: 0, w: dimensions.width, h: dimensions.height });
    zoomRef.current = 1;
    setZoomLevel(1);
  }, [dimensions]);

  useEffect(() => {
    const updateDimensions = () => {
      if (containerRef.current) {
        const { width, height } = containerRef.current.getBoundingClientRect();
        setDimensions({ width, height });
      }
    };

    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  useEffect(() => {
    const { width, height } = dimensions;
    if (width === 0 || height === 0) return;

    const { nodes: initialNodes, edges: initialEdges } = transformTopologyData(topology);

    setNodes(initialNodes);
    setEdges(initialEdges);
    setSimulationActive(true);

    const simulation = createForceSimulation(initialNodes, initialEdges, width, height);

    let lastUpdate = 0;
    const throttleDelay = 33;

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
  }, [topology, dimensions]);

  // --- Zoom handler (wheel) ---
  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    const container = containerRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    // Cursor position as fraction of container
    const cursorFracX = (e.clientX - rect.left) / rect.width;
    const cursorFracY = (e.clientY - rect.top) / rect.height;

    const zoomDelta = -e.deltaY * ZOOM_SENSITIVITY;
    const oldZoom = zoomRef.current;
    const newZoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, oldZoom * (1 + zoomDelta)));

    setViewBox((prev) => {
      // Point in graph-space under cursor
      const cursorGraphX = prev.x + cursorFracX * prev.w;
      const cursorGraphY = prev.y + cursorFracY * prev.h;

      const newW = dimensions.width / newZoom;
      const newH = dimensions.height / newZoom;

      // Keep the point under the cursor stationary
      const newX = cursorGraphX - cursorFracX * newW;
      const newY = cursorGraphY - cursorFracY * newH;

      return { x: newX, y: newY, w: newW, h: newH };
    });

    zoomRef.current = newZoom;
    setZoomLevel(newZoom);
  }, [dimensions]);

  // Attach wheel listener with passive:false
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    container.addEventListener('wheel', handleWheel, { passive: false });
    return () => container.removeEventListener('wheel', handleWheel);
  }, [handleWheel]);

  // --- Pan handlers (mouse drag) ---
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    // Only pan on left-click on empty canvas (not on a node)
    if (e.button !== 0) return;
    const target = e.target as Element;
    if (target.closest('[data-graph-node]')) return;

    isPanningRef.current = true;
    panStartRef.current = { x: e.clientX, y: e.clientY };
    viewBoxStartRef.current = { x: viewBox.x, y: viewBox.y };
    e.preventDefault();
  }, [viewBox.x, viewBox.y]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isPanningRef.current || !containerRef.current) return;

    const rect = containerRef.current.getBoundingClientRect();
    // Convert pixel delta to graph-space delta
    const dx = (e.clientX - panStartRef.current.x) / rect.width * viewBox.w;
    const dy = (e.clientY - panStartRef.current.y) / rect.height * viewBox.h;

    setViewBox((prev) => ({
      ...prev,
      x: viewBoxStartRef.current.x - dx,
      y: viewBoxStartRef.current.y - dy,
    }));
  }, [viewBox.w, viewBox.h]);

  const handleMouseUp = useCallback(() => {
    isPanningRef.current = false;
  }, []);

  // --- Zoom controls ---
  const zoomIn = useCallback(() => {
    const newZoom = Math.min(MAX_ZOOM, zoomRef.current * 1.3);
    setViewBox((prev) => {
      const cx = prev.x + prev.w / 2;
      const cy = prev.y + prev.h / 2;
      const newW = dimensions.width / newZoom;
      const newH = dimensions.height / newZoom;
      return { x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH };
    });
    zoomRef.current = newZoom;
    setZoomLevel(newZoom);
  }, [dimensions]);

  const zoomOut = useCallback(() => {
    const newZoom = Math.max(MIN_ZOOM, zoomRef.current / 1.3);
    setViewBox((prev) => {
      const cx = prev.x + prev.w / 2;
      const cy = prev.y + prev.h / 2;
      const newW = dimensions.width / newZoom;
      const newH = dimensions.height / newZoom;
      return { x: cx - newW / 2, y: cy - newH / 2, w: newW, h: newH };
    });
    zoomRef.current = newZoom;
    setZoomLevel(newZoom);
  }, [dimensions]);

  const resetView = useCallback(() => {
    setViewBox({ x: 0, y: 0, w: dimensions.width, h: dimensions.height });
    zoomRef.current = 1;
    setZoomLevel(1);
  }, [dimensions]);

  const getNodePosition = useCallback((id: string) => {
    return nodes.find((n) => n.id === id);
  }, [nodes]);

  const getCurvedPath = useCallback((edge: ForceEdge) => {
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
  }, [getNodePosition]);

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

  const isEdgeHighlighted = (edge: ForceEdge, activeNodeId: string | null) => {
    if (!activeNodeId) return false;

    const sourceId = typeof edge.source === 'object' ? edge.source.id : edge.source;
    const targetId = typeof edge.target === 'object' ? edge.target.id : edge.target;

    return sourceId === activeNodeId || targetId === activeNodeId;
  };

  // Convert graph-space coords to screen-space for tooltip positioning
  const graphToScreen = useCallback((gx: number, gy: number) => {
    const container = containerRef.current;
    if (!container) return { x: gx, y: gy };
    const rect = container.getBoundingClientRect();
    const sx = ((gx - viewBox.x) / viewBox.w) * rect.width;
    const sy = ((gy - viewBox.y) / viewBox.h) * rect.height;
    return { x: sx, y: sy };
  }, [viewBox]);

  const { width, height } = dimensions;

  return (
    <div className="bg-surface-1 rounded-lg h-full flex flex-col">
      <div className="p-4 flex items-center justify-between border-b border-border">
        <h2 className="font-semibold text-foreground">Network Topology</h2>
      </div>

      <div
        ref={containerRef}
        className="flex-1 relative overflow-hidden"
        style={{ cursor: isPanningRef.current ? 'grabbing' : 'grab' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      >
        <svg
          ref={svgRef}
          viewBox={`${viewBox.x} ${viewBox.y} ${viewBox.w} ${viewBox.h}`}
          preserveAspectRatio="xMidYMid meet"
          className="absolute inset-0 w-full h-full"
          style={{ background: 'transparent' }}
        >
          <defs>
            <clipPath id="graph-clip">
              <rect x="-10000" y="-10000" width="20000" height="20000" />
            </clipPath>
            <pattern
              id="grid"
              width="40"
              height="40"
              patternUnits="userSpaceOnUse"
            >
              <path
                d="M 40 0 L 0 0 0 40"
                fill="none"
                style={{ stroke: 'var(--border)' }}
                strokeWidth="0.5"
                opacity="0.5"
              />
            </pattern>
            <filter id="glow-critical" x="-50%" y="-50%" width="200%" height="200%">
              <feGaussianBlur stdDeviation="8" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          <rect x={viewBox.x} y={viewBox.y} width={viewBox.w} height={viewBox.h} fill="url(#grid)" />

          <g clipPath="url(#graph-clip)">
            {edges.map((edge, i) => {
              const activeNodeId = hoveredNode || selectedNode;
              const isHighlighted = isEdgeHighlighted(edge, activeNodeId);
              const hasAnyHover = hoveredNode !== null || selectedNode !== null;

              return (
                <motion.path
                  key={i}
                  d={getCurvedPath(edge)}
                  stroke={isHighlighted ? 'var(--accent)' : 'var(--border-light)'}
                  strokeWidth={isHighlighted ? '2.5' : '1.5'}
                  fill="none"
                  opacity={hasAnyHover ? (isHighlighted ? 1 : 0.2) : 0.6}
                  animate={{
                    stroke: isHighlighted ? 'var(--accent)' : '#2D3748',
                    strokeWidth: isHighlighted ? 2.5 : 1.5,
                    opacity: hasAnyHover ? (isHighlighted ? 1 : 0.2) : 0.6,
                  }}
                  transition={{ duration: 0.2 }}
                  style={{ pointerEvents: 'none' }}
                />
              );
            })}

            {nodes.map((node) => {
              if (node.x === undefined || node.y === undefined) return null;

              const isHovered = hoveredDeviceId === node.id || hoveredNode === node.id;
              const isSelected = selectedNode === node.id;
              const strokeW = (isHovered || isSelected ? 3 : 2) / Math.max(zoomLevel, 0.5);

              // Subnet nodes render as dashed rounded rectangles with a label
              if (node.deviceType === 'subnet') {
                const SUBNET_COLOR = '#6366F1';
                const subnetW = 90 / Math.max(zoomLevel, 0.5);
                const subnetH = 26 / Math.max(zoomLevel, 0.5);
                const rx = 5 / Math.max(zoomLevel, 0.5);
                const fontSize = 8.5 / Math.max(zoomLevel, 0.5);
                const dashLen = 4 / Math.max(zoomLevel, 0.5);
                const gapLen = 2.5 / Math.max(zoomLevel, 0.5);
                const label = node.hostname ?? node.ip;
                return (
                  <motion.g
                    key={node.id}
                    data-graph-node
                    animate={{ scale: isHovered || isSelected ? 1.06 : 1 }}
                    transition={{ duration: 0.2 }}
                    style={{ transformOrigin: `${node.x}px ${node.y}px` }}
                  >
                    <rect
                      x={node.x - subnetW / 2}
                      y={node.y - subnetH / 2}
                      width={subnetW}
                      height={subnetH}
                      rx={rx}
                      fill="var(--surface-2)"
                      stroke={isHovered || isSelected ? '#818CF8' : SUBNET_COLOR}
                      strokeWidth={strokeW}
                      strokeDasharray={`${dashLen} ${gapLen}`}
                      style={{ cursor: 'pointer' }}
                      onMouseEnter={() => handleNodeHover(node.id)}
                      onMouseLeave={() => handleNodeHover(null)}
                      onClick={() => handleNodeClick(node.id)}
                      data-graph-node
                    />
                    <text
                      x={node.x}
                      y={node.y}
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fill={SUBNET_COLOR}
                      fontSize={fontSize}
                      fontFamily="monospace"
                      fontWeight="600"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}
                    >
                      {label}
                    </text>
                  </motion.g>
                );
              }

              const isCritical = !pendingColors && node.severity === 'critical';
              const nodeColor = pendingColors ? PENDING_NODE_COLOR : (SEVERITY_COLORS[node.severity] ?? PENDING_NODE_COLOR);
              const DeviceIcon = getDeviceIcon(node.deviceType);
              // Scale node radius inversely with zoom so nodes stay visually consistent
              const nodeRadius = 16 / Math.max(zoomLevel, 0.5);
              const iconSize = 16 / Math.max(zoomLevel, 0.5);

              return (
                <g key={node.id} data-graph-node>
                  {isCritical && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r={24 / Math.max(zoomLevel, 0.5)}
                      fill={nodeColor}
                      opacity="0.15"
                      filter="url(#glow-critical)"
                    />
                  )}
                  <motion.circle
                    cx={node.x}
                    cy={node.y}
                    r={nodeRadius}
                    stroke={nodeColor}
                    strokeWidth={strokeW}
                    animate={{
                      scale: isHovered || isSelected ? 1.15 : 1,
                    }}
                    transition={{ duration: 0.2 }}
                    style={{
                      fill: 'var(--surface-2)',
                      transformOrigin: `${node.x}px ${node.y}px`,
                      cursor: 'pointer',
                    }}
                    onMouseEnter={() => handleNodeHover(node.id)}
                    onMouseLeave={() => handleNodeHover(null)}
                    onClick={() => handleNodeClick(node.id)}
                    data-graph-node
                  />
                  <g transform={`translate(${node.x - iconSize / 2}, ${node.y - iconSize / 2})`}>
                    <DeviceIcon
                      size={iconSize}
                      color={nodeColor}
                      style={{ pointerEvents: 'none' }}
                    />
                  </g>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Zoom controls */}
        <div className="absolute bottom-3 right-3 flex flex-col gap-1 z-20">
          <button
            onClick={zoomIn}
            className="w-7 h-7 bg-surface-2/90 hover:bg-surface-3 rounded flex items-center justify-center text-foreground text-sm transition-colors border border-border"
            title="Zoom in"
          >
            +
          </button>
          <button
            onClick={resetView}
            className="w-7 h-7 bg-surface-2/90 hover:bg-surface-3 rounded flex items-center justify-center text-muted text-[10px] font-mono transition-colors border border-border"
            title="Reset view"
          >
            {Math.round(zoomLevel * 100)}%
          </button>
          <button
            onClick={zoomOut}
            className="w-7 h-7 bg-surface-2/90 hover:bg-surface-3 rounded flex items-center justify-center text-foreground text-sm transition-colors border border-border"
            title="Zoom out"
          >
            −
          </button>
        </div>

        {/* Tooltip */}
        {(hoveredNode || selectedNode) && (() => {
          const activeNode = nodes.find(n => n.id === (hoveredNode || selectedNode));
          if (!activeNode || activeNode.x === undefined || activeNode.y === undefined) return null;

          const screen = graphToScreen(activeNode.x, activeNode.y);
          const tooltipWidth = 220;
          const tooltipHeight = 220;
          const offset = 30;

          const containerEl = containerRef.current;
          const cw = containerEl?.clientWidth ?? width;
          const ch = containerEl?.clientHeight ?? height;

          let left = screen.x + offset;
          let top = screen.y - 20;

          if (left + tooltipWidth > cw - 10) {
            left = screen.x - tooltipWidth - offset;
          }
          if (top + tooltipHeight > ch - 10) {
            top = ch - tooltipHeight - 10;
          }
          if (top < 10) {
            top = 10;
          }

          return (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.9 }}
              transition={{ duration: 0.15 }}
              className="absolute bg-surface-2 rounded-lg p-3 shadow-xl border border-border pointer-events-none z-10"
              style={{
                left: `${left}px`,
                top: `${top}px`,
                maxWidth: `${tooltipWidth}px`,
              }}
            >
              {activeNode.deviceType === 'subnet' ? (
                <div className="flex flex-col gap-1.5 min-w-[150px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-muted-foreground font-medium">Type</span>
                    <span className="text-xs text-foreground" style={{ color: '#6366F1' }}>Network Subnet</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-muted-foreground font-medium">Subnet</span>
                    <span className="text-sm text-foreground font-mono">{activeNode.hostname ?? activeNode.ip}</span>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col gap-1.5 min-w-[150px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-muted-foreground font-medium">IP Address</span>
                    <span className="text-sm text-foreground font-mono">{activeNode.ip}</span>
                  </div>
                  {activeNode.hostname && (
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs text-muted-foreground font-medium">Hostname</span>
                      <span className="text-sm text-foreground font-mono">{activeNode.hostname}</span>
                    </div>
                  )}
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-muted-foreground font-medium">Device Type</span>
                    <span className="text-xs text-foreground capitalize">{activeNode.deviceType ?? 'unknown'}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-xs text-muted-foreground font-medium">Severity</span>
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
                    <div className="mt-1 pt-1.5 border-t border-border">
                      <p className="text-xs text-muted-foreground">{activeNode.description}</p>
                    </div>
                  )}
                </div>
              )}
            </motion.div>
          );
        })()}
      </div>

      <div className="p-4 border-t border-border">
        <div className="flex items-center justify-between">
          <span className="text-xs text-muted">
            {simulationActive ? 'Calculating layout…' : `${nodes.length} nodes · ${edges.length} connections`}
          </span>
          <span className="text-xs text-muted">
            {topology.networkName ?? 'Network Topology'}
          </span>
        </div>
      </div>
    </div>
  );
}
