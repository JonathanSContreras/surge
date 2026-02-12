'use client';

import { useState, useEffect } from 'react';
import { motion } from 'motion/react';

interface Node {
  id: string;
  x: number;
  y: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  label: string;
}

interface Edge {
  from: string;
  to: string;
}

const nodes: Node[] = [
  { id: '1', x: 300, y: 150, severity: 'critical', label: '192.168.1.10' },
  { id: '2', x: 450, y: 200, severity: 'high', label: '192.168.1.45' },
  { id: '3', x: 200, y: 250, severity: 'medium', label: '192.168.1.67' },
  { id: '4', x: 350, y: 300, severity: 'low', label: '192.168.1.88' },
  { id: '5', x: 500, y: 320, severity: 'medium', label: '192.168.1.102' },
  { id: '6', x: 150, y: 380, severity: 'high', label: '192.168.1.124' },
  { id: '7', x: 400, y: 420, severity: 'medium', label: '192.168.1.156' },
  { id: '8', x: 280, y: 480, severity: 'low', label: '192.168.1.178' },
];

const edges: Edge[] = [
  { from: '1', to: '2' },
  { from: '1', to: '3' },
  { from: '2', to: '4' },
  { from: '3', to: '4' },
  { from: '2', to: '5' },
  { from: '3', to: '6' },
  { from: '4', to: '7' },
  { from: '6', to: '8' },
  { from: '7', to: '8' },
];

const severityColors = {
  low: '#00E676',
  medium: '#FFB300',
  high: '#FF6F00',
  critical: '#FF1744',
};

export function NetworkGraph({ hoveredDeviceId }: { hoveredDeviceId: string | null }) {
  const [mode, setMode] = useState<'Live' | 'Demo'>('Live');
  const [progress, setProgress] = useState(67);
  const [elapsed, setElapsed] = useState(142);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => (prev >= 100 ? 0 : prev + 1));
      setElapsed((prev) => prev + 1);
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  const getNodePosition = (id: string) => {
    return nodes.find((n) => n.id === id);
  };

  const getCurvedPath = (from: string, to: string) => {
    const fromNode = getNodePosition(from);
    const toNode = getNodePosition(to);
    if (!fromNode || !toNode) return '';

    const dx = toNode.x - fromNode.x;
    const dy = toNode.y - fromNode.y;
    const dr = Math.sqrt(dx * dx + dy * dy) * 0.3;

    return `M ${fromNode.x} ${fromNode.y} Q ${fromNode.x + dx / 2 + dr / 2} ${
      fromNode.y + dy / 2 - dr / 2
    } ${toNode.x} ${toNode.y}`;
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
            {edges.map((edge, i) => (
              <path
                key={i}
                d={getCurvedPath(edge.from, edge.to)}
                stroke="#2D3748"
                strokeWidth="1.5"
                fill="none"
                opacity="0.6"
              />
            ))}
          </g>

          {/* Nodes */}
          <g>
            {nodes.map((node) => {
              const isHovered = hoveredDeviceId === node.id;
              const isCritical = node.severity === 'critical';
              return (
                <g key={node.id}>
                  {/* Outer glow for critical */}
                  {isCritical && (
                    <circle
                      cx={node.x}
                      cy={node.y}
                      r="24"
                      fill={severityColors[node.severity]}
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
                    stroke={severityColors[node.severity]}
                    strokeWidth={isHovered ? "3" : "2"}
                    animate={{
                      scale: isHovered ? 1.15 : 1,
                    }}
                    transition={{ duration: 0.2 }}
                    style={{
                      transformOrigin: `${node.x}px ${node.y}px`,
                    }}
                  />
                  {/* Inner dot */}
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="4"
                    fill={severityColors[node.severity]}
                  />
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* Progress bar */}
      <div className="p-4 border-t border-[#1F2937]">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#6B7280]">Active Scan Progress</span>
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
