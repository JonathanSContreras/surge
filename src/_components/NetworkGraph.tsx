'use client';
import { useEffect, useRef, useState } from "react";
import { motion } from "motion/react";

interface Node {
  id: string;
  x: number;
  y: number;
  severity: "low" | "medium" | "high";
  ip: string;
  hostname: string;
  vulnerabilities: number;
}

interface Edge {
  source: string;
  target: string;
}

const mockNodes: Node[] = [
  { id: "1", x: 250, y: 200, severity: "low", ip: "192.168.1.1", hostname: "gateway", vulnerabilities: 2 },
  { id: "2", x: 400, y: 150, severity: "high", ip: "192.168.1.50", hostname: "web-server", vulnerabilities: 12 },
  { id: "3", x: 400, y: 250, severity: "medium", ip: "192.168.1.51", hostname: "db-server", vulnerabilities: 5 },
  { id: "4", x: 550, y: 100, severity: "low", ip: "192.168.1.100", hostname: "workstation-1", vulnerabilities: 1 },
  { id: "5", x: 550, y: 200, severity: "high", ip: "192.168.1.101", hostname: "workstation-2", vulnerabilities: 8 },
  { id: "6", x: 550, y: 300, severity: "medium", ip: "192.168.1.102", hostname: "workstation-3", vulnerabilities: 4 },
  { id: "7", x: 250, y: 300, severity: "low", ip: "192.168.1.10", hostname: "firewall", vulnerabilities: 3 },
];

const mockEdges: Edge[] = [
  { source: "1", target: "2" },
  { source: "1", target: "3" },
  { source: "1", target: "7" },
  { source: "2", target: "4" },
  { source: "2", target: "5" },
  { source: "3", target: "6" },
];

export function NetworkGraph({ liveMode }: { liveMode: boolean }) {
  const [hoveredNode, setHoveredNode] = useState<Node | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const canvasRef = useRef<HTMLDivElement>(null);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low": return "#00E676";
      case "medium": return "#FFB300";
      case "high": return "#FF1744";
      default: return "#00E676";
    }
  };

  return (
    <div className="relative w-full h-full bg-gradient-to-br from-[#0F1117] to-[#1a1d2e] rounded-xl border border-white/10 overflow-hidden">
      {/* Grid background */}
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage: `
            linear-gradient(rgba(0, 230, 118, 0.1) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 230, 118, 0.1) 1px, transparent 1px)
          `,
          backgroundSize: "50px 50px"
        }}
      />

      {/* Live mode indicator */}
      {liveMode && (
        <div className="absolute top-4 right-4 z-20 flex items-center gap-2 px-3 py-2 rounded-lg bg-[#00E676]/10 border border-[#00E676]/30 backdrop-blur-sm">
          <div className="w-2 h-2 rounded-full bg-[#00E676] animate-pulse shadow-lg shadow-[#00E676]/50" />
          <span className="text-xs text-[#00E676] uppercase tracking-wide">Live Mode</span>
        </div>
      )}

      <div ref={canvasRef} className="relative w-full h-full p-8">
        {/* Edges */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          {mockEdges.map((edge, idx) => {
            const sourceNode = mockNodes.find((n) => n.id === edge.source);
            const targetNode = mockNodes.find((n) => n.id === edge.target);
            if (!sourceNode || !targetNode) return null;

            return (
              <motion.line
                key={idx}
                x1={sourceNode.x}
                y1={sourceNode.y}
                x2={targetNode.x}
                y2={targetNode.y}
                stroke="rgba(0, 230, 118, 0.2)"
                strokeWidth="2"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 1, delay: idx * 0.1 }}
              />
            );
          })}
        </svg>

        {/* Nodes */}
        {mockNodes.map((node, idx) => (
          <motion.div
            key={node.id}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: idx * 0.1, type: "spring" }}
            className="absolute cursor-pointer"
            style={{
              left: node.x,
              top: node.y,
              transform: "translate(-50%, -50%)",
            }}
            onMouseEnter={(e) => {
              setHoveredNode(node);
              const rect = canvasRef.current?.getBoundingClientRect();
              if (rect) {
                setTooltipPos({
                  x: e.clientX - rect.left,
                  y: e.clientY - rect.top,
                });
              }
            }}
            onMouseLeave={() => setHoveredNode(null)}
          >
            <div className="relative">
              {/* Glow effect */}
              <div
                className="absolute inset-0 rounded-full blur-xl animate-pulse"
                style={{
                  background: getSeverityColor(node.severity),
                  opacity: 0.3,
                }}
              />
              
              {/* Node circle */}
              <div
                className="relative w-12 h-12 rounded-full border-2 flex items-center justify-center backdrop-blur-sm"
                style={{
                  borderColor: getSeverityColor(node.severity),
                  background: `radial-gradient(circle, ${getSeverityColor(node.severity)}40, ${getSeverityColor(node.severity)}10)`,
                  boxShadow: `0 0 20px ${getSeverityColor(node.severity)}60`,
                }}
              >
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ background: getSeverityColor(node.severity) }}
                />
              </div>
            </div>
          </motion.div>
        ))}

        {/* Tooltip */}
        {hoveredNode && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="absolute z-30 p-4 rounded-lg bg-[#1a1d2e]/95 border border-white/20 backdrop-blur-xl shadow-2xl pointer-events-none"
            style={{
              left: tooltipPos.x + 20,
              top: tooltipPos.y - 20,
            }}
          >
            <p className="text-white mb-1">{hoveredNode.hostname}</p>
            <p className="text-[#B0B0B0] text-sm mb-2">{hoveredNode.ip}</p>
            <div className="flex items-center gap-2">
              <div
                className="w-2 h-2 rounded-full"
                style={{ background: getSeverityColor(hoveredNode.severity) }}
              />
              <span className="text-xs text-[#B0B0B0]">
                {hoveredNode.vulnerabilities} vulnerabilities
              </span>
            </div>
          </motion.div>
        )}
      </div>
    </div>
  );
}
