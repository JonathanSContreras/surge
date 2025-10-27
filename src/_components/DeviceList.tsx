'use client';

import { Search, Shield, AlertTriangle, AlertCircle } from "lucide-react";
import { motion } from "motion/react";
import { useState } from "react";

interface Device {
  ip: string;
  hostname: string;
  status: "online" | "offline";
  vulnerabilityScore: number;
  severity: "low" | "medium" | "high";
}

const mockDevices: Device[] = [
  { ip: "192.168.1.1", hostname: "gateway", status: "online", vulnerabilityScore: 2.3, severity: "low" },
  { ip: "192.168.1.50", hostname: "web-server", status: "online", vulnerabilityScore: 8.9, severity: "high" },
  { ip: "192.168.1.51", hostname: "db-server", status: "online", vulnerabilityScore: 5.4, severity: "medium" },
  { ip: "192.168.1.100", hostname: "workstation-1", status: "online", vulnerabilityScore: 1.2, severity: "low" },
  { ip: "192.168.1.101", hostname: "workstation-2", status: "online", vulnerabilityScore: 7.8, severity: "high" },
  { ip: "192.168.1.102", hostname: "workstation-3", status: "online", vulnerabilityScore: 4.5, severity: "medium" },
  { ip: "192.168.1.10", hostname: "firewall", status: "online", vulnerabilityScore: 3.1, severity: "low" },
  { ip: "192.168.1.200", hostname: "nas-storage", status: "offline", vulnerabilityScore: 6.2, severity: "medium" },
];

export function DeviceList() {
  const [searchQuery, setSearchQuery] = useState("");

  const filteredDevices = mockDevices.filter(
    (device) =>
      device.ip.includes(searchQuery) ||
      device.hostname.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "low": return <Shield className="w-4 h-4 text-[#00E676]" />;
      case "medium": return <AlertTriangle className="w-4 h-4 text-[#FFB300]" />;
      case "high": return <AlertCircle className="w-4 h-4 text-[#FF1744]" />;
      default: return <Shield className="w-4 h-4 text-[#00E676]" />;
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low": return "#00E676";
      case "medium": return "#FFB300";
      case "high": return "#FF1744";
      default: return "#00E676";
    }
  };

  return (
    <div className="h-full flex flex-col bg-gradient-to-br from-white/5 to-white/[0.02] backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-white/10">
        <h3 className="text-white mb-3 uppercase tracking-wide">Network Devices</h3>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#B0B0B0]" />
          <input
            placeholder="Search by IP or hostname..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-10 bg-white/5 border-white/10 text-white placeholder:text-[#B0B0B0] focus:border-[#00E676]/50 focus:ring-[#00E676]/20"
          />
        </div>
      </div>

      {/* Device List */}
      <div className="flex-1">
        <div className="p-2">
          {filteredDevices.map((device, idx) => (
            <motion.div
              key={device.ip}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: idx * 0.05 }}
              className="group p-4 mb-2 rounded-lg bg-white/[0.02] hover:bg-white/5 border border-transparent hover:border-white/10 cursor-pointer transition-all duration-300"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{
                      background: `${getSeverityColor(device.severity)}20`,
                      boxShadow: `0 0 10px ${getSeverityColor(device.severity)}20`,
                    }}
                  >
                    {getSeverityIcon(device.severity)}
                  </div>
                  <div>
                    <p className="text-white text-sm">{device.hostname}</p>
                    <p className="text-[#B0B0B0] text-xs">{device.ip}</p>
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <div
                    className={`w-2 h-2 rounded-full ${
                      device.status === "online" ? "bg-[#00E676]" : "bg-[#B0B0B0]"
                    }`}
                  />
                  <span
                    className={`text-xs ${
                      device.status === "online" ? "text-[#00E676]" : "text-[#B0B0B0]"
                    }`}
                  >
                    {device.status}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-xs text-[#B0B0B0]">Vulnerability Score</span>
                <div className="flex items-center gap-2">
                  <div className="w-24 h-1.5 bg-white/10 rounded-full overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(device.vulnerabilityScore / 10) * 100}%` }}
                      transition={{ delay: idx * 0.05 + 0.2, duration: 0.5 }}
                      className="h-full rounded-full"
                      style={{ background: getSeverityColor(device.severity) }}
                    />
                  </div>
                  <span
                    className="text-xs w-8 text-right"
                    style={{ color: getSeverityColor(device.severity) }}
                  >
                    {device.vulnerabilityScore}
                  </span>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
