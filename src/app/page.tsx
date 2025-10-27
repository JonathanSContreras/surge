'use client';

import { useState } from "react";
import { SummaryCard } from "../_components/SummaryCard";
import { NetworkGraph } from "../_components/NetworkGraph";
import { DeviceList } from "../_components/DeviceList";
import { AgentFeedback } from "../_components/AgentFeedback";
import { Server, Shield, Activity, Target, ToggleRight, ToggleLeft } from "lucide-react";

export default function Dashboard() {
  const [liveMode, setLiveMode] = useState(true);

  return (
    <div className="p-6 space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <SummaryCard
          title="Total Devices"
          value={8}
          icon={Server}
          accentColor="#00E676"
          subtitle="Active network nodes"
        />
        <SummaryCard
          title="Vulnerabilities"
          value={37}
          icon={Shield}
          accentColor="#FF1744"
          subtitle="Critical: 12, High: 15"
        />
        <SummaryCard
          title="Avg CVSS Score"
          value="6.8"
          icon={Activity}
          accentColor="#FFB300"
          subtitle="Medium severity"
        />
        <SummaryCard
          title="Exploit Success"
          value="73%"
          icon={Target}
          accentColor="#00E676"
          subtitle="27 of 37 exploited"
        />
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 h-[calc(100vh-280px)]">
        {/* Left: Device List */}
        <div className="lg:col-span-3 h-full">
          <DeviceList />
        </div>

        {/* Center: Network Graph */}
        <div className="lg:col-span-6 h-full flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-white uppercase tracking-wide">Network Topology</h2>
              <p className="text-sm text-[#B0B0B0]">GNN-based visualization</p>
            </div>
            <div className="flex items-center gap-3 px-4 py-2 rounded-lg bg-white/5 border border-white/10">
                {/* <Label htmlFor="live-mode" className="text-sm text-[#B0B0B0]">
                  {liveMode ? "Live Mode" : "Presentation Mode"}
                </Label>
                <Switch
                  id="live-mode"
                  checked={liveMode}
                  onCheckedChange={setLiveMode}
                />
                */}
              </div>
          </div>
          <div className="flex-1">
            <NetworkGraph liveMode={liveMode} />
          </div>
        </div>

        {/* Right: Agent Feedback */}
        <div className="lg:col-span-3 h-full">
          <AgentFeedback />
        </div>
      </div>
    </div>
  );
}
