'use client';

import { useState } from 'react';
import { DeviceList } from '../_components/DeviceList';
import { NetworkGraph } from '../_components/NetworkGraph';
import { ActivityFeed } from '../_components/ActivityFeed';
import { StatCards } from '../_components/StatCards';
import { VulnerabilityChart } from '../_components/VulnerabilityChart';
import { ExploitQueue } from '../_components/ExploitQueue';

export function Dashboard() {
  const [hoveredDeviceId, setHoveredDeviceId] = useState<string | null>(null);

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      {/* Three-column main grid */}
      <div className="grid grid-cols-12 gap-6 mb-6" style={{ height: '640px' }}>
        {/* Left: Device List */}
        <div className="col-span-3">
          <DeviceList onDeviceHover={setHoveredDeviceId} />
        </div>

        {/* Center: Network Graph */}
        <div className="col-span-6">
          <NetworkGraph hoveredDeviceId={hoveredDeviceId} />
        </div>

        {/* Right: Activity Feed */}
        <div className="col-span-3">
          <ActivityFeed />
        </div>
      </div>

      {/* Stat Cards */}
      <div className="mb-6">
        <StatCards />
      </div>

      {/* Bottom row: Chart and Queue */}
      <div className="grid grid-cols-2 gap-6">
        <VulnerabilityChart />
        <ExploitQueue />
      </div>
    </div>
  );
}
