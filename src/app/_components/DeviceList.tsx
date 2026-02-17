'use client';

import { useState } from 'react';
import { SEVERITY_COLORS, NetworkDevice } from './types/network-topology';
import { sampleTopology } from './data/sample-topology';

const statusColors = {
  online: 'bg-[#00E676]/10 text-[#00E676]',
  offline: 'bg-[#6B7280]/10 text-[#6B7280]',
  scanning: 'bg-[#FFB300]/10 text-[#FFB300]',
};

export function DeviceList({ onDeviceHover }: { onDeviceHover: (id: string | null) => void }) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const devices = sampleTopology.devices;

  const handleMouseEnter = (id: string) => {
    setHoveredId(id);
    onDeviceHover(id);
  };

  const handleMouseLeave = () => {
    setHoveredId(null);
    onDeviceHover(null);
  };

  const getStatusColor = (device: NetworkDevice) => {
    const status = device.status || 'online';
    return statusColors[status as keyof typeof statusColors] || statusColors.online;
  };

  return (
    <div className="bg-[#13151C] rounded-lg h-full overflow-hidden flex flex-col">
      <div className="p-4 border-b border-[#1F2937]">
        <h2 className="font-semibold text-white">Device Inventory</h2>
        <p className="text-sm text-[#6B7280] mt-0.5">{devices.length} devices detected</p>
      </div>
      <div className="overflow-y-auto flex-1">
        {devices.map((device, index) => (
          <div key={device.id}>
            <div
              className={`p-4 border-l-2 cursor-pointer transition-all ${
                hoveredId === device.id ? 'bg-[#16181F]' : 'hover:bg-[#16181F]/50'
              }`}
              style={{ borderLeftColor: SEVERITY_COLORS[device.severity] }}
              onMouseEnter={() => handleMouseEnter(device.id)}
              onMouseLeave={handleMouseLeave}
            >
              <div className="flex items-start justify-between mb-2">
                <code className="text-white font-mono text-sm">{device.ip}</code>
                <span className="font-semibold text-white text-sm">{device.cvss?.toFixed(1) ?? '—'}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#6B7280] text-xs">{device.hostname || 'Unknown'}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${getStatusColor(device)}`}>
                  {device.status || 'online'}
                </span>
              </div>
            </div>
            {index < devices.length - 1 && <div className="h-px bg-[#1F2937] mx-4" />}
          </div>
        ))}
      </div>
    </div>
  );
}
