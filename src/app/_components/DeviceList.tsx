'use client';

import { useState } from 'react';
import { SEVERITY_COLORS } from './types/network-topology';

interface Device {
  id: string;
  ip: string;
  hostname: string;
  status: 'Online' | 'Offline' | 'Scanning';
  cvss: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

const devices: Device[] = [
  { id: '1', ip: '192.168.1.10', hostname: 'gateway-primary', status: 'Online', cvss: 9.8, severity: 'critical' },
  { id: '2', ip: '192.168.1.45', hostname: 'db-server-01', status: 'Scanning', cvss: 7.5, severity: 'high' },
  { id: '3', ip: '192.168.1.67', hostname: 'web-frontend', status: 'Online', cvss: 5.2, severity: 'medium' },
  { id: '4', ip: '192.168.1.88', hostname: 'api-service', status: 'Online', cvss: 3.1, severity: 'low' },
  { id: '5', ip: '192.168.1.102', hostname: 'backup-storage', status: 'Offline', cvss: 6.8, severity: 'medium' },
  { id: '6', ip: '192.168.1.124', hostname: 'mail-server', status: 'Online', cvss: 8.3, severity: 'high' },
  { id: '7', ip: '192.168.1.156', hostname: 'dev-workstation', status: 'Online', cvss: 4.6, severity: 'medium' },
  { id: '8', ip: '192.168.1.178', hostname: 'analytics-node', status: 'Scanning', cvss: 2.4, severity: 'low' },
];

const statusColors = {
  Online: 'bg-[#00E676]/10 text-[#00E676]',
  Offline: 'bg-[#6B7280]/10 text-[#6B7280]',
  Scanning: 'bg-[#FFB300]/10 text-[#FFB300]',
};

export function DeviceList({ onDeviceHover }: { onDeviceHover: (id: string | null) => void }) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);

  const handleMouseEnter = (id: string) => {
    setHoveredId(id);
    onDeviceHover(id);
  };

  const handleMouseLeave = () => {
    setHoveredId(null);
    onDeviceHover(null);
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
                <span className="font-semibold text-white text-sm">{device.cvss}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[#6B7280] text-xs">{device.hostname}</span>
                <span
                  className={`text-xs px-2 py-0.5 rounded ${statusColors[device.status]}`}
                >
                  {device.status}
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
