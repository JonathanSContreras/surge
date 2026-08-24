'use client';

import { useState, useEffect } from 'react';
import { SEVERITY_COLORS, Severity } from './types/network-topology';
import { getDevices, DeviceRecord, RawTopologyHost } from '@/lib/api';

const statusColors = {
  online: 'bg-[#00E676]/10 text-[#00E676]',
  offline: 'bg-[#6B7280]/10 text-muted',
  scanning: 'bg-[#FFB300]/10 text-[#FFB300]',
};

// Minimal shape needed to render a device row (DB record or live topology host)
interface DisplayDevice {
  key: string;
  ip: string;
  hostname: string | null;
  cvss: number;
  severity: Severity;
  status: 'online' | 'offline' | 'scanning';
}

function fromRecord(d: DeviceRecord): DisplayDevice {
  return {
    key: String(d.id),
    ip: d.ip,
    hostname: d.hostname,
    cvss: d.cvss_score,
    severity: (d.severity ?? 'low') as Severity,
    status: d.status,
  };
}

function fromLiveHost(h: RawTopologyHost): DisplayDevice {
  return {
    key: h.ip,
    ip: h.ip,
    hostname: h.hostname === 'idk' ? null : h.hostname,
    cvss: h.cvss,
    severity: (['low', 'medium', 'high', 'critical'].includes(h.severity) ? h.severity : 'low') as Severity,
    status: h.status === 'up' ? 'online' : 'offline',
  };
}

export function DeviceList({
  onDeviceHover,
  scanId,
  isLiveMode,
  liveHosts,
}: {
  onDeviceHover: (id: string | null) => void;
  scanId?: string;
  isLiveMode?: boolean;
  liveHosts?: RawTopologyHost[];
}) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [devices, setDevices] = useState<DisplayDevice[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Live mode: use topology hosts if available, else show empty
    if (isLiveMode) {
      setDevices(liveHosts && liveHosts.length > 0 ? liveHosts.map(fromLiveHost) : []);
      setLoading(false);
      return;
    }
    setLoading(true);
    getDevices(scanId)
      .then((records) => setDevices(records.map(fromRecord)))
      .catch(() => setDevices([]))
      .finally(() => setLoading(false));
  }, [scanId, isLiveMode, liveHosts]);

  const handleMouseEnter = (id: string) => {
    setHoveredId(id);
    onDeviceHover(id);
  };

  const handleMouseLeave = () => {
    setHoveredId(null);
    onDeviceHover(null);
  };

  return (
    <div className="bg-surface-1 rounded-lg h-full overflow-hidden flex flex-col">
      <div className="p-4 border-b border-border">
        <h2 className="font-semibold text-foreground">Device Inventory</h2>
        <p className="text-sm text-muted mt-0.5">
          {loading ? 'Loading…' : `${devices.length} devices detected`}
        </p>
      </div>
      <div className="overflow-y-auto flex-1">
        {!loading && devices.length === 0 && (
          <p className="p-4 text-sm text-muted">
            {isLiveMode ? 'Waiting for scan data…' : 'No devices found. Run a scan to populate.'}
          </p>
        )}
        {devices.map((device, index) => (
          <div key={device.key}>
            <div
              className={`p-4 border-l-2 cursor-pointer transition-all ${
                hoveredId === device.key ? 'bg-surface-2' : 'hover:bg-surface-2/50'
              }`}
              style={{ borderLeftColor: SEVERITY_COLORS[device.severity] }}
              onMouseEnter={() => handleMouseEnter(device.key)}
              onMouseLeave={handleMouseLeave}
            >
              <div className="flex items-start justify-between mb-2">
                <code className="text-foreground font-mono text-sm">{device.ip}</code>
                <span className="font-semibold text-foreground text-sm">
                  {device.cvss > 0 ? device.cvss.toFixed(1) : '—'}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted text-xs">{device.hostname ?? 'Unknown'}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${statusColors[device.status] ?? statusColors.online}`}>
                  {device.status}
                </span>
              </div>
            </div>
            {index < devices.length - 1 && <div className="h-px bg-border mx-4" />}
          </div>
        ))}
      </div>
    </div>
  );
}
