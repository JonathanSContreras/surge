export type DeviceType = 'router' | 'switch' | 'firewall' | 'server' | 'workstation' | 'iot' | 'unknown';
export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface NetworkDevice {
  id: string;                    // Unique identifier
  ip: string;                    // IP address (primary display)
  severity: Severity;            // Risk severity level
  description?: string;          // Optional description text
  deviceType: DeviceType;        // Device category

  // Optional fields for future expansion
  hostname?: string;
  cvss?: number;
  status?: 'online' | 'offline' | 'scanning';
  metadata?: Record<string, unknown>;
}

export interface NetworkConnection {
  from: string;                  // Source device ID
  to: string;                    // Target device ID

  // Future expansion fields (designed but not used yet)
  connectionType?: string;
  bandwidth?: number;
  latency?: number;
  protocol?: string;
  strength?: number;
  metadata?: Record<string, unknown>;
}

export interface NetworkTopology {
  devices: NetworkDevice[];
  connections: NetworkConnection[];

  // Optional metadata
  scanDate?: string;
  networkName?: string;
  metadata?: Record<string, unknown>;
}

// Internal types for D3 force simulation
export interface ForceNode extends NetworkDevice {
  x?: number;
  y?: number;
  vx?: number;
  vy?: number;
  fx?: number | null;
  fy?: number | null;
}

export interface ForceEdge extends NetworkConnection {
  source: string | ForceNode;
  target: string | ForceNode;
}

// Shared severity colors (consolidate duplicates)
export const SEVERITY_COLORS: Record<Severity, string> = {
  low: '#00E676',
  medium: '#FFB300',
  high: '#FF6F00',
  critical: '#FF1744',
};
