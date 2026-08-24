import { NetworkTopology, DeviceType, Severity } from '../types/network-topology';

interface RawHost {
  id: string;
  ip: string;
  severity: string;
  description: string;
  deviceType: string;
  hostname: string;
  cvss: number;
  cve: string;
  vulnerability_description: string;
  status: string;
}

interface RawTopologyNode {
  id: string;
  ip: string | null;
  label: string;
  nodeType: string;
  deviceType: string | null;
  mac_vendor: string | null;
  os: string | null;
  status: string;
  isIntermediate: boolean;
  services: number;
}

interface RawTopologyLink {
  source: string;
  target: string;
  type: string;
}

interface RawScanData {
  hosts: RawHost[];
  topology: {
    nodes: RawTopologyNode[];
    links: RawTopologyLink[];
    metadata: Record<string, unknown>;
  };
}

const DEVICE_TYPE_MAP: Record<string, DeviceType> = {
  router: 'router',
  firewall: 'firewall',
  switch: 'switch',
  server: 'server',
  workstation: 'workstation',
  iot: 'iot',
  phone: 'workstation',
  specialized: 'iot',
  WAP: 'router',
  'general purpose': 'server',
  scanner: 'unknown',
  // Additional nmap osclass type strings:
  'broadband router': 'router',
  'print server': 'server',
  'storage-misc': 'server',
  'load balancer': 'server',
  webcam: 'iot',
  printer: 'iot',
  'media device': 'iot',
  'game console': 'iot',
  hub: 'switch',
  idk: 'unknown',
  subnet: 'subnet',
};

function mapDeviceType(raw: string | null): DeviceType {
  if (!raw) return 'unknown';
  return DEVICE_TYPE_MAP[raw] ?? 'unknown';
}

function mapSeverity(raw: string): Severity {
  if (['critical', 'high', 'medium', 'low'].includes(raw)) return raw as Severity;
  return 'low';
}

export function fromRawScan(rawData: RawScanData, networkName = 'Imported Network Scan'): NetworkTopology {
  // Build a lookup map from ip → host details
  const hostByIp = new Map<string, RawHost>();
  for (const host of rawData.hosts) {
    hostByIp.set(host.ip, host);
  }

  // Convert topology nodes to NetworkDevice entries
  const devices = rawData.topology.nodes.map((node) => {
    const host = node.ip ? hostByIp.get(node.ip) : undefined;

    const severity = host ? mapSeverity(host.severity) : 'low';
    const deviceType = mapDeviceType(host?.deviceType ?? node.deviceType ?? node.nodeType);
    const hostname = host?.hostname && host.hostname !== 'idk' ? host.hostname : node.label;
    const description = host?.description ?? node.os ?? undefined;

    return {
      id: node.id,
      ip: node.ip ?? node.id,
      severity,
      description,
      deviceType,
      hostname,
      cvss: host?.cvss ?? 0,
      status: node.status === 'up' ? ('online' as const) : ('offline' as const),
      metadata: {
        mac_vendor: node.mac_vendor,
        os: node.os,
        services: node.services,
        cve: host?.cve,
        vulnerability_description: host?.vulnerability_description,
        nodeType: node.nodeType,
      },
    };
  });

  // Convert topology links to NetworkConnection entries
  const connections = rawData.topology.links.map((link) => ({
    from: link.source,
    to: link.target,
    connectionType: link.type,
  }));

  return {
    networkName,
    scanDate: new Date().toISOString(),
    devices,
    connections,
  };
}
