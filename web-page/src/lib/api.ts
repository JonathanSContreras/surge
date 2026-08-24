/**
 * Surge API client — all fetch calls go through here.
 * Import individual functions rather than the base URL throughout the app.
 */

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';
const WS  = process.env.NEXT_PUBLIC_WS_URL  ?? 'ws://localhost:8000';

// ---------------------------------------------------------------------------
// Shared types (mirrors api/models.py)
// ---------------------------------------------------------------------------

export type ScanType   = 'quick' | 'normal' | 'deep' | 'stealth';
export type ScanStatus = 'running' | 'completed' | 'failed';
export type Severity   = 'low' | 'medium' | 'high' | 'critical';

export interface ScanRecord {
  scan_id:       string;
  name:          string | null;
  target_range:  string;
  scan_type:     ScanType;
  status:        ScanStatus;
  devices_count: number;
  vulns_count:   number;
  avg_cvss:      number | null;
  created_at:    string;
  completed_at:  string | null;
  duration_s:    number | null;
}

export interface ScanCreatedResponse {
  scan_id: string;
  status:  ScanStatus;
}

export interface ScanProgressEvent {
  scan_id:         string;
  status:          ScanStatus;
  progress:        number;
  elapsed_seconds: number;
  events:          { node: string; message: string; timestamp: string }[];
}

export interface DeviceRecord {
  id:          number;
  scan_id:     string;
  ip:          string;
  hostname:    string | null;
  device_type: string | null;
  os_name:     string | null;
  description: string | null;
  status:      'online' | 'offline' | 'scanning';
  severity:    Severity;
  cvss_score:  number;
  subnet:      string | null;
}

export interface VulnRecord {
  id:                       number;
  scan_id:                  string;
  cve_id:                   string;
  affected_device_ip:       string;
  affected_device_hostname: string | null;
  product:                  string | null;
  version:                  string | null;
  cvss_score_raw:           number | null;
  cvss_score_predicted:     number | null;
  severity:                 string | null;
  summary:                  string | null;
  exploitable:              boolean | null;
  remediation:              string | null;
  exploit_availability:     'public' | 'private' | 'none';
  status:                   'queued' | 'in_progress' | 'exploited' | 'patched';
}

export interface DashboardStats {
  devices_scanned:       number;
  vulnerabilities_found: number;
  avg_cvss:              number | null;
  active_scans:          number;
}

export interface ActivityEventRecord {
  id:         number;
  scan_id:    string | null;
  event_type: 'info' | 'warning' | 'critical' | 'patch' | 'exploit';
  message:    string;
  detail:     string | null;
  ip:         string | null;
  agent_node: string | null;
  created_at: string;
}

export interface ReportTemplate {
  id:          string;
  name:        string;
  description: string;
}

export interface RiskMatrix {
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

export interface ReportRecord {
  id:                string;
  scan_id:           string;
  template_id:       string;
  created_at:        string;
  raw_markdown:      string | null;
  executive_summary: string | null;
  scope:             string | null;
  methodology:       string | null;
  key_findings:      string | null;
  recommendations:   string | null;
  risk_matrix:       RiskMatrix;
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) throw new Error(`GET ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function patch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`PATCH ${path} → ${res.status}`);
  return res.json() as Promise<T>;
}

async function del(path: string): Promise<void> {
  const res = await fetch(`${API}${path}`, { method: 'DELETE' });
  if (!res.ok) throw new Error(`DELETE ${path} → ${res.status}`);
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const getScans = (): Promise<ScanRecord[]> =>
  get<ScanRecord[]>('/scans');

export const stopScan = (scanId: string): Promise<{ scan_id: string; status: string }> =>
  post<{ scan_id: string; status: string }>(`/scans/${scanId}/stop`, {});

export const renameScan = (scanId: string, name: string): Promise<ScanRecord> =>
  patch<ScanRecord>(`/scans/${scanId}`, { name });

export const deleteScan = (scanId: string): Promise<void> =>
  del(`/scans/${scanId}`);

export const getScan = (scanId: string): Promise<ScanRecord> =>
  get<ScanRecord>(`/scans/${scanId}`);

export const createScan = (body: {
  name?: string;
  target?: string;
  scan_type?: ScanType;
  agent_mode?: 'manual' | 'autonomous';
}): Promise<ScanCreatedResponse> =>
  post<ScanCreatedResponse>('/scans', body);

/** Returns a WebSocket connected to the scan progress stream. */
export function scanWebSocket(scanId: string): WebSocket {
  return new WebSocket(`${WS}/scans/ws/${scanId}`);
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

export const getDevices = (scanId?: string): Promise<DeviceRecord[]> =>
  get<DeviceRecord[]>(scanId ? `/devices?scan_id=${scanId}` : '/devices');

// ---------------------------------------------------------------------------
// Vulnerabilities
// ---------------------------------------------------------------------------

export const getVulnerabilities = (scanId?: string): Promise<VulnRecord[]> =>
  get<VulnRecord[]>(scanId ? `/vulnerabilities?scan_id=${scanId}` : '/vulnerabilities');

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export const getDashboardStats = (): Promise<DashboardStats> =>
  get<DashboardStats>('/dashboard/stats');

export const getActivityFeed = (limit = 50): Promise<ActivityEventRecord[]> =>
  get<ActivityEventRecord[]>(`/dashboard/activity-feed?limit=${limit}`);

export const getAgentsStatus = (): Promise<{ active_count: number }> =>
  get<{ active_count: number }>('/agents/status')

// Raw topology payload — shape matches what fromRawScan() in raw-scan-parser.ts expects
export interface RawTopologyHost {
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

export interface RawTopologyVuln {
  host?: string;
  ip?: string;
  cve_id: string;
  severity?: string | null;
  predicted_score?: number | null;
  summary?: string | null;
}

export interface RawTopologyPayload {
  hosts: RawTopologyHost[];
  vulns?: RawTopologyVuln[];
  topology: {
    nodes: {
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
    }[];
    links: { source: string; target: string; type: string }[];
    metadata: Record<string, unknown>;
  };
}

export const getTopology = (scanId?: string): Promise<RawTopologyPayload> =>
  get<RawTopologyPayload>(scanId ? `/topology?scan_id=${scanId}` : '/topology');

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export const getReportTemplates = (): Promise<ReportTemplate[]> =>
  get<ReportTemplate[]>('/reports/templates');

export const generateReport = (body: {
  template_id: string;
  scan_id: string;
}): Promise<ReportRecord> =>
  post<ReportRecord>('/reports/generate', body);

export const getReport = (reportId: string): Promise<ReportRecord> =>
  get<ReportRecord>(`/reports/${reportId}`);

export const getReports = (scanId?: string): Promise<ReportRecord[]> =>
  get<ReportRecord[]>(scanId ? `/reports?scan_id=${scanId}` : '/reports');

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

/** Format duration_s (float seconds) into a human-readable string. */
export function formatDuration(seconds: number | null): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  if (m < 60) return `${m}m ${s}s`;
  const h = Math.floor(m / 60);
  const rm = m % 60;
  return `${h}h ${rm}m`;
}
