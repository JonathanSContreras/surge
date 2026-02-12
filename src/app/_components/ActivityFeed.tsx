'use client';

import { useState } from 'react';
import { Info, AlertTriangle, AlertCircle, Shield, Bug } from 'lucide-react';

interface Activity {
  id: string;
  type: 'info' | 'warning' | 'critical' | 'patch' | 'exploit';
  timestamp: string;
  summary: string;
  detail: string;
  ip?: string;
}

const activities: Activity[] = [
  {
    id: '1',
    type: 'critical',
    timestamp: '14:23:45',
    summary: 'CVE-2024-1234 detected on gateway-primary',
    detail: 'Critical remote code execution vulnerability detected. Buffer overflow in network stack allows arbitrary code execution. Immediate patching required.',
    ip: '192.168.1.10',
  },
  {
    id: '2',
    type: 'exploit',
    timestamp: '14:22:11',
    summary: 'Exploit attempt successful on db-server-01',
    detail: 'SQL injection payload successfully executed. Database credentials exposed. Agent deployed countermeasures.',
    ip: '192.168.1.45',
  },
  {
    id: '3',
    type: 'warning',
    timestamp: '14:19:33',
    summary: 'Outdated TLS configuration on mail-server',
    detail: 'TLS 1.0 still enabled. Weak cipher suites detected. Recommendation: upgrade to TLS 1.3 minimum.',
    ip: '192.168.1.124',
  },
  {
    id: '4',
    type: 'patch',
    timestamp: '14:15:02',
    summary: 'Security patch applied to web-frontend',
    detail: 'Successfully patched XSS vulnerability in input validation layer. Service restarted without downtime.',
    ip: '192.168.1.67',
  },
  {
    id: '5',
    type: 'info',
    timestamp: '14:12:18',
    summary: 'Scan initiated on analytics-node',
    detail: 'Deep packet inspection and vulnerability assessment started. Estimated completion: 8 minutes.',
    ip: '192.168.1.178',
  },
  {
    id: '6',
    type: 'warning',
    timestamp: '14:08:54',
    summary: 'Elevated privilege escalation risk on dev-workstation',
    detail: 'Weak sudo configuration detected. User permissions exceed principle of least privilege.',
    ip: '192.168.1.156',
  },
  {
    id: '7',
    type: 'info',
    timestamp: '14:05:29',
    summary: 'Network topology mapping complete',
    detail: 'Discovered 8 active hosts, 23 open ports, 12 services. Vulnerability correlation in progress.',
  },
  {
    id: '8',
    type: 'critical',
    timestamp: '14:01:47',
    summary: 'Unpatched kernel vulnerability on backup-storage',
    detail: 'CVE-2024-5678: Local privilege escalation via race condition in filesystem driver. Patch available.',
    ip: '192.168.1.102',
  },
];

const typeConfig = {
  info: { icon: Info, color: '#6B7280', label: 'Info' },
  warning: { icon: AlertTriangle, color: '#FFB300', label: 'Warning' },
  critical: { icon: AlertCircle, color: '#FF1744', label: 'Critical' },
  patch: { icon: Shield, color: '#00E676', label: 'Patch' },
  exploit: { icon: Bug, color: '#FF1744', label: 'Exploit' },
};

export function ActivityFeed() {
  const [filter, setFilter] = useState<'All' | 'Alerts' | 'Patches' | 'Exploits'>('All');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filters: Array<'All' | 'Alerts' | 'Patches' | 'Exploits'> = ['All', 'Alerts', 'Patches', 'Exploits'];

  const filteredActivities = activities.filter((activity) => {
    if (filter === 'All') return true;
    if (filter === 'Alerts') return activity.type === 'warning' || activity.type === 'critical';
    if (filter === 'Patches') return activity.type === 'patch';
    if (filter === 'Exploits') return activity.type === 'exploit';
    return true;
  });

  return (
    <div className="bg-[#13151C] rounded-lg h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-[#1F2937]">
        <h2 className="font-semibold text-white mb-3">Agent Activity</h2>
        <div className="flex items-center gap-2">
          {filters.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                filter === f
                  ? 'bg-[#16181F] text-white'
                  : 'text-[#6B7280] hover:text-white hover:bg-[#16181F]/50'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Activity List */}
      <div className="flex-1 overflow-y-auto">
        {filteredActivities.map((activity) => {
          const config = typeConfig[activity.type];
          const Icon = config.icon;
          const isExpanded = expandedId === activity.id;

          return (
            <div
              key={activity.id}
              className="p-4 border-b border-[#1F2937] hover:bg-[#16181F]/50 cursor-pointer transition-colors"
              onClick={() => setExpandedId(isExpanded ? null : activity.id)}
            >
              <div className="flex items-start gap-3">
                <Icon
                  className="w-4 h-4 mt-0.5 flex-shrink-0"
                  style={{ color: config.color }}
                />
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm text-white leading-snug">{activity.summary}</p>
                    <span className="text-xs text-[#6B7280] whitespace-nowrap font-mono">
                      {activity.timestamp}
                    </span>
                  </div>
                  {activity.ip && (
                    <code className="text-xs text-[#6B7280] font-mono">{activity.ip}</code>
                  )}
                  {isExpanded && (
                    <p className="text-xs text-[#6B7280] mt-2 leading-relaxed">
                      {activity.detail}
                    </p>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
