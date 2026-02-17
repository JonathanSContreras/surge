'use client';

import React, { useState } from 'react';
import { Play, MoreVertical } from 'lucide-react';

interface Scan {
  id: string;
  targetRange: string;
  type: 'Quick' | 'Deep' | 'Stealth';
  status: 'Running' | 'Completed' | 'Failed';
  devicesFound: number;
  vulnerabilities: number;
  duration: string;
  progress?: number;
  devices?: Array<{
    ip: string;
    hostname: string;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
}

const scans: Scan[] = [
  {
    id: 'SCN-2847',
    targetRange: '192.168.1.0/24',
    type: 'Deep',
    status: 'Running',
    devicesFound: 8,
    vulnerabilities: 24,
    duration: '12m 34s',
    progress: 67,
    devices: [
      { ip: '192.168.1.10', hostname: 'gateway-primary', critical: 2, high: 3, medium: 1, low: 0 },
      { ip: '192.168.1.45', hostname: 'db-server-01', critical: 1, high: 2, medium: 4, low: 2 },
    ],
  },
  {
    id: 'SCN-2846',
    targetRange: '10.0.0.0/16',
    type: 'Stealth',
    status: 'Completed',
    devicesFound: 142,
    vulnerabilities: 387,
    duration: '2h 18m',
    devices: [],
  },
  {
    id: 'SCN-2845',
    targetRange: '192.168.50.0/24',
    type: 'Quick',
    status: 'Completed',
    devicesFound: 32,
    vulnerabilities: 89,
    duration: '8m 42s',
    devices: [],
  },
  {
    id: 'SCN-2844',
    targetRange: '172.16.0.0/12',
    type: 'Deep',
    status: 'Failed',
    devicesFound: 0,
    vulnerabilities: 0,
    duration: '1m 05s',
    devices: [],
  },
];

const profiles = [
  { name: 'Lab Network — Deep', target: '192.168.1.0/24', type: 'Deep' },
  { name: 'DMZ — Stealth', target: '10.0.0.0/16', type: 'Stealth' },
  { name: 'Production — Quick', target: '172.16.0.0/12', type: 'Quick' },
];

const statusColors = {
  Running: 'bg-[#FFB300]/10 text-[#FFB300]',
  Completed: 'bg-[#00E676]/10 text-[#00E676]',
  Failed: 'bg-[#FF1744]/10 text-[#FF1744]',
};

export function Scans() {
  const [scanType, setScanType] = useState<'Quick' | 'Deep' | 'Stealth'>('Deep');
  const [agentMode, setAgentMode] = useState<'Manual' | 'Autonomous'>('Autonomous');
  const [filter, setFilter] = useState<'All' | 'Running' | 'Completed' | 'Failed'>('All');
  const [expandedScan, setExpandedScan] = useState<string | null>(null);

  const filters: Array<'All' | 'Running' | 'Completed' | 'Failed'> = [
    'All',
    'Running',
    'Completed',
    'Failed',
  ];

  const filteredScans = scans.filter((scan) => filter === 'All' || scan.status === filter);

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      <div className="grid grid-cols-12 gap-6">
        {/* Left Control Panel */}
        <div className="col-span-4">
          <div className="bg-[#13151C] rounded-lg p-6 mb-6">
            <h2 className="font-semibold text-white mb-4">New Scan</h2>

            {/* Target */}
            <div className="mb-4">
              <label className="block text-sm text-[#6B7280] mb-2">Target</label>
              <input
                type="text"
                placeholder="192.168.1.0/24"
                className="w-full bg-[#0F1117] border border-[#1F2937] rounded px-3 py-2 text-white font-mono text-sm focus:outline-none focus:border-[#00E676] transition-colors"
              />
            </div>

            {/* Scan Type */}
            <div className="mb-4">
              <label className="block text-sm text-[#6B7280] mb-2">Scan Type</label>
              <div className="flex items-center gap-0 bg-[#0F1117] rounded p-0.5">
                {(['Quick', 'Deep', 'Stealth'] as const).map((type) => (
                  <button
                    key={type}
                    onClick={() => setScanType(type)}
                    className={`flex-1 px-3 py-1.5 rounded text-sm font-medium transition-all ${
                      scanType === type
                        ? 'bg-[#16181F] text-white'
                        : 'text-[#6B7280] hover:text-white'
                    }`}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>

            {/* Agent Mode */}
            <div className="mb-6">
              <label className="block text-sm text-[#6B7280] mb-2">Agent Mode</label>
              <div className="flex items-center gap-0 bg-[#0F1117] rounded p-0.5">
                {(['Manual', 'Autonomous'] as const).map((mode) => (
                  <button
                    key={mode}
                    onClick={() => setAgentMode(mode)}
                    className={`flex-1 px-3 py-1.5 rounded text-sm font-medium transition-all ${
                      agentMode === mode
                        ? 'bg-[#16181F] text-white'
                        : 'text-[#6B7280] hover:text-white'
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>

            {/* Launch Button */}
            <button className="w-full bg-[#00E676] hover:bg-[#00BFA5] text-[#0F1117] font-semibold py-3 rounded-lg flex items-center justify-center gap-2 transition-colors">
              <Play className="w-4 h-4" fill="currentColor" />
              Launch Scan
            </button>
          </div>

          {/* Saved Profiles */}
          <div className="bg-[#13151C] rounded-lg p-6">
            <h3 className="font-semibold text-white mb-4">Saved Profiles</h3>
            <div className="space-y-2">
              {profiles.map((profile) => (
                <button
                  key={profile.name}
                  className="w-full text-left p-3 bg-[#0F1117] hover:bg-[#16181F] rounded-lg transition-colors"
                >
                  <div className="text-sm text-white mb-1">{profile.name}</div>
                  <div className="flex items-center gap-2">
                    <code className="text-xs text-[#6B7280] font-mono">{profile.target}</code>
                    <span className="text-xs text-[#6B7280]">•</span>
                    <span className="text-xs text-[#6B7280]">{profile.type}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Right Results Area */}
        <div className="col-span-8">
          <div className="bg-[#13151C] rounded-lg overflow-hidden">
            {/* Header */}
            <div className="p-6 border-b border-[#1F2937]">
              <div className="flex items-center justify-between mb-4">
                <h2 className="font-semibold text-white">Scan History</h2>
                <div className="flex items-center gap-2">
                  <div className="relative">
                    <div className="w-2 h-2 bg-[#00E676] rounded-full animate-pulse"></div>
                  </div>
                  <span className="text-sm text-[#6B7280]">Agents Active: 3</span>
                </div>
              </div>

              {/* Filters */}
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

            {/* Scans Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1F2937]">
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Scan ID
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Target Range
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Type
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Status
                    </th>
                    <th className="text-right text-xs text-[#6B7280] font-medium px-6 py-3">
                      Devices
                    </th>
                    <th className="text-right text-xs text-[#6B7280] font-medium px-6 py-3">
                      Vulns
                    </th>
                    <th className="text-right text-xs text-[#6B7280] font-medium px-6 py-3">
                      Duration
                    </th>
                    <th className="text-right text-xs text-[#6B7280] font-medium px-6 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredScans.map((scan) => (
                    <React.Fragment key={scan.id}>
                      <tr
                        className="border-b border-[#1F2937] hover:bg-[#16181F] transition-colors cursor-pointer"
                        onClick={() =>
                          setExpandedScan(expandedScan === scan.id ? null : scan.id)
                        }
                      >
                        <td className="px-6 py-4">
                          <code className="text-sm text-white font-mono">{scan.id}</code>
                        </td>
                        <td className="px-6 py-4">
                          <code className="text-sm text-[#6B7280] font-mono">
                            {scan.targetRange}
                          </code>
                        </td>
                        <td className="px-6 py-4">
                          <span className="text-sm text-[#6B7280]">{scan.type}</span>
                        </td>
                        <td className="px-6 py-4">
                          <div>
                            <span
                              className={`text-xs px-2 py-1 rounded inline-flex items-center gap-1.5 ${
                                statusColors[scan.status]
                              }`}
                            >
                              {scan.status === 'Running' && (
                                <div className="w-1.5 h-1.5 bg-[#FFB300] rounded-full animate-pulse" />
                              )}
                              {scan.status}
                            </span>
                            {scan.status === 'Running' && scan.progress !== undefined && (
                              <div className="mt-2 h-1 bg-[#1F2937] rounded-full overflow-hidden w-24">
                                <div
                                  className="h-full bg-[#FFB300]"
                                  style={{ width: `${scan.progress}%` }}
                                />
                              </div>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <span className="text-sm text-white">{scan.devicesFound}</span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <span className="text-sm text-white">{scan.vulnerabilities}</span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <span className="text-sm text-[#6B7280] font-mono">
                            {scan.duration}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button className="text-[#6B7280] hover:text-white transition-colors">
                            <MoreVertical className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                      {expandedScan === scan.id && scan.devices && scan.devices.length > 0 && (
                        <tr>
                          <td colSpan={8} className="bg-[#0F1117] px-6 py-4">
                            <div className="space-y-2">
                              <h4 className="text-sm font-semibold text-white mb-3">
                                Device Breakdown
                              </h4>
                              {scan.devices.map((device) => (
                                <div
                                  key={device.ip}
                                  className="flex items-center gap-4 p-3 bg-[#13151C] rounded"
                                >
                                  <div className="flex-1">
                                    <code className="text-sm text-white font-mono">
                                      {device.ip}
                                    </code>
                                    <div className="text-xs text-[#6B7280] mt-0.5">
                                      {device.hostname}
                                    </div>
                                  </div>
                                  <div className="flex items-center gap-2 flex-1">
                                    <div
                                      className="h-2 bg-[#FF1744] rounded"
                                      style={{
                                        width: `${(device.critical / 10) * 100}%`,
                                        minWidth: device.critical > 0 ? '8px' : '0',
                                      }}
                                    />
                                    <div
                                      className="h-2 bg-[#FF6F00] rounded"
                                      style={{
                                        width: `${(device.high / 10) * 100}%`,
                                        minWidth: device.high > 0 ? '8px' : '0',
                                      }}
                                    />
                                    <div
                                      className="h-2 bg-[#FFB300] rounded"
                                      style={{
                                        width: `${(device.medium / 10) * 100}%`,
                                        minWidth: device.medium > 0 ? '8px' : '0',
                                      }}
                                    />
                                    <div
                                      className="h-2 bg-[#00E676] rounded"
                                      style={{
                                        width: `${(device.low / 10) * 100}%`,
                                        minWidth: device.low > 0 ? '8px' : '0',
                                      }}
                                    />
                                  </div>
                                  <div className="flex items-center gap-3 text-xs">
                                    <span className="text-[#FF1744]">{device.critical} C</span>
                                    <span className="text-[#FF6F00]">{device.high} H</span>
                                    <span className="text-[#FFB300]">{device.medium} M</span>
                                    <span className="text-[#00E676]">{device.low} L</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
