'use client';

import { useState } from 'react';
import { ChevronRight, Copy, Trash2, Plus, Check } from 'lucide-react';

const sections = [
  'General',
  'Agents',
  'Network',
  'Notifications',
  'API Keys',
  'Appearance',
];

const agents = [
  {
    name: 'Reconnaissance',
    description: 'Network discovery and asset enumeration',
    enabled: true,
  },
  {
    name: 'Enumeration',
    description: 'Service identification and banner grabbing',
    enabled: true,
  },
  {
    name: 'Vulnerability Analysis',
    description: 'CVE detection and severity scoring',
    enabled: true,
  },
  {
    name: 'Risk Assessment',
    description: 'Impact analysis and prioritization',
    enabled: true,
  },
  {
    name: 'Reporting',
    description: 'Documentation generation and export',
    enabled: false,
  },
];

const apiKeys = [
  {
    name: 'Production API',
    key: 'sk_live_••••••••••••••••••••1a2b',
    created: 'Jan 15, 2026',
    lastUsed: '2 hours ago',
  },
  {
    name: 'Development',
    key: 'sk_test_••••••••••••••••••••3c4d',
    created: 'Dec 8, 2025',
    lastUsed: 'Never',
  },
];

const notificationTypes = [
  {
    id: 'critical',
    label: 'Critical Vulnerability Found',
    description: 'Alert when CVSS ≥ 9.0 is discovered',
  },
  {
    id: 'exploit',
    label: 'Exploit Success',
    description: 'Notify when exploitation attempt succeeds',
  },
  {
    id: 'scan',
    label: 'Scan Complete',
    description: 'Alert when scheduled scan finishes',
  },
  {
    id: 'error',
    label: 'Agent Error',
    description: 'Notify on agent failures or timeouts',
  },
];

export function Settings() {
  const [activeSection, setActiveSection] = useState('General');
  const [agentStates, setAgentStates] = useState(
    agents.reduce((acc, agent) => ({ ...acc, [agent.name]: agent.enabled }), {} as Record<string, boolean>)
  );

  type NotificationKey = 'critical' | 'exploit' | 'scan' | 'error';

  const [notifications, setNotifications] = useState<Record<NotificationKey, boolean>>({
    critical: true,
    exploit: true,
    scan: false,
    error: true,
  });
  const [selectedAccent, setSelectedAccent] = useState('green');

  const toggleAgent = (name: string) => {
    setAgentStates((prev) => ({ ...prev, [name]: !prev[name] }));
  };

  const toggleNotification = (id: string) => {
    const key = id as NotificationKey;
    setNotifications((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const renderContent = () => {
    switch (activeSection) {
      case 'General':
        return (
          <div className="space-y-6">
            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Tool Name</label>
              <input
                type="text"
                defaultValue="SURGE"
                className="w-full bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#00E676] transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Organization</label>
              <input
                type="text"
                defaultValue="Enterprise Lab"
                className="w-full bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#00E676] transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Lab Environment Name</label>
              <input
                type="text"
                defaultValue="Production Testing Lab"
                className="w-full bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#00E676] transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Timezone</label>
              <select className="w-full bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#00E676] transition-colors">
                <option>UTC-8 (Pacific Time)</option>
                <option>UTC-5 (Eastern Time)</option>
                <option>UTC+0 (GMT)</option>
                <option>UTC+1 (Central European Time)</option>
              </select>
            </div>

            <div className="border-t border-[#1F2937] pt-6 mt-8">
              <h3 className="font-semibold text-white mb-4">Danger Zone</h3>
              <div className="space-y-3">
                <button className="w-full px-4 py-3 bg-[#0F1117] hover:bg-[#16181F] border border-[#FF1744]/30 text-[#FF1744] rounded-lg text-sm font-medium transition-colors">
                  Reset All Data
                </button>
                <button className="w-full px-4 py-3 bg-[#0F1117] hover:bg-[#16181F] border border-[#FF1744]/30 text-[#FF1744] rounded-lg text-sm font-medium transition-colors">
                  Factory Reset
                </button>
              </div>
            </div>
          </div>
        );

      case 'Agents':
        return (
          <div className="space-y-4">
            {agents.map((agent) => (
              <div key={agent.name} className="bg-[#0F1117] rounded-lg p-6">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <h3 className="font-semibold text-white mb-1">{agent.name}</h3>
                    <p className="text-sm text-[#6B7280]">{agent.description}</p>
                  </div>
                  <button
                    onClick={() => toggleAgent(agent.name)}
                    className={`w-10 h-5 rounded-full transition-colors ${
                      agentStates[agent.name] ? 'bg-[#00E676]' : 'bg-[#1F2937]'
                    }`}
                  >
                    <div
                      className={`w-4 h-4 bg-white rounded-full transition-transform ${
                        agentStates[agent.name] ? 'translate-x-5' : 'translate-x-0.5'
                      }`}
                    />
                  </button>
                </div>

                {agentStates[agent.name] && (
                  <div className="mt-4 pt-4 border-t border-[#1F2937] space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs text-[#6B7280] mb-1">Timeout (seconds)</label>
                        <input
                          type="number"
                          defaultValue="300"
                          className="w-full bg-[#13151C] border border-[#1F2937] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#00E676] transition-colors"
                        />
                      </div>
                      <div>
                        <label className="block text-xs text-[#6B7280] mb-1">Retry Limit</label>
                        <input
                          type="number"
                          defaultValue="3"
                          className="w-full bg-[#13151C] border border-[#1F2937] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#00E676] transition-colors"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs text-[#6B7280] mb-2">Verbosity Level</label>
                      <div className="flex items-center gap-0 bg-[#13151C] rounded p-0.5">
                        {['Minimal', 'Standard', 'Verbose'].map((level) => (
                          <button
                            key={level}
                            className={`flex-1 px-3 py-1.5 rounded text-xs font-medium transition-all ${
                              level === 'Standard'
                                ? 'bg-[#16181F] text-white'
                                : 'text-[#6B7280] hover:text-white'
                            }`}
                          >
                            {level}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        );

      case 'Network':
        return (
          <div className="space-y-6">
            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Default Scan Target Range</label>
              <input
                type="text"
                defaultValue="192.168.1.0/24"
                className="w-full bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white font-mono focus:outline-none focus:border-[#00E676] transition-colors"
              />
            </div>

            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Excluded IP Addresses</label>
              <div className="flex flex-wrap gap-2 bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 min-h-[44px]">
                <span className="px-2 py-1 bg-[#16181F] text-white text-sm rounded flex items-center gap-1">
                  192.168.1.1
                  <button className="text-[#6B7280] hover:text-white">×</button>
                </span>
                <span className="px-2 py-1 bg-[#16181F] text-white text-sm rounded flex items-center gap-1">
                  192.168.1.254
                  <button className="text-[#6B7280] hover:text-white">×</button>
                </span>
                <input
                  type="text"
                  placeholder="Add IP..."
                  className="flex-1 min-w-[120px] bg-transparent text-white text-sm focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="block text-sm text-[#6B7280] mb-2">Max Concurrent Threads</label>
              <div className="flex items-center gap-3">
                <input
                  type="number"
                  defaultValue="16"
                  className="flex-1 bg-[#0F1117] border border-[#1F2937] rounded-lg px-4 py-2 text-white focus:outline-none focus:border-[#00E676] transition-colors"
                />
                <div className="flex gap-1">
                  <button className="w-10 h-10 bg-[#0F1117] hover:bg-[#16181F] border border-[#1F2937] rounded-lg text-white transition-colors">
                    −
                  </button>
                  <button className="w-10 h-10 bg-[#0F1117] hover:bg-[#16181F] border border-[#1F2937] rounded-lg text-white transition-colors">
                    +
                  </button>
                </div>
              </div>
            </div>

            <div>
              <div className="flex items-start justify-between p-4 bg-[#0F1117] rounded-lg">
                <div className="flex-1">
                  <div className="font-semibold text-white mb-1">Stealth Mode</div>
                  <p className="text-sm text-[#6B7280]">
                    Reduce scan speed and randomize packet timing to avoid detection
                  </p>
                </div>
                <button className="w-10 h-5 rounded-full bg-[#1F2937] ml-4">
                  <div className="w-4 h-4 bg-white rounded-full translate-x-0.5" />
                </button>
              </div>
            </div>
          </div>
        );

      case 'Notifications':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="font-semibold text-white mb-4">Alert Types</h3>
              <div className="space-y-3">
                {notificationTypes.map((type) => (
                  <div
                    key={type.id}
                    className="flex items-start justify-between p-4 bg-[#0F1117] rounded-lg"
                  >
                    <div className="flex-1">
                      <div className="font-medium text-white mb-1">{type.label}</div>
                      <p className="text-sm text-[#6B7280]">{type.description}</p>
                    </div>
                    <button
                      onClick={() => toggleNotification(type.id)}
                      className={`w-10 h-5 rounded-full transition-colors ${
                        notifications[type.id as keyof typeof notifications]
                          ? 'bg-[#00E676]'
                          : 'bg-[#1F2937]'
                      }`}
                    >
                      <div
                        className={`w-4 h-4 bg-white rounded-full transition-transform ${
                          notifications[type.id as keyof typeof notifications]
                            ? 'translate-x-5'
                            : 'translate-x-0.5'
                        }`}
                      />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <h3 className="font-semibold text-white mb-4">Notification Channels</h3>
              <div className="space-y-3">
                <div className="flex items-center justify-between p-4 bg-[#0F1117] rounded-lg">
                  <span className="text-white">In-App</span>
                  <button className="w-10 h-5 rounded-full bg-[#00E676]">
                    <div className="w-4 h-4 bg-white rounded-full translate-x-5" />
                  </button>
                </div>
                <div className="flex items-center justify-between p-4 bg-[#0F1117] rounded-lg">
                  <span className="text-white">Email</span>
                  <button className="w-10 h-5 rounded-full bg-[#00E676]">
                    <div className="w-4 h-4 bg-white rounded-full translate-x-5" />
                  </button>
                </div>
                <div className="p-4 bg-[#0F1117] rounded-lg">
                  <label className="block text-sm text-[#6B7280] mb-2">Webhook URL</label>
                  <input
                    type="text"
                    placeholder="https://your-webhook-url.com"
                    className="w-full bg-[#13151C] border border-[#1F2937] rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-[#00E676] transition-colors"
                  />
                </div>
              </div>
            </div>
          </div>
        );

      case 'API Keys':
        return (
          <div className="space-y-4">
            <button className="px-4 py-2 bg-[#00E676] hover:bg-[#00BFA5] text-[#0F1117] font-semibold rounded-lg flex items-center gap-2 transition-colors">
              <Plus className="w-4 h-4" />
              Generate New Key
            </button>

            <div className="bg-[#0F1117] rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-[#1F2937]">
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Name
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Key
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Created
                    </th>
                    <th className="text-left text-xs text-[#6B7280] font-medium px-6 py-3">
                      Last Used
                    </th>
                    <th className="text-right text-xs text-[#6B7280] font-medium px-6 py-3">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {apiKeys.map((key) => (
                    <tr key={key.name} className="border-b border-[#1F2937]">
                      <td className="px-6 py-4 text-sm text-white">{key.name}</td>
                      <td className="px-6 py-4">
                        <code className="text-sm text-[#6B7280] font-mono">{key.key}</code>
                      </td>
                      <td className="px-6 py-4 text-sm text-[#6B7280]">{key.created}</td>
                      <td className="px-6 py-4 text-sm text-[#6B7280]">{key.lastUsed}</td>
                      <td className="px-6 py-4 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button className="p-2 text-[#6B7280] hover:text-white transition-colors">
                            <Copy className="w-4 h-4" />
                          </button>
                          <button className="p-2 text-[#6B7280] hover:text-[#FF1744] transition-colors">
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );

      case 'Appearance':
        return (
          <div className="space-y-6">
            <div>
              <h3 className="font-semibold text-white mb-4">Theme</h3>
              <div className="grid grid-cols-3 gap-4">
                <div className="relative p-6 bg-[#0F1117] border-2 border-[#00E676] rounded-lg cursor-pointer">
                  <div className="absolute top-3 right-3">
                    <div className="w-5 h-5 bg-[#00E676] rounded-full flex items-center justify-center">
                      <Check className="w-3 h-3 text-[#0F1117]" />
                    </div>
                  </div>
                  <div className="w-full h-20 bg-gradient-to-br from-[#13151C] to-[#0F1117] rounded mb-3" />
                  <div className="text-sm text-white font-medium">Dark</div>
                </div>
                <div className="relative p-6 bg-[#0F1117] border-2 border-[#1F2937] rounded-lg opacity-50 cursor-not-allowed">
                  <div className="w-full h-20 bg-gradient-to-br from-[#F9FAFB] to-[#E5E7EB] rounded mb-3" />
                  <div className="text-sm text-white font-medium">Light</div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="px-2 py-1 bg-[#1F2937] text-[#6B7280] text-xs rounded">
                      Coming Soon
                    </span>
                  </div>
                </div>
                <div className="relative p-6 bg-[#0F1117] border-2 border-[#1F2937] rounded-lg opacity-50 cursor-not-allowed">
                  <div className="w-full h-20 bg-gradient-to-r from-[#13151C] to-[#F9FAFB] rounded mb-3" />
                  <div className="text-sm text-white font-medium">System</div>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="px-2 py-1 bg-[#1F2937] text-[#6B7280] text-xs rounded">
                      Coming Soon
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div>
              <h3 className="font-semibold text-white mb-4">Accent Color</h3>
              <div className="flex items-center gap-3">
                {[
                  { id: 'green', color: '#00E676' },
                  { id: 'amber', color: '#FFB300' },
                  { id: 'blue', color: '#2196F3' },
                ].map((accent) => (
                  <button
                    key={accent.id}
                    onClick={() => setSelectedAccent(accent.id)}
                    className={`w-12 h-12 rounded-lg transition-all ${
                      selectedAccent === accent.id
                        ? 'ring-2 ring-offset-2 ring-offset-[#13151C] scale-110'
                        : 'hover:scale-105'
                    }`}
                    style={{
                      backgroundColor: accent.color,
                      boxShadow: selectedAccent === accent.id ? `0 0 0 2px ${accent.color}` : 'none'
                    }}
                  >
                    {selectedAccent === accent.id && (
                      <Check className="w-5 h-5 text-[#0F1117] mx-auto" />
                    )}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <h3 className="font-semibold text-white mb-4">Density</h3>
              <div className="flex items-center gap-0 bg-[#0F1117] rounded-lg p-0.5 max-w-md">
                {['Compact', 'Default', 'Comfortable'].map((density) => (
                  <button
                    key={density}
                    className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                      density === 'Default'
                        ? 'bg-[#16181F] text-white'
                        : 'text-[#6B7280] hover:text-white'
                    }`}
                  >
                    {density}
                  </button>
                ))}
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      <div className="grid grid-cols-12 gap-6">
        {/* Left Sidebar */}
        <div className="col-span-3">
          <div className="bg-[#13151C] rounded-lg p-4 sticky top-24">
            <h2 className="font-semibold text-white mb-4 px-2">Settings</h2>
            <nav className="space-y-1">
              {sections.map((section) => (
                <button
                  key={section}
                  onClick={() => setActiveSection(section)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    activeSection === section
                      ? 'bg-[#16181F] text-white border-l-2 border-l-[#00E676] pl-[10px]'
                      : 'text-[#6B7280] hover:text-white hover:bg-[#16181F]/50'
                  }`}
                >
                  {section}
                  <ChevronRight className="w-4 h-4" />
                </button>
              ))}
            </nav>
          </div>
        </div>

        {/* Main Content */}
        <div className="col-span-9">
          <div className="bg-[#13151C] rounded-lg p-8">
            <h2 className="text-2xl font-semibold text-white mb-6">{activeSection}</h2>
            {renderContent()}
          </div>
        </div>
      </div>
    </div>
  );
}
