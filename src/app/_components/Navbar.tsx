import { Shield, User } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  onTabChange: (tab: string) => void;
}

export function Navbar({ activeTab, onTabChange }: NavbarProps) {
  const tabs = ['Dashboard', 'Scans', 'Exploits', 'Reports', 'Settings'];

  return (
    <nav className="fixed top-0 left-0 right-0 bg-[#0F1117] border-b border-[#1F2937] z-50">
      <div className="flex items-center justify-between px-6 h-16">
        {/* Logo & Wordmark */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-[#00E676] to-[#00BFA5] rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-[#0F1117]" strokeWidth={2.5} />
          </div>
          <span className="text-white font-semibold text-lg tracking-tight">SURGE</span>
        </div>

        {/* Center Navigation Tabs */}
        <div className="flex items-center gap-2 bg-[#13151C] rounded-full p-1">
          {tabs.map((tab) => (
            <button
              key={tab}
              onClick={() => onTabChange(tab)}
              className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${
                tab === activeTab
                  ? 'bg-[#16181F] text-white'
                  : 'text-[#6B7280] hover:text-white hover:bg-[#16181F]/50'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Right: Status & Avatar */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="w-2 h-2 bg-[#00E676] rounded-full animate-pulse"></div>
              <div className="absolute inset-0 w-2 h-2 bg-[#00E676] rounded-full animate-ping opacity-75"></div>
            </div>
            <span className="text-sm text-[#6B7280]">System Active</span>
          </div>
          <div className="w-8 h-8 bg-gradient-to-br from-[#6B7280] to-[#4B5563] rounded-full flex items-center justify-center">
            <User className="w-4 h-4 text-white" />
          </div>
        </div>
      </div>
    </nav>
  );
}