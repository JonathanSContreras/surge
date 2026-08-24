'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, User } from 'lucide-react';

const tabs = [
  { label: 'Dashboard', href: '/' },
  { label: 'Scans', href: '/scans' },
  { label: 'Topology', href: '/topology' },
  { label: 'Exploits', href: '/exploits' },
  { label: 'Reports', href: '/reports' },
  { label: 'Agents', href: '/agents' },
  { label: 'Settings', href: '/settings' },
];

export function Navbar() {
  const pathname = usePathname();

  return (
    <nav className="fixed top-0 left-0 right-0 bg-background border-b border-border z-50">
      <div className="flex items-center justify-between px-6 h-16">
        {/* Logo & Wordmark */}
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-gradient-to-br from-[var(--accent)] to-[var(--accent-hover)] rounded-lg flex items-center justify-center">
            <Shield className="w-5 h-5 text-[#0F1117]" strokeWidth={2.5} />
          </div>
          <span className="text-foreground font-semibold text-lg tracking-tight">SURGE</span>
        </div>

        {/* Center Navigation Tabs */}
        <div className="flex items-center gap-2 bg-surface-1 rounded-full p-1">
          {tabs.map(({ label, href }) => {
            const isActive = pathname === href;
            return (
              <Link
                key={href}
                href={href}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-surface-2 text-foreground'
                    : 'text-muted hover:text-foreground hover:bg-surface-2/50'
                }`}
              >
                {label}
              </Link>
            );
          })}
        </div>

        {/* Right: Status & Avatar */}
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="relative">
              <div className="w-2 h-2 bg-[var(--accent)] rounded-full animate-pulse"></div>
              <div className="absolute inset-0 w-2 h-2 bg-[var(--accent)] rounded-full animate-ping opacity-75"></div>
            </div>
            <span className="text-sm text-muted">System Active</span>
          </div>
          <div className="w-8 h-8 bg-surface-3 rounded-full flex items-center justify-center">
            <User className="w-4 h-4 text-foreground" />
          </div>
        </div>
      </div>
    </nav>
  );
}
