import { Shield } from 'lucide-react';

export function Footer() {
  return (
    <footer className="fixed bottom-0 left-0 right-0 border-t border-border bg-background z-50">
      <div className="flex items-center justify-between px-6 h-14">
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 bg-gradient-to-br from-[var(--accent)] to-[var(--accent-hover)] rounded-md flex items-center justify-center">
            <Shield className="w-3.5 h-3.5 text-[#0F1117]" strokeWidth={2.5} />
          </div>
          <span className="text-sm font-semibold text-foreground tracking-tight">SURGE</span>
          <span className="text-muted text-sm">— Agentic Network Analysis</span>
        </div>

        <div className="flex items-center gap-6 text-xs text-muted">
          <span>v1.0.0</span>
          <span>© {new Date().getFullYear()} Surge. All rights reserved.</span>
        </div>
      </div>
    </footer>
  );
}
