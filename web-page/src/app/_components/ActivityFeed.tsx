'use client';

import { useEffect, useState } from 'react';
import { Info, AlertTriangle, AlertCircle, CheckCircle } from 'lucide-react';
import { getActivityFeed, type ActivityEventRecord } from '@/lib/api';

const typeConfig = {
  info:     { icon: Info,          color: '#6B7280', label: 'Info' },
  warning:  { icon: AlertTriangle, color: '#FFB300', label: 'Warning' },
  critical: { icon: AlertCircle,   color: '#FF1744', label: 'Critical' },
  success:  { icon: CheckCircle,   color: '#00E676', label: 'Success' },
};

type Filter = 'All' | 'Alerts';
const FILTERS: Filter[] = ['All', 'Alerts'];

function formatTime(isoString: string): string {
  try {
    // SQLite omits timezone info — treat bare timestamps as UTC
    const normalized = /[Z+\-]\d*$/.test(isoString) ? isoString : isoString + 'Z';
    return new Date(normalized).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch {
    return isoString;
  }
}

export function ActivityFeed() {
  const [events, setEvents]       = useState<ActivityEventRecord[]>([]);
  const [filter, setFilter]       = useState<Filter>('All');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  useEffect(() => {
    const refresh = () => getActivityFeed(50).then(setEvents).catch(console.error);
    refresh();
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, []);

  const filtered = events.filter((e) => {
    if (filter === 'Alerts') return e.event_type === 'warning' || e.event_type === 'critical';
    return true;
  });

  return (
    <div className="bg-surface-1 rounded-lg h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-border">
        <h2 className="font-semibold text-foreground mb-3">Agent Activity</h2>
        <div className="flex items-center gap-2">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                filter === f
                  ? 'bg-surface-2 text-foreground'
                  : 'text-muted hover:text-foreground hover:bg-surface-2/50'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {filtered.length === 0 && (
          <p className="p-4 text-sm text-muted">No activity yet.</p>
        )}
        {filtered.map((event) => {
          const config = typeConfig[event.event_type as keyof typeof typeConfig] ?? typeConfig.info;
          const Icon = config.icon;
          const isExpanded = expandedId === event.id;

          return (
            <div
              key={event.id}
              className="p-4 border-b border-border hover:bg-surface-2/50 cursor-pointer transition-colors"
              onClick={() => setExpandedId(isExpanded ? null : event.id)}
            >
              <div className="flex items-start gap-3">
                <Icon className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: config.color }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <p className="text-sm text-foreground leading-snug">{event.message}</p>
                    <span className="text-xs text-muted whitespace-nowrap font-mono">
                      {formatTime(event.created_at)}
                    </span>
                  </div>
                  {event.ip && (
                    <code className="text-xs text-muted font-mono">{event.ip}</code>
                  )}
                  {isExpanded && event.detail && (
                    <p className="text-xs text-muted mt-2 leading-relaxed">{event.detail}</p>
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
