import { Server, AlertTriangle, Activity, Radio } from 'lucide-react';

interface StatCardsProps {
  devicesScanned:       number;
  vulnerabilitiesFound: number;
  avgCvss:              number | null;
  activeScans:          number;
}

function MiniSparkline({ data }: { data: number[] }) {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;

  const points = data
    .map((value, index) => {
      const x = (index / (data.length - 1)) * 100;
      const y = 100 - ((value - min) / range) * 100;
      return `${x},${y}`;
    })
    .join(' ');

  return (
    <svg viewBox="0 0 100 30" className="w-20 h-8" preserveAspectRatio="none">
      <polyline
        points={points}
        fill="none"
        stroke="var(--accent)"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.6"
      />
    </svg>
  );
}

// Static sparkline placeholder — replace with real time-series data when available
const PLACEHOLDER_TREND = [20, 35, 28, 45, 38, 52, 48, 60, 55, 67, 72, 80];

export function StatCards({ devicesScanned, vulnerabilitiesFound, avgCvss, activeScans }: StatCardsProps) {
  const stats = [
    { label: 'Devices Scanned',      value: devicesScanned.toLocaleString(),                       icon: Server },
    { label: 'Vulnerabilities Found', value: vulnerabilitiesFound.toLocaleString(),                 icon: AlertTriangle },
    { label: 'Avg. CVSS Score',       value: avgCvss != null ? avgCvss.toFixed(1) : '—',            icon: Activity },
    { label: 'Active Scans',          value: activeScans.toString(),                                icon: Radio },
  ];

  return (
    <div className="grid grid-cols-4 gap-4">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <div
            key={stat.label}
            className="bg-surface-2 rounded-lg p-6 hover:bg-[#1A1C23] transition-colors"
          >
            <div className="flex items-start justify-between mb-3">
              <Icon className="w-5 h-5 text-muted" />
              <MiniSparkline data={PLACEHOLDER_TREND} />
            </div>
            <div className="text-3xl font-semibold text-foreground mb-1">{stat.value}</div>
            <div className="text-sm text-muted">{stat.label}</div>
          </div>
        );
      })}
    </div>
  );
}
