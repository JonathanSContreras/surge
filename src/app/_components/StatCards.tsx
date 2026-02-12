import { Server, AlertTriangle, Activity, Target } from 'lucide-react';

interface Stat {
  label: string;
  value: string;
  icon: React.ElementType;
  trend?: number[];
}

const stats: Stat[] = [
  {
    label: 'Devices Scanned',
    value: '247',
    icon: Server,
    trend: [20, 35, 28, 45, 38, 52, 48, 60, 55, 67, 72, 80],
  },
  {
    label: 'Vulnerabilities Found',
    value: '1,842',
    icon: AlertTriangle,
    trend: [40, 42, 38, 48, 52, 55, 58, 54, 60, 65, 62, 68],
  },
  {
    label: 'Avg. CVSS Score',
    value: '6.4',
    icon: Activity,
    trend: [50, 48, 52, 49, 54, 51, 56, 53, 58, 55, 60, 57],
  },
  {
    label: 'Exploit Success Rate',
    value: '73%',
    icon: Target,
    trend: [30, 35, 38, 42, 40, 45, 48, 52, 55, 58, 60, 65],
  },
];

function MiniSparkline({ data }: { data: number[] }) {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min;

  const points = data.map((value, index) => {
    const x = (index / (data.length - 1)) * 100;
    const y = 100 - ((value - min) / range) * 100;
    return `${x},${y}`;
  }).join(' ');

  return (
    <svg
      viewBox="0 0 100 30"
      className="w-20 h-8"
      preserveAspectRatio="none"
    >
      <polyline
        points={points}
        fill="none"
        stroke="#00E676"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        opacity="0.6"
      />
    </svg>
  );
}

export function StatCards() {
  return (
    <div className="grid grid-cols-4 gap-4">
      {stats.map((stat) => {
        const Icon = stat.icon;
        return (
          <div
            key={stat.label}
            className="bg-[#16181F] rounded-lg p-6 hover:bg-[#1A1C23] transition-colors"
          >
            <div className="flex items-start justify-between mb-3">
              <Icon className="w-5 h-5 text-[#6B7280]" />
              {stat.trend && <MiniSparkline data={stat.trend} />}
            </div>
            <div className="text-3xl font-semibold text-white mb-1">
              {stat.value}
            </div>
            <div className="text-sm text-[#6B7280]">{stat.label}</div>
          </div>
        );
      })}
    </div>
  );
}
