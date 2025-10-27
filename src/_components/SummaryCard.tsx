import { LucideIcon } from "lucide-react";
import { motion } from "motion/react";

interface SummaryCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  accentColor: string;
  subtitle?: string;
}

export function SummaryCard({ title, value, icon: Icon, accentColor, subtitle }: SummaryCardProps) {
  return (
    <motion.div
      whileHover={{ scale: 1.02, y: -2 }}
      className="relative p-6 rounded-xl bg-gradient-to-br from-white/5 to-white/[0.02] backdrop-blur-xl border border-white/10 overflow-hidden group"
    >
      {/* Glow effect */}
      <div
        className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-xl"
        style={{ background: `radial-gradient(circle at center, ${accentColor}20, transparent 70%)` }}
      />
      
      <div className="relative z-10">
        <div className="flex items-start justify-between mb-4">
          <div
            className="w-12 h-12 rounded-lg flex items-center justify-center"
            style={{
              background: `linear-gradient(135deg, ${accentColor}20, ${accentColor}10)`,
              boxShadow: `0 0 20px ${accentColor}30`
            }}
          >
            <Icon className="w-6 h-6" style={{ color: accentColor }} />
          </div>
        </div>
        
        <div>
          <p className="text-[#B0B0B0] text-sm mb-2 uppercase tracking-wide">{title}</p>
          <p className="text-3xl text-white mb-1">{value}</p>
          {subtitle && <p className="text-xs text-[#B0B0B0]">{subtitle}</p>}
        </div>
      </div>
    </motion.div>
  );
}
