import { ScrollArea } from "./ui/scroll-area";
import { Badge } from "./ui/badge";
import { motion } from "motion/react";
import { Bot, AlertTriangle, Info, CheckCircle } from "lucide-react";

interface FeedbackItem {
  id: string;
  timestamp: string;
  severity: "info" | "warning" | "success" | "critical";
  message: string;
}

const mockFeedback: FeedbackItem[] = [
  {
    id: "1",
    timestamp: "14:32:15",
    severity: "critical",
    message: "Critical vulnerability detected on web-server (192.168.1.50) - CVE-2023-12345. Immediate patching recommended.",
  },
  {
    id: "2",
    timestamp: "14:30:42",
    severity: "success",
    message: "Successful exploitation of workstation-2 using EternalBlue exploit. Access granted.",
  },
  {
    id: "3",
    timestamp: "14:28:19",
    severity: "warning",
    message: "Database server has 5 medium-severity vulnerabilities. Consider updating to latest version.",
  },
  {
    id: "4",
    timestamp: "14:25:03",
    severity: "info",
    message: "Network scan completed. 8 devices discovered, analyzing attack surface...",
  },
  {
    id: "5",
    timestamp: "14:22:55",
    severity: "warning",
    message: "Outdated SSH version detected on 192.168.1.101. Brute force attack recommended.",
  },
  {
    id: "6",
    timestamp: "14:20:31",
    severity: "info",
    message: "GNN model analyzing network topology for optimal exploitation path.",
  },
];

export function AgentFeedback() {
  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case "critical":
        return {
          color: "#FF1744",
          bg: "bg-[#FF1744]/10",
          border: "border-[#FF1744]/30",
          icon: AlertTriangle,
        };
      case "warning":
        return {
          color: "#FFB300",
          bg: "bg-[#FFB300]/10",
          border: "border-[#FFB300]/30",
          icon: AlertTriangle,
        };
      case "success":
        return {
          color: "#00E676",
          bg: "bg-[#00E676]/10",
          border: "border-[#00E676]/30",
          icon: CheckCircle,
        };
      case "info":
        return {
          color: "#00E676",
          bg: "bg-white/5",
          border: "border-white/10",
          icon: Info,
        };
      default:
        return {
          color: "#00E676",
          bg: "bg-white/5",
          border: "border-white/10",
          icon: Info,
        };
    }
  };

  return (
    <div className="h-full flex flex-col bg-gradient-to-br from-white/5 to-white/[0.02] backdrop-blur-xl border border-white/10 rounded-xl overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-white/10 flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-[#00E676]/20 flex items-center justify-center">
          <Bot className="w-5 h-5 text-[#00E676]" />
        </div>
        <div>
          <h3 className="text-white uppercase tracking-wide">Agent Feedback</h3>
          <p className="text-xs text-[#B0B0B0]">AI-generated alerts & recommendations</p>
        </div>
      </div>

      {/* Feedback List */}
      <ScrollArea className="flex-1">
        <div className="p-3 space-y-3">
          {mockFeedback.map((item, idx) => {
            const config = getSeverityConfig(item.severity);
            const Icon = config.icon;

            return (
              <motion.div
                key={item.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.1 }}
                className={`p-4 rounded-lg border ${config.border} ${config.bg} backdrop-blur-sm group hover:scale-[1.02] transition-transform duration-300`}
              >
                <div className="flex items-start gap-3">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5"
                    style={{
                      background: `${config.color}20`,
                      boxShadow: `0 0 10px ${config.color}20`,
                    }}
                  >
                    <Icon className="w-4 h-4" style={{ color: config.color }} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-2">
                      <Badge
                        variant="outline"
                        className="uppercase text-xs px-2 py-0.5 border-0"
                        style={{
                          background: `${config.color}20`,
                          color: config.color,
                        }}
                      >
                        {item.severity}
                      </Badge>
                      <span className="text-xs text-[#B0B0B0]">{item.timestamp}</span>
                    </div>
                    <p className="text-sm text-white leading-relaxed">{item.message}</p>
                  </div>
                </div>
              </motion.div>
            );
          })}
        </div>
      </ScrollArea>
    </div>
  );
}
