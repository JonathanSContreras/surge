'use client';

import { useState } from 'react';
import { FileText, Download, Link as LinkIcon, Edit2, Clock } from 'lucide-react';

const templates = [
  {
    id: 'executive',
    name: 'Executive Summary',
    description: 'High-level overview for leadership',
  },
  {
    id: 'full',
    name: 'Full Vulnerability Report',
    description: 'Complete technical assessment',
  },
  {
    id: 'chain',
    name: 'Exploitation Chain Report',
    description: 'Attack path analysis and tactics',
  },
  {
    id: 'compliance',
    name: 'Compliance Overview',
    description: 'Regulatory framework alignment',
  },
  {
    id: 'custom',
    name: 'Custom',
    description: 'Build your own report structure',
  },
];

const reportSections = [
  { title: 'Executive Summary', content: 'High-level findings and risk assessment...' },
  { title: 'Scope', content: 'Network range: 192.168.1.0/24, Target devices: 247...' },
  { title: 'Methodology', content: 'Deep scan with autonomous agents, OWASP testing...' },
  {
    title: 'Key Findings',
    content: '1,842 vulnerabilities discovered across 8 critical categories...',
  },
  { title: 'Risk Matrix', content: 'Critical: 89, High: 247, Medium: 892, Low: 614...' },
  {
    title: 'Recommendations',
    content: 'Immediate patching required for CVE-2024-1234, CVE-2024-5678...',
  },
];

const scheduledReports = [
  { name: 'Weekly Security Digest', frequency: 'Weekly', nextRun: 'Feb 17, 2026 9:00 AM', enabled: true },
  { name: 'Monthly Compliance Report', frequency: 'Monthly', nextRun: 'Mar 1, 2026 8:00 AM', enabled: true },
  { name: 'Quarterly Executive Summary', frequency: 'Quarterly', nextRun: 'Apr 1, 2026 10:00 AM', enabled: false },
];

const frequencyColors = {
  Weekly: 'bg-[#00E676]/10 text-[#00E676]',
  Monthly: 'bg-[#FFB300]/10 text-[#FFB300]',
  Quarterly: 'bg-[#6B7280]/10 text-[#6B7280]',
};

export function Reports() {
  const [selectedTemplate, setSelectedTemplate] = useState('executive');

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      <div className="grid grid-cols-12 gap-6">
        {/* Left Sidebar */}
        <div className="col-span-3">
          {/* Templates */}
          <div className="bg-[#13151C] rounded-lg p-6 mb-6">
            <h2 className="font-semibold text-white mb-4">Report Templates</h2>
            <div className="space-y-2">
              {templates.map((template) => (
                <button
                  key={template.id}
                  onClick={() => setSelectedTemplate(template.id)}
                  className={`w-full text-left p-3 rounded-lg transition-all ${
                    selectedTemplate === template.id
                      ? 'bg-[#16181F] border-l-2 border-l-[#00E676]'
                      : 'bg-[#0F1117] hover:bg-[#16181F] border-l-2 border-l-transparent'
                  }`}
                >
                  <div className="text-sm text-white mb-1">{template.name}</div>
                  <div className="text-xs text-[#6B7280]">{template.description}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Scheduled Reports */}
          <div className="bg-[#13151C] rounded-lg p-6">
            <h3 className="font-semibold text-white mb-4">Scheduled Reports</h3>
            <div className="space-y-3">
              {scheduledReports.map((report) => (
                <div key={report.name} className="p-3 bg-[#0F1117] rounded-lg">
                  <div className="flex items-start justify-between mb-2">
                    <div className="text-sm text-white">{report.name}</div>
                    <button
                      className={`w-10 h-5 rounded-full transition-colors ${
                        report.enabled ? 'bg-[#00E676]' : 'bg-[#1F2937]'
                      }`}
                    >
                      <div
                        className={`w-4 h-4 bg-white rounded-full transition-transform ${
                          report.enabled ? 'translate-x-5' : 'translate-x-0.5'
                        }`}
                      />
                    </button>
                  </div>
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      frequencyColors[report.frequency as keyof typeof frequencyColors]
                    }`}
                  >
                    {report.frequency}
                  </span>
                  <div className="flex items-center gap-1 mt-2">
                    <Clock className="w-3 h-3 text-[#6B7280]" />
                    <span className="text-xs text-[#6B7280]">{report.nextRun}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main Preview Area */}
        <div className="col-span-9">
          <div className="bg-[#13151C] rounded-lg overflow-hidden">
            {/* Header */}
            <div className="p-6 border-b border-[#1F2937] flex items-center justify-between">
              <div>
                <h2 className="font-semibold text-white">Report Preview</h2>
                <p className="text-sm text-[#6B7280] mt-0.5">
                  {templates.find((t) => t.id === selectedTemplate)?.name}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button className="px-4 py-2 bg-[#16181F] hover:bg-[#1A1C23] text-white text-sm font-medium rounded-lg flex items-center gap-2 transition-colors">
                  <Download className="w-4 h-4" />
                  Export PDF
                </button>
                <button className="px-4 py-2 bg-[#16181F] hover:bg-[#1A1C23] text-white text-sm font-medium rounded-lg flex items-center gap-2 transition-colors">
                  <FileText className="w-4 h-4" />
                  Export CSV
                </button>
                <button className="px-4 py-2 bg-[#16181F] hover:bg-[#1A1C23] text-white text-sm font-medium rounded-lg flex items-center gap-2 transition-colors">
                  <LinkIcon className="w-4 h-4" />
                  Copy Link
                </button>
              </div>
            </div>

            {/* Preview Document */}
            <div className="p-8">
              <div className="bg-[#1A1D26] rounded-lg p-8 max-w-4xl mx-auto">
                {/* Report Header */}
                <div className="border-b border-[#2D3748] pb-6 mb-6">
                  <h1 className="text-2xl font-semibold text-white mb-2">
                    Security Assessment Report
                  </h1>
                  <div className="flex items-center gap-4 text-sm text-[#6B7280]">
                    <span>Generated: February 12, 2026</span>
                    <span>•</span>
                    <span>Organization: Enterprise Lab</span>
                    <span>•</span>
                    <span>Scan ID: SCN-2847</span>
                  </div>
                </div>

                {/* Report Sections */}
                <div className="space-y-6">
                  {reportSections.map((section, index) => (
                    <div key={index} className="group">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="text-lg font-semibold text-white">{section.title}</h3>
                        <button className="opacity-0 group-hover:opacity-100 transition-opacity text-[#6B7280] hover:text-white">
                          <Edit2 className="w-4 h-4" />
                        </button>
                      </div>
                      <p className="text-sm text-[#6B7280] leading-relaxed">{section.content}</p>
                    </div>
                  ))}
                </div>

                {/* Footer */}
                <div className="border-t border-[#2D3748] pt-6 mt-8">
                  <p className="text-xs text-[#6B7280]">
                    This report was automatically generated by SURGE Vulnerability Analysis Platform.
                    For questions or clarifications, contact security@enterprise.lab
                  </p>
                </div>
              </div>

              {/* Last Generated */}
              <div className="text-center mt-6">
                <p className="text-xs text-[#6B7280]">Last Generated: February 12, 2026 at 2:34 PM</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
