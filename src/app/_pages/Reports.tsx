'use client';

import { useEffect, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import {
  FileText, Download, TrendingUp, Terminal, Globe, BookOpen, Users,
  type LucideIcon,
} from 'lucide-react';
import {
  getReportTemplates,
  getScans,
  generateReport,
  type ReportRecord,
  type ScanRecord,
} from '@/lib/api';

// ---------------------------------------------------------------------------
// Markdown section parser
// ---------------------------------------------------------------------------

interface MdSection {
  title: string;
  content: string;
}

function parseMarkdownSections(markdown: string): MdSection[] {
  const sections: MdSection[] = [];
  let currentTitle = '';
  let currentLines: string[] = [];

  for (const line of markdown.split('\n')) {
    if (line.startsWith('## ')) {
      if (currentTitle) {
        const content = currentLines.join('\n').trim();
        if (content) sections.push({ title: currentTitle, content });
      }
      currentTitle = line.slice(3).trim();
      currentLines = [];
    } else if (currentTitle) {
      currentLines.push(line);
    }
  }
  if (currentTitle) {
    const content = currentLines.join('\n').trim();
    if (content) sections.push({ title: currentTitle, content });
  }
  return sections;
}

// ---------------------------------------------------------------------------
// Template metadata
// ---------------------------------------------------------------------------

type TemplateId = 'executive' | 'technical' | 'public' | 'final';

interface TemplateMeta {
  id:       TemplateId;
  name:     string;
  audience: string;
  tagline:  string;
  icon:     LucideIcon;   // not ComponentType<{className}> — these are rendered with `style` too
  accent:   string;          // tailwind color class for border / text
  accentHex: string;         // hex for inline styles
}

const TEMPLATES: TemplateMeta[] = [
  {
    id:        'executive',
    name:      'Executive Report',
    audience:  'CEO / Board / Stakeholders',
    tagline:   'Risk exposure, financial impact, and exploit snapshot — no jargon.',
    icon:      TrendingUp,
    accent:    'border-[#FFB300] text-[#FFB300]',
    accentHex: '#FFB300',
  },
  {
    id:        'technical',
    name:      'Technical Report',
    audience:  'CISO / Security Team',
    tagline:   'Exploitation paths, coverage gaps, ports to close, and fix roadmap.',
    icon:      Terminal,
    accent:    'border-[#40C4FF] text-[#40C4FF]',
    accentHex: '#40C4FF',
  },
  {
    id:        'public',
    name:      'Public Facing',
    audience:  'Press / Newsletter / Public',
    tagline:   'High-level posture summary — no sensitive details, no technical data.',
    icon:      Globe,
    accent:    'border-[#00E676] text-[#00E676]',
    accentHex: '#00E676',
  },
  {
    id:        'final',
    name:      'Final Report',
    audience:  'All Audiences',
    tagline:   'Complete combined report across all perspectives.',
    icon:      BookOpen,
    accent:    'border-[#CE93D8] text-[#CE93D8]',
    accentHex: '#CE93D8',
  },
];

// ---------------------------------------------------------------------------
// Financial impact estimation (Executive view)
// ---------------------------------------------------------------------------

function estimateFinancialImpact(risk: ReportRecord['risk_matrix']) {
  // Conservative industry-average breach cost per severity tier
  const COST = { critical: 50_000, high: 15_000, medium: 3_000, low: 500 };
  const total =
    risk.critical * COST.critical +
    risk.high     * COST.high +
    risk.medium   * COST.medium +
    risk.low      * COST.low;
  const fmt = (n: number) =>
    n >= 1_000_000
      ? `$${(n / 1_000_000).toFixed(1)}M`
      : n >= 1_000
      ? `$${(n / 1_000).toFixed(0)}K`
      : `$${n}`;
  return {
    total:    fmt(total),
    critical: fmt(risk.critical * COST.critical),
    high:     fmt(risk.high     * COST.high),
    medium:   fmt(risk.medium   * COST.medium),
    low:      fmt(risk.low      * COST.low),
  };
}

// ---------------------------------------------------------------------------
// Section renderers per template
// ---------------------------------------------------------------------------

function SectionBlock({ title, content, accent }: { title: string; content: string; accent: string }) {
  return (
    <div>
      <h3 className="text-base font-semibold mb-3" style={{ color: accent }}>{title}</h3>
      <div className="text-sm text-muted-foreground leading-relaxed">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={{
            p:      ({ children }) => <p className="mb-3 text-muted-foreground">{children}</p>,
            strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
            em:     ({ children }) => <em className="text-muted-foreground">{children}</em>,
            ul:     ({ children }) => <ul className="list-disc space-y-2 mb-3 text-muted-foreground pl-5">{children}</ul>,
            ol:     ({ children }) => <ol className="list-decimal space-y-3 mb-3 text-muted-foreground pl-5">{children}</ol>,
            li:     ({ children }) => <li className="text-muted-foreground leading-relaxed [&>p]:inline [&>p]:m-0">{children}</li>,
            h3:     ({ children }) => <h4 className="text-sm font-semibold text-foreground mt-4 mb-2">{children}</h4>,
            h4:     ({ children }) => <h5 className="text-sm font-medium text-[#D1D5DB] mt-3 mb-1">{children}</h5>,
            table:  ({ children }) => (
              <div className="overflow-x-auto mb-4">
                <table className="w-full text-xs border-collapse">{children}</table>
              </div>
            ),
            thead: ({ children }) => <thead>{children}</thead>,
            tbody: ({ children }) => <tbody>{children}</tbody>,
            tr:    ({ children }) => <tr className="border-b border-border">{children}</tr>,
            th:    ({ children }) => (
              <th className="text-left px-3 py-2 text-muted font-medium bg-background whitespace-nowrap">{children}</th>
            ),
            td:    ({ children }) => (
              <td className="px-3 py-2 text-muted-foreground align-top">{children}</td>
            ),
            code:  ({ children }) => (
              <code className="bg-background text-[#00E676] px-1.5 py-0.5 rounded text-xs font-mono">{children}</code>
            ),
            blockquote: ({ children }) => (
              <blockquote className="border-l-2 border-[#374151] pl-4 italic text-muted mb-3">{children}</blockquote>
            ),
            hr: () => <hr className="border-border my-4" />,
          }}
        >
          {content}
        </ReactMarkdown>
      </div>
    </div>
  );
}

function AllSections({ sections, accent }: { sections: MdSection[]; accent: string }) {
  if (sections.length === 0) return null;
  return (
    <div className="space-y-8">
      {sections.map((s) => (
        <SectionBlock key={s.title} title={s.title} content={s.content} accent={accent} />
      ))}
    </div>
  );
}

function RiskBadge({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex-1 bg-background rounded-lg p-4 text-center">
      <div className="text-2xl font-bold mb-1" style={{ color }}>{count}</div>
      <div className="text-xs text-muted uppercase tracking-wide">{label}</div>
    </div>
  );
}

function ExecutiveView({ report, scan }: { report: ReportRecord; scan?: ScanRecord }) {
  const fin = estimateFinancialImpact(report.risk_matrix);
  const totalVulns =
    report.risk_matrix.critical + report.risk_matrix.high +
    report.risk_matrix.medium  + report.risk_matrix.low;
  const sections = report.raw_markdown ? parseMarkdownSections(report.raw_markdown) : [];

  return (
    <div className="space-y-8">
      {/* KPI strip */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-[#FFB300] mb-1">{fin.total}</div>
          <div className="text-xs text-muted">Est. Total Exposure</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-[#FF1744] mb-1">{report.risk_matrix.critical}</div>
          <div className="text-xs text-muted">Critical Vulnerabilities</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-foreground mb-1">{totalVulns}</div>
          <div className="text-xs text-muted">Total Findings</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-foreground mb-1">{scan?.devices_count ?? '—'}</div>
          <div className="text-xs text-muted">Devices Scanned</div>
        </div>
      </div>

      {/* Risk distribution */}
      <div>
        <h3 className="text-base font-semibold mb-3" style={{ color: '#FFB300' }}>Risk Distribution</h3>
        <div className="flex gap-3">
          <RiskBadge label="Critical" count={report.risk_matrix.critical} color="#FF1744" />
          <RiskBadge label="High"     count={report.risk_matrix.high}     color="#FF6D00" />
          <RiskBadge label="Medium"   count={report.risk_matrix.medium}   color="#FFB300" />
          <RiskBadge label="Low"      count={report.risk_matrix.low}      color="#6B7280" />
        </div>
      </div>

      {/* All AI-written sections */}
      <AllSections sections={sections} accent="#FFB300" />
    </div>
  );
}

function TechnicalView({ report }: { report: ReportRecord }) {
  const sections = report.raw_markdown ? parseMarkdownSections(report.raw_markdown) : [];

  return (
    <div className="space-y-8">
      {/* Risk matrix */}
      <div>
        <h3 className="text-base font-semibold mb-3" style={{ color: '#40C4FF' }}>Severity Breakdown</h3>
        <div className="flex gap-3">
          <RiskBadge label="Critical" count={report.risk_matrix.critical} color="#FF1744" />
          <RiskBadge label="High"     count={report.risk_matrix.high}     color="#FF6D00" />
          <RiskBadge label="Medium"   count={report.risk_matrix.medium}   color="#FFB300" />
          <RiskBadge label="Low"      count={report.risk_matrix.low}      color="#6B7280" />
        </div>
      </div>

      {/* All AI-written sections */}
      <AllSections sections={sections} accent="#40C4FF" />
    </div>
  );
}

function PublicView({ report, scan }: { report: ReportRecord; scan?: ScanRecord }) {
  const totalVulns =
    report.risk_matrix.critical + report.risk_matrix.high +
    report.risk_matrix.medium  + report.risk_matrix.low;

  const posture =
    report.risk_matrix.critical > 0 ? 'Elevated'
    : report.risk_matrix.high > 2   ? 'Moderate'
    : 'Acceptable';
  const postureColor =
    posture === 'Elevated' ? '#FF6D00' : posture === 'Moderate' ? '#FFB300' : '#00E676';

  const sections = report.raw_markdown ? parseMarkdownSections(report.raw_markdown) : [];

  return (
    <div className="space-y-8">
      {/* Posture banner */}
      <div className="bg-background rounded-lg p-6 text-center">
        <div className="text-xs uppercase tracking-widest text-muted mb-2">Overall Security Posture</div>
        <div className="text-4xl font-bold mb-2" style={{ color: postureColor }}>{posture}</div>
        <div className="text-sm text-muted">
          Based on the most recent network assessment{scan ? ` of ${scan.target_range}` : ''}.
        </div>
      </div>

      {/* Stats */}
      <div>
        <h3 className="text-base font-semibold mb-3" style={{ color: '#00E676' }}>By the Numbers</h3>
        <div className="grid grid-cols-3 gap-4">
          <div className="bg-background rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-foreground mb-1">{scan?.devices_count ?? '—'}</div>
            <div className="text-xs text-muted">Endpoints Assessed</div>
          </div>
          <div className="bg-background rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-foreground mb-1">{totalVulns}</div>
            <div className="text-xs text-muted">Issues Identified</div>
          </div>
          <div className="bg-background rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-[#00E676] mb-1">Active</div>
            <div className="text-xs text-muted">Remediation Status</div>
          </div>
        </div>
      </div>

      {/* All AI-written sections */}
      <AllSections sections={sections} accent="#00E676" />

      <p className="text-xs text-[#4B5563]">
        This summary contains no sensitive technical details, IP addresses, or vulnerability identifiers.
        It is intended for public distribution only.
      </p>
    </div>
  );
}

function FinalView({ report, scan }: { report: ReportRecord; scan?: ScanRecord }) {
  const fin = estimateFinancialImpact(report.risk_matrix);
  const sections = report.raw_markdown ? parseMarkdownSections(report.raw_markdown) : [];

  return (
    <div className="space-y-8">
      {/* Combined KPI strip */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-[#CE93D8] mb-1">{fin.total}</div>
          <div className="text-xs text-muted">Est. Exposure</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-[#FF1744] mb-1">{report.risk_matrix.critical}</div>
          <div className="text-xs text-muted">Critical</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-foreground mb-1">{scan?.devices_count ?? '—'}</div>
          <div className="text-xs text-muted">Devices</div>
        </div>
        <div className="bg-background rounded-lg p-4 text-center">
          <div className="text-2xl font-bold text-foreground mb-1">
            {report.risk_matrix.critical + report.risk_matrix.high + report.risk_matrix.medium + report.risk_matrix.low}
          </div>
          <div className="text-xs text-muted">Total Findings</div>
        </div>
      </div>

      {/* Risk distribution */}
      <div>
        <h3 className="text-base font-semibold mb-3" style={{ color: '#CE93D8' }}>Risk Distribution</h3>
        <div className="flex gap-3">
          <RiskBadge label="Critical" count={report.risk_matrix.critical} color="#FF1744" />
          <RiskBadge label="High"     count={report.risk_matrix.high}     color="#FF6D00" />
          <RiskBadge label="Medium"   count={report.risk_matrix.medium}   color="#FFB300" />
          <RiskBadge label="Low"      count={report.risk_matrix.low}      color="#6B7280" />
        </div>
      </div>

      {/* All AI-written sections */}
      <AllSections sections={sections} accent="#CE93D8" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// PDF print helpers
// ---------------------------------------------------------------------------

function mdToHtml(md: string): string {
  const lines = md.split('\n');
  const out: string[] = [];
  let inUl = false, inOl = false, inTable = false, tableHeader = true;

  const inline = (s: string) =>
    s
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.+?)\*/g, '<em>$1</em>')
      .replace(/`(.+?)`/g, '<code>$1</code>');

  const closeList = () => {
    if (inUl) { out.push('</ul>'); inUl = false; }
    if (inOl) { out.push('</ol>'); inOl = false; }
  };
  const closeTable = () => {
    if (inTable) { out.push('</tbody></table>'); inTable = false; tableHeader = true; }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();

    // Headings
    if (line.startsWith('#### ')) { closeList(); closeTable(); out.push(`<h4>${inline(line.slice(5))}</h4>`); continue; }
    if (line.startsWith('### '))  { closeList(); closeTable(); out.push(`<h3>${inline(line.slice(4))}</h3>`); continue; }

    // Table rows
    if (line.startsWith('|')) {
      const cells = line.split('|').slice(1, -1).map((c) => c.trim());
      if (cells.every((c) => /^[-: ]+$/.test(c))) {
        // separator row — emit thead/tbody boundary
        out.push('</thead><tbody>');
        tableHeader = false;
        continue;
      }
      if (!inTable) {
        closeList();
        out.push('<table><thead>');
        inTable = true;
        tableHeader = true;
      }
      const tag = tableHeader ? 'th' : 'td';
      out.push(`<tr>${cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join('')}</tr>`);
      continue;
    }
    if (inTable) { closeTable(); }

    // Unordered list
    if (/^[-*] /.test(line)) {
      if (!inUl) { closeList(); out.push('<ul>'); inUl = true; }
      out.push(`<li>${inline(line.replace(/^[-*] /, ''))}</li>`);
      continue;
    }

    // Ordered list
    if (/^\d+\. /.test(line)) {
      if (!inOl) { closeList(); out.push('<ol>'); inOl = true; }
      out.push(`<li>${inline(line.replace(/^\d+\. /, ''))}</li>`);
      continue;
    }

    // Blank line
    if (line.trim() === '') { closeList(); out.push(''); continue; }

    // Paragraph
    closeList();
    out.push(`<p>${inline(line)}</p>`);
  }

  closeList(); closeTable();
  return out.join('\n');
}

interface PrintArgs {
  title: string; audience: string; scanId: string; target: string; date: string;
  risk: { critical: number; high: number; medium: number; low: number };
  totalVulns: number; fin: ReturnType<typeof estimateFinancialImpact>;
  devicesCount: number; sectionsHtml: string;
}

function buildPrintHtml(a: PrintArgs): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>${a.title} — SURGE</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Georgia', serif; font-size: 11pt; color: #1a1a1a; background: #fff; padding: 48px 56px; max-width: 900px; margin: 0 auto; }
  header { border-bottom: 3px solid #111; padding-bottom: 18px; margin-bottom: 28px; }
  header .label { font-size: 8pt; text-transform: uppercase; letter-spacing: .1em; color: #666; margin-bottom: 6px; }
  header h1 { font-size: 22pt; font-weight: bold; margin-bottom: 8px; }
  header .meta { font-size: 9pt; color: #666; }
  .kpis { display: grid; grid-template-columns: repeat(4,1fr); gap: 12px; margin-bottom: 28px; }
  .kpi { border: 1px solid #ddd; border-radius: 6px; padding: 14px 10px; text-align: center; }
  .kpi .val { font-size: 20pt; font-weight: bold; margin-bottom: 4px; }
  .kpi .lbl { font-size: 8pt; text-transform: uppercase; color: #777; letter-spacing: .06em; }
  .badges { display: flex; gap: 10px; margin-bottom: 28px; }
  .badge { flex: 1; border-radius: 6px; padding: 12px 8px; text-align: center; border: 1px solid; }
  .badge .bval { font-size: 18pt; font-weight: bold; margin-bottom: 3px; }
  .badge .blbl { font-size: 8pt; text-transform: uppercase; letter-spacing: .06em; color: #555; }
  h2 { font-size: 13pt; font-weight: bold; color: #1a3a6b; border-bottom: 1px solid #cdd5e0; padding-bottom: 5px; margin: 24px 0 10px; }
  h3 { font-size: 11pt; font-weight: bold; margin: 16px 0 6px; }
  h4 { font-size: 10pt; font-weight: bold; color: #333; margin: 12px 0 4px; }
  p  { margin-bottom: 8px; line-height: 1.65; }
  ul, ol { padding-left: 22px; margin-bottom: 10px; }
  li { margin-bottom: 4px; line-height: 1.55; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 9pt; }
  th { background: #f0f4f8; text-align: left; padding: 7px 10px; border: 1px solid #ccc; font-weight: bold; }
  td { padding: 6px 10px; border: 1px solid #ddd; vertical-align: top; }
  tr:nth-child(even) td { background: #fafbfc; }
  code { font-family: monospace; background: #f3f4f6; padding: 1px 4px; border-radius: 3px; font-size: 9pt; }
  footer { margin-top: 40px; border-top: 1px solid #ddd; padding-top: 12px; font-size: 8pt; color: #999; }
  @media print { body { padding: 0; } @page { margin: 18mm 16mm; } }
</style>
</head>
<body>
<header>
  <div class="label">${a.audience}</div>
  <h1>${a.title}</h1>
  <div class="meta">Generated: ${a.date} &nbsp;·&nbsp; Target: ${a.target} &nbsp;·&nbsp; Scan: ${a.scanId}</div>
</header>

<div class="kpis">
  <div class="kpi"><div class="val" style="color:#b45309">${a.fin.total}</div><div class="lbl">Est. Exposure</div></div>
  <div class="kpi"><div class="val" style="color:#dc2626">${a.risk.critical}</div><div class="lbl">Critical</div></div>
  <div class="kpi"><div class="val" style="color:#1a1a1a">${a.totalVulns}</div><div class="lbl">Total Findings</div></div>
  <div class="kpi"><div class="val" style="color:#1a1a1a">${a.devicesCount}</div><div class="lbl">Devices Scanned</div></div>
</div>

<div class="badges">
  <div class="badge" style="border-color:#fca5a5;background:#fff1f2"><div class="bval" style="color:#dc2626">${a.risk.critical}</div><div class="blbl">Critical</div></div>
  <div class="badge" style="border-color:#fdba74;background:#fff7ed"><div class="bval" style="color:#ea580c">${a.risk.high}</div><div class="blbl">High</div></div>
  <div class="badge" style="border-color:#fcd34d;background:#fffbeb"><div class="bval" style="color:#d97706">${a.risk.medium}</div><div class="blbl">Medium</div></div>
  <div class="badge" style="border-color:#d1d5db;background:#f9fafb"><div class="bval" style="color:#6b7280">${a.risk.low}</div><div class="blbl">Low</div></div>
</div>

${a.sectionsHtml}

<footer>Generated by SURGE Vulnerability Analysis Platform &nbsp;·&nbsp; ${a.title}</footer>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function Reports() {
  const [scans, setScans]                   = useState<ScanRecord[]>([]);
  const [selectedTemplate, setSelectedTemplate] = useState<TemplateId>('executive');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [report, setReport]                 = useState<ReportRecord | null>(null);
  const [generating, setGenerating]         = useState(false);
  const [error, setError]                   = useState<string | null>(null);
  const [showRaw, setShowRaw]               = useState(false);
  const [exporting, setExporting]           = useState(false);

  useEffect(() => {
    getReportTemplates().catch(console.error); // still call so backend registers any cache
    getScans()
      .then((data) => {
        const completed = data.filter((s) => s.status === 'completed');
        setScans(completed);
        if (completed.length > 0) setSelectedScanId(completed[0].scan_id);
      })
      .catch(console.error);
  }, []);

  async function handleGenerate() {
    if (!selectedScanId) return;
    setGenerating(true);
    setError(null);
    setReport(null);
    setShowRaw(false);
    try {
      const result = await generateReport({ template_id: selectedTemplate, scan_id: selectedScanId });
      setReport(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  }

  const activeMeta = TEMPLATES.find((t) => t.id === selectedTemplate)!;
  const selectedScan = scans.find((s) => s.scan_id === selectedScanId);

  function handleExportPdf() {
    if (!report) return;
    setExporting(true);
    try {
      const win = window.open('', '_blank');
      if (!win) return;
      const totalVulns = report.risk_matrix.critical + report.risk_matrix.high + report.risk_matrix.medium + report.risk_matrix.low;
      const fin = estimateFinancialImpact(report.risk_matrix);
      const sections = report.raw_markdown ? parseMarkdownSections(report.raw_markdown) : [];
      const sectionsHtml = sections.map((s) => `
        <h2>${s.title}</h2>
        ${mdToHtml(s.content)}
      `).join('');

      win.document.write(buildPrintHtml({
        title: activeMeta.name,
        audience: activeMeta.audience,
        scanId: report.scan_id.slice(0, 8).toUpperCase(),
        target: selectedScan?.target_range ?? '—',
        date: new Date(report.created_at).toLocaleDateString(),
        risk: report.risk_matrix,
        totalVulns,
        fin,
        devicesCount: selectedScan?.devices_count ?? 0,
        sectionsHtml,
      }));
      win.document.close();
      win.onload = () => { win.print(); };
    } finally {
      setExporting(false);
    }
  }

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      {/* Page header */}
      <div className="mb-6">
        <h1 className="text-lg font-semibold text-foreground">Reports</h1>
        <p className="text-sm text-muted mt-0.5">Generate audience-specific reports from completed scans.</p>
      </div>

      <div className="grid grid-cols-12 gap-6">
        {/* Left Sidebar */}
        <div className="col-span-3 space-y-4">
          {/* Template cards */}
          {TEMPLATES.map((t) => {
            const Icon = t.icon;
            const active = selectedTemplate === t.id;
            return (
              <button
                key={t.id}
                onClick={() => { setSelectedTemplate(t.id); setReport(null); setError(null); }}
                className={`w-full text-left p-4 rounded-lg border-l-2 transition-all ${
                  active
                    ? `bg-surface-2 ${t.accent}`
                    : 'bg-surface-1 border-l-transparent hover:bg-surface-2'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Icon
                    className="w-4 h-4 flex-shrink-0"
                    style={{ color: active ? t.accentHex : '#6B7280' }}
                  />
                  <span className={`text-sm font-semibold ${active ? 'text-foreground' : 'text-muted-foreground'}`}>
                    {t.name}
                  </span>
                </div>
                <div className="flex items-center gap-1.5 mb-2">
                  <Users className="w-3 h-3 text-[#4B5563]" />
                  <span className="text-xs text-[#4B5563]">{t.audience}</span>
                </div>
                <p className="text-xs text-muted leading-snug">{t.tagline}</p>
              </button>
            );
          })}

          {/* Generate card */}
          <div className="bg-surface-1 rounded-lg p-4">
            <h3 className="text-sm font-semibold text-foreground mb-3">Generate</h3>
            <div className="mb-3">
              <label className="block text-xs text-muted mb-1.5">Scan</label>
              {scans.length === 0 ? (
                <p className="text-xs text-muted">No completed scans yet.</p>
              ) : (
                <select
                  value={selectedScanId}
                  onChange={(e) => setSelectedScanId(e.target.value)}
                  className="w-full bg-background border border-border rounded px-3 py-2 text-foreground text-xs focus:outline-none focus:border-[var(--accent)]"
                >
                  {scans.map((s) => (
                    <option key={s.scan_id} value={s.scan_id}>
                      {s.name ?? `${s.scan_type.charAt(0).toUpperCase() + s.scan_type.slice(1)} Scan`}
                      {' · '}{s.scan_id.slice(0, 8).toUpperCase()}
                    </option>
                  ))}
                </select>
              )}
            </div>
            {error && <p className="text-xs text-[#FF1744] mb-3">{error}</p>}
            <button
              onClick={handleGenerate}
              disabled={generating || !selectedScanId}
              className="w-full font-semibold py-2 rounded-lg text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              style={{
                backgroundColor: activeMeta.accentHex,
                color: '#0F1117',
              }}
            >
              {generating ? 'Generating…' : `Generate ${activeMeta.name}`}
            </button>
          </div>
        </div>

        {/* Main Preview Area */}
        <div className="col-span-9">
          <div className="bg-surface-1 rounded-lg overflow-hidden">
            {/* Header */}
            <div
              className="p-5 border-b border-border flex items-center justify-between"
              style={{ borderLeftColor: activeMeta.accentHex, borderLeftWidth: 3 }}
            >
              <div className="flex items-center gap-3">
                {(() => { const Icon = activeMeta.icon; return <Icon className="w-5 h-5" style={{ color: activeMeta.accentHex }} />; })()}
                <div>
                  <h2 className="font-semibold text-foreground">{activeMeta.name}</h2>
                  <p className="text-xs text-muted mt-0.5">For: {activeMeta.audience}</p>
                </div>
              </div>
              {report && (
                <div className="flex items-center gap-2">
                  {report.raw_markdown && (
                    <button
                      onClick={() => setShowRaw((v) => !v)}
                      className="px-3 py-1.5 bg-surface-2 hover:bg-[#1A1C23] text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors"
                      style={{ color: showRaw ? activeMeta.accentHex : '#9CA3AF' }}
                    >
                      <FileText className="w-3.5 h-3.5" />
                      {showRaw ? 'Structured View' : 'Full Report'}
                    </button>
                  )}
                  <button
                    onClick={handleExportPdf}
                    disabled={exporting}
                    className="px-3 py-1.5 bg-surface-2 hover:bg-[#1A1C23] text-foreground text-xs font-medium rounded-lg flex items-center gap-1.5 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Download className="w-3.5 h-3.5" />
                    {exporting ? 'Exporting…' : 'Export PDF'}
                  </button>
                </div>
              )}
            </div>

            {/* Content */}
            <div className="p-8">
              {!report ? (
                <div className="bg-surface-3 rounded-lg p-12 text-center">
                  {(() => { const Icon = activeMeta.icon; return <Icon className="w-10 h-10 mx-auto mb-4 opacity-20" style={{ color: activeMeta.accentHex }} />; })()}
                  <p className="text-sm text-muted mb-1">{activeMeta.tagline}</p>
                  <p className="text-xs text-[#4B5563]">Select a completed scan and click Generate.</p>
                </div>
              ) : (
                <div className="bg-surface-3 rounded-lg p-8 max-w-4xl mx-auto">
                  {/* Report document header */}
                  <div className="border-b border-[#2D3748] pb-6 mb-8">
                    <div
                      className="text-xs uppercase tracking-widest font-medium mb-2"
                      style={{ color: activeMeta.accentHex }}
                    >
                      {activeMeta.audience}
                    </div>
                    <h1 className="text-2xl font-semibold text-foreground mb-2">{activeMeta.name}</h1>
                    <div className="flex items-center gap-3 text-xs text-muted flex-wrap">
                      <span>Generated: {new Date(report.created_at).toLocaleDateString()}</span>
                      <span>·</span>
                      {selectedScan && <span>Target: {selectedScan.target_range}</span>}
                      <span>·</span>
                      <span>Scan: {report.scan_id.slice(0, 8).toUpperCase()}</span>
                    </div>
                  </div>

                  {/* Template-specific content or raw markdown */}
                  {showRaw && report.raw_markdown ? (
                    <pre className="whitespace-pre-wrap text-sm text-muted-foreground font-mono leading-relaxed">
                      {report.raw_markdown}
                    </pre>
                  ) : (
                    <>
                      {selectedTemplate === 'executive' && (
                        <ExecutiveView report={report} scan={selectedScan} />
                      )}
                      {selectedTemplate === 'technical' && (
                        <TechnicalView report={report} />
                      )}
                      {selectedTemplate === 'public' && (
                        <PublicView report={report} scan={selectedScan} />
                      )}
                      {selectedTemplate === 'final' && (
                        <FinalView report={report} scan={selectedScan} />
                      )}
                    </>
                  )}

                  <div className="border-t border-[#2D3748] pt-6 mt-10">
                    <p className="text-xs text-[#4B5563]">
                      Generated by SURGE Vulnerability Analysis Platform · {activeMeta.name}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
