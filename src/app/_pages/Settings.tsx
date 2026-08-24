'use client';

import { useState, useEffect } from 'react';
import {
  ChevronRight,
  Check,
  Wifi,
  WifiOff,
  Loader2,
  Info,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function usePersisted<T>(key: string, initial: T): [T, (v: T) => void] {
  const [value, setValue] = useState<T>(() => {
    if (typeof window === 'undefined') return initial;
    try {
      const raw = localStorage.getItem(key);
      return raw !== null ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });

  const set = (v: T) => {
    setValue(v);
    localStorage.setItem(key, JSON.stringify(v));
  };

  return [value, set];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const sections = ['General', 'Pipeline', 'Model', 'Notifications', 'Appearance', 'About'];

const pipelineStages = [
  { name: 'Reconnaissance',       description: 'nmap discovers live hosts and open ports on the target network range.' },
  { name: 'Enumeration',          description: 'Service versions and banners are extracted from each open port.' },
  { name: 'Vulnerability Analysis', description: 'CVEs are matched via the CIRCL API and filtered by service relevance.' },
  { name: 'Risk Assessment',      description: 'An XGBoost ML model re-scores severity and predicts exploitability.' },
  { name: 'Reporting',            description: 'Structured reports are generated across Executive, Technical, and Remediation templates.' },
];

const notificationTypes = [
  { id: 'critical', label: 'Critical Vulnerability Found', description: 'Alert when CVSS ≥ 9.0 is discovered' },
  { id: 'exploit',  label: 'Exploit Success',              description: 'Notify when exploitation attempt succeeds' },
  { id: 'scan',     label: 'Scan Complete',                description: 'Alert when a scan finishes' },
  { id: 'error',    label: 'Agent Error',                  description: 'Notify on agent failures or timeouts' },
];

type AccentId = 'green' | 'amber' | 'blue';
type Density  = 'Compact' | 'Default' | 'Comfortable';
type Theme    = 'dark' | 'light' | 'system';

const accentMap: Record<AccentId, { hex: string; hover: string }> = {
  green: { hex: '#00E676', hover: '#00BFA5' },
  amber: { hex: '#FFB300', hover: '#E6A200' },
  blue:  { hex: '#2196F3', hover: '#1976D2' },
};

const densityMap: Record<Density, string> = {
  Compact:     '14px',
  Default:     '16px',
  Comfortable: '18px',
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

// ---------------------------------------------------------------------------
// Toggle component
// ---------------------------------------------------------------------------

function Toggle({ on, onChange }: { on: boolean; onChange: () => void }) {
  return (
    <button
      onClick={onChange}
      className={`w-10 h-5 rounded-full transition-colors flex-shrink-0 ${on ? '' : 'bg-border'}`}
      style={on ? { backgroundColor: 'var(--accent)' } : undefined}
    >
      <div
        className={`w-4 h-4 bg-white rounded-full transition-transform ${on ? 'translate-x-5' : 'translate-x-0.5'}`}
      />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function Settings() {
  const [activeSection, setActiveSection] = useState('General');

  // Persisted preferences
  const [defaultTarget, setDefaultTarget] = usePersisted<string>('surge:defaultTarget', '');
  const [notifications, setNotifications] = usePersisted<Record<string, boolean>>(
    'surge:notifications',
    { critical: true, exploit: true, scan: false, error: true }
  );
  const [accentColor, setAccentColor] = usePersisted<AccentId>('surge:accentColor', 'green');
  const [density,     setDensity]     = usePersisted<Density>('surge:density', 'Default');
  const [theme,       setTheme]       = usePersisted<Theme>('surge:theme', 'dark');

  // Model settings (persisted locally, synced from backend on section activate)
  const [modelMode,      setModelMode]      = usePersisted<'online' | 'offline'>('surge:modelMode', 'online');
  const [onlineModel,    setOnlineModel]    = usePersisted<string>('surge:onlineModel', 'z-ai/glm-5');
  const [offlineBaseUrl, setOfflineBaseUrl] = usePersisted<string>('surge:offlineBaseUrl', '');
  const [offlineModel,   setOfflineModel]   = usePersisted<string>('surge:offlineModel', 'gpt-oss:20b');
  const [saveStatus,     setSaveStatus]     = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [orModels,       setOrModels]       = useState<{ id: string; name: string }[]>([]);
  const [orModelsStatus, setOrModelsStatus] = useState<'idle' | 'loading' | 'error'>('idle');

  // Backend health state (not persisted)
  const [backendStatus,  setBackendStatus]  = useState<'checking' | 'ok' | 'error'>('checking');
  const [backendVersion, setBackendVersion] = useState<string | null>(null);

  // Apply accent color CSS variables whenever the selection changes
  useEffect(() => {
    const { hex, hover } = accentMap[accentColor];
    document.documentElement.style.setProperty('--accent', hex);
    document.documentElement.style.setProperty('--accent-hover', hover);
  }, [accentColor]);

  // Apply density via the --font-size CSS variable
  useEffect(() => {
    document.documentElement.style.setProperty('--font-size', densityMap[density]);
  }, [density]);

  // Apply theme class to <html> — system mode tracks matchMedia
  useEffect(() => {
    const html = document.documentElement;
    if (theme === 'light') {
      html.classList.add('light');
      return;
    }
    if (theme === 'dark') {
      html.classList.remove('light');
      return;
    }
    // system
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const apply = (e: MediaQueryListEvent | MediaQueryList) => {
      e.matches ? html.classList.add('light') : html.classList.remove('light');
    };
    apply(mq);
    mq.addEventListener('change', apply);
    return () => mq.removeEventListener('change', apply);
  }, [theme]);

  useEffect(() => {
    if (activeSection !== 'Model') return;

    fetch(`${API_URL}/settings/model`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        setModelMode(data.mode);
        setOnlineModel(data.online_model);
        setOfflineBaseUrl(data.offline_base_url);
        setOfflineModel(data.offline_model);
      })
      .catch(() => {});

    setOrModelsStatus('loading');
    fetch(`${API_URL}/settings/models`)
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) { setOrModelsStatus('error'); return; }
        setOrModels(data);
        setOrModelsStatus('idle');
      })
      .catch(() => setOrModelsStatus('error'));
  }, [activeSection]);

  useEffect(() => {
    let cancelled = false;
    setBackendStatus('checking');

    fetch(`${API_URL}/health`)
      .then((r) => r.json())
      .then((data) => {
        if (!cancelled) {
          setBackendStatus('ok');
          if (data.version) setBackendVersion(data.version as string);
        }
      })
      .catch(() => {
        if (!cancelled) setBackendStatus('error');
      });

    return () => { cancelled = true; };
  }, []);

  function recheck() {
    setBackendStatus('checking');
    setBackendVersion(null);

    fetch(`${API_URL}/health`)
      .then((r) => r.json())
      .then((data) => {
        setBackendStatus('ok');
        if (data.version) setBackendVersion(data.version as string);
      })
      .catch(() => setBackendStatus('error'));
  }

  const toggleNotification = (id: string) =>
    setNotifications({ ...notifications, [id]: !notifications[id] });

  // ------------------------------------------------------------------
  // Section renderers
  // ------------------------------------------------------------------

  const renderGeneral = () => (
    <div className="space-y-6">
      {/* Backend status */}
      <div className="p-4 bg-background rounded-lg flex items-center justify-between">
        <div>
          <div className="font-medium text-foreground mb-1">Backend Status</div>
          <p className="text-sm text-muted font-mono">{API_URL}</p>
        </div>
        <div className="flex items-center gap-3">
          {backendStatus === 'checking' && (
            <span className="flex items-center gap-1.5 text-sm text-muted">
              <Loader2 className="w-4 h-4 animate-spin" /> Checking…
            </span>
          )}
          {backendStatus === 'ok' && (
            <span className="flex items-center gap-1.5 text-sm" style={{ color: 'var(--accent)' }}>
              <Wifi className="w-4 h-4" /> Connected
            </span>
          )}
          {backendStatus === 'error' && (
            <span className="flex items-center gap-1.5 text-sm text-[#FF1744]">
              <WifiOff className="w-4 h-4" /> Unreachable
            </span>
          )}
          <button
            onClick={recheck}
            className="px-3 py-1.5 bg-surface-2 hover:bg-border border border-border text-muted hover:text-foreground text-xs rounded transition-colors"
          >
            Re-check
          </button>
        </div>
      </div>

      {/* Default scan target */}
      <div>
        <label className="block text-sm text-muted mb-2">
          Default Scan Target
          <span className="ml-2 text-xs text-[#3D4451]">pre-fills the New Scan form</span>
        </label>
        <input
          type="text"
          value={defaultTarget}
          onChange={(e) => setDefaultTarget(e.target.value)}
          placeholder="192.168.1.0/24"
          className="w-full bg-background border border-border rounded-lg px-4 py-2 text-foreground font-mono focus:outline-none focus:border-[var(--accent)] transition-colors"
        />
      </div>

      <div className="border-t border-border pt-6 mt-2">
        <h3 className="font-semibold text-foreground mb-1">Danger Zone</h3>
        <p className="text-xs text-muted mb-4">Clears all locally saved preferences.</p>
        <button
          onClick={() => {
            [
              'surge:defaultTarget', 'surge:notifications', 'surge:accentColor',
              'surge:density', 'surge:theme', 'surge:modelMode', 'surge:onlineModel',
              'surge:offlineBaseUrl', 'surge:offlineModel',
            ].forEach((k) => localStorage.removeItem(k));
            window.location.reload();
          }}
          className="px-4 py-3 bg-background hover:bg-surface-2 border border-[#FF1744]/30 text-[#FF1744] rounded-lg text-sm font-medium transition-colors"
        >
          Reset All Preferences
        </button>
      </div>
    </div>
  );

  const renderPipeline = () => (
    <div className="space-y-2">
      <div className="p-4 bg-background rounded-lg flex items-start gap-3 mb-6">
        <Info className="w-4 h-4 text-muted mt-0.5 flex-shrink-0" />
        <p className="text-sm text-muted">
          The Surge pipeline runs all stages sequentially on every scan. All stages are always active and cannot be skipped.
        </p>
      </div>

      <div className="relative">
        {pipelineStages.map((stage, i) => (
          <div key={stage.name} className="relative">
            {i < pipelineStages.length - 1 && (
              <div className="absolute left-[19px] top-full w-0.5 h-2 bg-border z-10" />
            )}
            <div className="bg-background rounded-lg p-5 flex items-start gap-4 mb-2">
              <div className="w-9 h-9 rounded-full bg-surface-2 border border-border flex items-center justify-center flex-shrink-0 text-sm font-bold text-muted">
                {i + 1}
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="font-semibold text-foreground mb-1">{stage.name}</h3>
                <p className="text-sm text-muted">{stage.description}</p>
              </div>
              <div className="flex items-center gap-1.5 px-2.5 py-1 bg-[var(--accent)]/10 rounded-full flex-shrink-0">
                <div className="w-1.5 h-1.5 rounded-full bg-[var(--accent)] animate-pulse" />
                <span className="text-xs text-[var(--accent)] font-medium">Always Active</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  const renderNotifications = () => (
    <div className="space-y-6">
      {/* Not-yet-implemented banner */}
      <div className="p-4 bg-[#FFB300]/10 border border-[#FFB300]/30 rounded-lg flex items-start gap-3">
        <Info className="w-4 h-4 text-[#FFB300] mt-0.5 flex-shrink-0" />
        <div>
          <p className="text-sm font-medium text-[#FFB300] mb-0.5">Not yet implemented</p>
          <p className="text-sm text-muted">
            Notifications are planned for a future release. The preview below shows what the feature will look like.
          </p>
        </div>
      </div>

      {/* Dimmed non-interactive preview */}
      <div className="opacity-40 pointer-events-none space-y-6">
        <div>
          <h3 className="font-semibold text-foreground mb-4">Alert Types</h3>
          <div className="space-y-3">
            {notificationTypes.map((type) => (
              <div key={type.id} className="flex items-start justify-between p-4 bg-background rounded-lg">
                <div className="flex-1 pr-4">
                  <div className="font-medium text-foreground mb-1">{type.label}</div>
                  <p className="text-sm text-muted">{type.description}</p>
                </div>
                <Toggle on={!!notifications[type.id]} onChange={() => toggleNotification(type.id)} />
              </div>
            ))}
          </div>
        </div>

        <div>
          <h3 className="font-semibold text-foreground mb-4">Notification Channels</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-4 bg-background rounded-lg">
              <span className="text-foreground">In-App</span>
              <Toggle on={true} onChange={() => {}} />
            </div>
            <div className="p-4 bg-background rounded-lg">
              <label className="block text-sm text-muted mb-2">Webhook URL</label>
              <input
                type="text"
                placeholder="https://your-webhook-url.com"
                className="w-full bg-surface-1 border border-border rounded px-3 py-2 text-foreground text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
                readOnly
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  const accentOptions: { id: AccentId; color: string }[] = [
    { id: 'green', color: '#00E676' },
    { id: 'amber', color: '#FFB300' },
    { id: 'blue',  color: '#2196F3' },
  ];

  const themeOptions: { id: Theme; label: string; preview: string }[] = [
    { id: 'dark',   label: 'Dark',   preview: 'bg-gradient-to-br from-[#13151C] to-[#0F1117]' },
    { id: 'light',  label: 'Light',  preview: 'bg-gradient-to-br from-[#F9FAFB] to-[#E5E7EB]' },
    { id: 'system', label: 'System', preview: 'bg-gradient-to-br from-[#13151C] via-[#8B949E] to-[#F1F5F9]' },
  ];

  const renderAppearance = () => (
    <div className="space-y-6">
      <div>
        <h3 className="font-semibold text-foreground mb-4">Theme</h3>
        <div className="grid grid-cols-3 gap-4">
          {themeOptions.map((t) => {
            const isSelected = theme === t.id;
            return (
              <button
                key={t.id}
                onClick={() => setTheme(t.id)}
                className="relative p-6 bg-surface-1 border-2 rounded-lg cursor-pointer transition-all hover:border-border text-left"
                style={{ borderColor: isSelected ? 'var(--accent)' : undefined }}
              >
                {isSelected && (
                  <div className="absolute top-3 right-3">
                    <div className="w-5 h-5 rounded-full flex items-center justify-center" style={{ backgroundColor: 'var(--accent)' }}>
                      <Check className="w-3 h-3 text-[#0F1117]" />
                    </div>
                  </div>
                )}
                <div className={`w-full h-20 ${t.preview} rounded mb-3`} />
                <div className="text-sm text-foreground font-medium">{t.label}</div>
              </button>
            );
          })}
        </div>
      </div>

      <div>
        <h3 className="font-semibold text-foreground mb-1">Accent Color</h3>
        <p className="text-xs text-muted mb-3">Applied to active states and highlights across the app.</p>
        <div className="flex items-center gap-3">
          {accentOptions.map((a) => (
            <button
              key={a.id}
              onClick={() => setAccentColor(a.id)}
              className={`w-12 h-12 rounded-lg transition-all ${
                accentColor === a.id ? 'ring-2 ring-offset-2 ring-offset-surface-1 scale-110' : 'hover:scale-105'
              }`}
              style={{
                backgroundColor: a.color,
                boxShadow: accentColor === a.id ? `0 0 0 2px ${a.color}` : 'none',
              }}
            >
              {accentColor === a.id && <Check className="w-5 h-5 text-[#0F1117] mx-auto" />}
            </button>
          ))}
        </div>
      </div>

      <div>
        <h3 className="font-semibold text-foreground mb-1">Density</h3>
        <p className="text-xs text-muted mb-3">Adjusts the base font size across the dashboard.</p>
        <div className="flex items-center gap-0 bg-background rounded-lg p-0.5 max-w-md">
          {(['Compact', 'Default', 'Comfortable'] as Density[]).map((d) => (
            <button
              key={d}
              onClick={() => setDensity(d)}
              className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                density === d ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      </div>
    </div>
  );

  const renderAbout = () => (
    <div className="space-y-6">
      {/* About Surge */}
      <div>
        <h3 className="font-semibold text-foreground mb-3">About Surge</h3>
        <div className="bg-background rounded-lg p-5 space-y-3">
          <p className="text-sm text-muted-foreground leading-relaxed">
            Surge is an agentic network vulnerability scanner that combines autonomous AI agents with industry-standard
            tooling to discover hosts, fingerprint services, correlate CVEs, and score risk — all from a single scan.
          </p>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Built for security teams, system administrators, and researchers who need automated vulnerability
            intelligence without stitching together disparate tools by hand.
          </p>
        </div>
      </div>

      {/* How It Works */}
      <div>
        <h3 className="font-semibold text-foreground mb-3">How It Works</h3>
        <div className="bg-background rounded-lg overflow-hidden divide-y divide-border">
          {[
            { step: '1', name: 'Reconnaissance',         desc: 'nmap discovers live hosts and open ports on the target network range.' },
            { step: '2', name: 'Enumeration',             desc: 'Service versions and banners are extracted from each open port.' },
            { step: '3', name: 'Vulnerability Analysis',  desc: 'CVEs are matched via the CIRCL CVE API and filtered by service relevance.' },
            { step: '4', name: 'Risk Assessment',         desc: 'An XGBoost ML model re-scores severity and predicts exploitability.' },
            { step: '5', name: 'Reporting',               desc: 'Structured reports are generated across Executive, Technical, and Remediation templates.' },
          ].map((s) => (
            <div key={s.step} className="flex items-start gap-4 px-5 py-4">
              <span className="text-xs font-bold text-muted mt-0.5 w-4 flex-shrink-0">{s.step}</span>
              <div>
                <div className="text-sm font-medium text-foreground mb-0.5">{s.name}</div>
                <div className="text-sm text-muted">{s.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Tech Stack */}
      <div>
        <h3 className="font-semibold text-foreground mb-3">Tech Stack</h3>
        <div className="bg-background rounded-lg overflow-hidden">
          {[
            { label: 'Frontend',      value: 'Next.js 15 / React 19' },
            { label: 'Backend',       value: 'FastAPI + LangGraph MAS' },
            { label: 'AI Framework',  value: 'LangGraph (multi-agent graph)' },
            { label: 'ML Model',      value: 'XGBoost (CVSS re-scoring)' },
            { label: 'Database',      value: 'SQLite (dev) / PostgreSQL (prod)' },
            { label: 'Scanner',       value: 'nmap + CIRCL CVE API' },
            { label: 'API URL',       value: API_URL, mono: true },
            {
              label: 'API Status',
              value: backendStatus === 'checking' ? 'Checking…' : backendStatus === 'ok' ? 'Connected' : 'Unreachable',
              color: backendStatus === 'ok' ? 'var(--accent)' : backendStatus === 'error' ? '#FF1744' : '#6B7280',
            },
            ...(backendVersion ? [{ label: 'API Version', value: backendVersion }] : []),
          ].map((row, i) => (
            <div
              key={i}
              className="flex items-center justify-between px-6 py-3 border-b border-border last:border-0"
            >
              <span className="text-sm text-muted">{row.label}</span>
              <span
                className={`text-sm ${row.mono ? 'font-mono' : 'font-medium'}`}
                style={{ color: row.color ?? 'white' }}
              >
                {row.value}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Development Team */}
      <div>
        <h3 className="font-semibold text-foreground mb-3">Development Team</h3>
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-background rounded-lg p-5">
            <div className="font-medium text-foreground mb-1">Jonathan Contreras</div>
            <div className="text-xs font-medium mb-2" style={{ color: 'var(--accent)' }}>Frontend Engineer</div>
            <p className="text-xs text-muted">
              Next.js dashboard, real-time scan UI, API integration, topology visualization, exploit queue
            </p>
          </div>
          <div className="bg-background rounded-lg p-5">
            <div className="font-medium text-foreground mb-1">Brianna</div>
            <div className="text-xs font-medium mb-2" style={{ color: 'var(--accent)' }}>Backend &amp; AI Engineer</div>
            <p className="text-xs text-muted">
              LangGraph agent pipeline, nmap integration, CVE correlation, XGBoost ML scoring
            </p>
          </div>
        </div>
        <p className="text-xs text-[#3D4451] mt-3 text-center">University Capstone Project — 2026</p>
      </div>

      {/* Requirements */}
      <div className="p-4 bg-background rounded-lg flex items-start gap-3">
        <Info className="w-4 h-4 text-muted mt-0.5 flex-shrink-0" />
        <p className="text-sm text-muted">
          Scanner backend requires <code className="text-foreground">nmap</code> to be installed and the FastAPI
          server to be running on the configured API URL.
        </p>
      </div>
    </div>
  );

  async function saveModelConfig() {
    setSaveStatus('saving');
    try {
      const res = await fetch(`${API_URL}/settings/model`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: modelMode,
          online_model: onlineModel,
          offline_base_url: offlineBaseUrl,
          offline_model: offlineModel,
        }),
      });
      if (!res.ok) throw new Error();
      setSaveStatus('saved');
      setTimeout(() => setSaveStatus('idle'), 2000);
    } catch {
      setSaveStatus('error');
      setTimeout(() => setSaveStatus('idle'), 3000);
    }
  }

  const renderModel = () => (
    <div className="space-y-6">
      <div>
        <h3 className="font-semibold text-foreground mb-3">Provider Mode</h3>
        <div className="flex items-center gap-0 bg-background rounded-lg p-0.5 max-w-sm">
          {(['offline', 'online'] as const).map((m) => (
            <button
              key={m}
              onClick={() => setModelMode(m)}
              className={`flex-1 px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                modelMode === m ? 'bg-surface-2 text-foreground' : 'text-muted hover:text-foreground'
              }`}
            >
              {m === 'offline' ? 'Offline (Ollama)' : 'Online (OpenRouter)'}
            </button>
          ))}
        </div>
      </div>

      {modelMode === 'online' && (
        <div className="bg-background rounded-lg p-5">
          <label className="block text-sm text-muted mb-2">OpenRouter Model</label>
          {orModelsStatus === 'loading' ? (
            <div className="flex items-center gap-2 text-sm text-muted">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading models…
            </div>
          ) : orModelsStatus === 'error' ? (
            <p className="text-sm text-[#FF1744]">Could not load models from OpenRouter.</p>
          ) : (
            <select
              value={onlineModel}
              onChange={(e) => setOnlineModel(e.target.value)}
              className="w-full bg-surface-1 border border-border rounded-lg px-3 py-2 text-foreground text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
            >
              {orModels.map((m) => (
                <option key={m.id} value={m.id}>{m.name}</option>
              ))}
            </select>
          )}
        </div>
      )}

      {modelMode === 'offline' && (
        <div className="bg-background rounded-lg p-5 space-y-4">
          <div>
            <label className="block text-sm text-muted mb-2">Ollama Base URL</label>
            <input
              type="text"
              value={offlineBaseUrl}
              onChange={(e) => setOfflineBaseUrl(e.target.value)}
              placeholder="http://localhost:11434/v1"
              className="w-full bg-surface-1 border border-border rounded-lg px-3 py-2 text-foreground font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
          <div>
            <label className="block text-sm text-muted mb-2">Model Name</label>
            <input
              type="text"
              value={offlineModel}
              onChange={(e) => setOfflineModel(e.target.value)}
              placeholder="gpt-oss:20b"
              className="w-full bg-surface-1 border border-border rounded-lg px-3 py-2 text-foreground font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
        </div>
      )}

      <div className="p-4 bg-background rounded-lg flex items-start gap-3">
        <Info className="w-4 h-4 text-muted mt-0.5 flex-shrink-0" />
        <p className="text-sm text-muted">
          Changes take effect on the next scan run. Config is stored in memory and resets when the backend restarts.
        </p>
      </div>

      <div className="flex justify-end">
        <button
          onClick={saveModelConfig}
          disabled={saveStatus === 'saving'}
          className={`flex items-center gap-2 px-5 py-2.5 rounded-lg text-sm font-medium transition-all ${
            saveStatus === 'saved'
              ? 'bg-[var(--accent)]/20 text-[var(--accent)] border border-[var(--accent)]/30'
              : saveStatus === 'error'
              ? 'bg-[#FF1744]/10 text-[#FF1744] border border-[#FF1744]/30'
              : 'bg-[var(--accent)] text-[#0F1117] hover:bg-[var(--accent-hover)]'
          }`}
        >
          {saveStatus === 'saving' && <Loader2 className="w-4 h-4 animate-spin" />}
          {saveStatus === 'saved' && <Check className="w-4 h-4" />}
          {saveStatus === 'saved' ? 'Saved' : saveStatus === 'error' ? 'Failed — retry' : 'Save Model Config'}
        </button>
      </div>
    </div>
  );

  const renderContent = () => {
    switch (activeSection) {
      case 'General':       return renderGeneral();
      case 'Pipeline':      return renderPipeline();
      case 'Model':         return renderModel();
      case 'Notifications': return renderNotifications();
      case 'Appearance':    return renderAppearance();
      case 'About':         return renderAbout();
      default:              return null;
    }
  };

  return (
    <div className="max-w-[1800px] mx-auto p-6">
      <div className="grid grid-cols-12 gap-6">
        {/* Sidebar */}
        <div className="col-span-3">
          <div className="bg-surface-1 rounded-lg p-4 sticky top-24">
            <h2 className="font-semibold text-foreground mb-4 px-2">Settings</h2>
            <nav className="space-y-1">
              {sections.map((section) => (
                <button
                  key={section}
                  onClick={() => setActiveSection(section)}
                  style={activeSection === section ? { borderLeftColor: 'var(--accent)' } : undefined}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                    activeSection === section
                      ? 'bg-surface-2 text-foreground border-l-2 pl-[10px]'
                      : 'text-muted hover:text-foreground hover:bg-surface-2/50'
                  }`}
                >
                  {section}
                  <ChevronRight className="w-4 h-4" />
                </button>
              ))}
            </nav>
          </div>
        </div>

        {/* Content */}
        <div className="col-span-9">
          <div className="bg-surface-1 rounded-lg p-8">
            <h2 className="text-2xl font-semibold text-foreground mb-6">{activeSection}</h2>
            {renderContent()}
          </div>
        </div>
      </div>
    </div>
  );
}
