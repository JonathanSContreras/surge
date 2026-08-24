# Surge Integration Architecture Report

## 1. Repo Findings

### Agent Repo (`surge-ai`)

**Top-level structure:**
```
surge-ai/
├── main.py                  ← CLI entry point
├── core/
│   ├── state.py             ← AgentState TypedDict (the shared graph state)
│   ├── orchestration.py     ← execute_workflow() — creates run_dir, calls runner
│   ├── llm.py               ← LLM factory (2 tiers: local Ollama + OpenRouter)
│   └── cve.py               ← CVEEntry TypedDict
├── workflow/
│   ├── graph.py             ← build_mas_graph() — LangGraph StateGraph definition
│   └── runner.py            ← run_workflow() — calls graph.invoke(initial_state)
├── agents/
│   ├── recon_agent.py       ← Main recon loop (nmap via LLM decisions)
│   ├── recon_analysis.py    ← LLM summarizes recon output
│   ├── os_fingerprint_agent.py ← nmap OS detection, batched
│   ├── os_analysis.py       ← LLM summarizes OS landscape
│   ├── vuln_agent.py        ← CVE lookup via CIRCL API + LLM normalization
│   ├── data_formatting_agent.py ← LLM normalizes to CVEEntry schema for XGBoost
│   ├── cvss_scoring.py      ← XGBoost regressor → predicted_score + dashboard_data.json
│   ├── reporter.py          ← LLM writes final_report.md
│   ├── dashboard_payload.py ← Builds dashboard_data.json from XML + vuln scoring
│   └── prompts.py           ← System prompts for each agent
├── execution/
│   ├── nmap_scanner.py      ← @tool nmap_scanning (subprocess, sanitized flags)
│   ├── xml_parser.py        ← xml_parse() → structured dict keyed by IP
│   ├── address_grab.py      ← ARP sweep, gateway detect, derives initial targets
│   ├── cve_search.py        ← CIRCL CVE lookup
│   └── cvss_regessor_model.py ← XGBoost inference
├── governance/
│   └── sanitization.py      ← Validates nmap flags against tier allowlists
├── config/
│   ├── constants.py         ← Model config, scan convergence limits, paths
│   └── logging_config.py    ← File logger setup
├── model/
│   ├── xgb_regressor.json   ← Trained XGBoost model
│   ├── ohe_encoder.pkl      ← One-hot encoder for categorical features
│   └── tfidf_encoder.pkl    ← TF-IDF for text features
├── report/                  ← Run output dirs (timestamped)
│   └── 2026-02-25_18-46-14_hcu_fully_online/
│       ├── dashboard_data.json
│       ├── final_report.md
│       ├── final_state_result.json
│       └── ...
├── scan_results/            ← Raw nmap XML files (timestamped)
├── log/
│   ├── surge_log.log        ← Structured app log
│   └── scan_dumps.txt       ← Raw LLM decisions + scan output dump
└── requirements.txt
```

**Execution model:** `main.py` calls `execute_workflow(scan_type, targets)` → `run_workflow(initial_state)` → `graph.invoke(initial_state)`. This is **fully synchronous and blocking**. The LangGraph graph runs to completion and returns the final state as a dict. There is no streaming, no background threads, no HTTP server.

**LangGraph graph topology** (`workflow/graph.py`):
```
recon ──┬─→ recon_analyzer ─→ os_analyzer ─→ vulnerability ─→ cvss_data_formatter ─→ cvss_scoring ─→ reporter → END
        └─→ os_finder      ─────────────────↗
```
`recon` fans out to `recon_analyzer` and `os_finder` in parallel, then both feed `os_analyzer`. The remaining nodes are strictly sequential.

**Data agents produce** (key output shapes):

`AgentState` at completion:
```python
{
  "scan_type": "low"/"medium"/"high",
  "targets": ["10.10.160.0/24"],
  "run_dir": "./report/2026-02-25_...",
  "recon_results": {
    "discovered_hosts": ["10.10.163.109", ...],  # list of IPs
    "parsed_network": { "10.10.163.109": { ... } },  # xml_parse output
    "all_logs": [{ "timestamp", "command", "xml_dir", "xml_file", "success" }]
  },
  "os_fingerprint_results": {
    "10.10.163.109": {
      "os_matches": [{"name": "...", "accuracy": 91}],
      "cpe": ["cpe:/o:linux:linux_kernel:4.4"],
      "device_type": "general purpose",
      "vendor": "Linux"
    }
  },
  "vuln_raw_results": [
    { "host": "10.10.163.109", "product": "...", "cve_id": "CVE-...",
      "cvss_score": 7.5, "severity": "High", "summary": "...",
      "exploitable": true, "remediation": "..." }
  ],
  "vuln_normalized_results": [
    { "cve_id": "...", "cvss": 7.5, "cwe_code": 89, "cwe_name": "...",
      "access_authentication": "NONE", "access_complexity": "LOW",
      "access_vector": "NETWORK", "impact_availability": "PARTIAL",
      "impact_confidentiality": "PARTIAL", "impact_integrity": "PARTIAL",
      "product": "...", "version": "...", "host": "10.10.163.109" }
  ],
  "vuln_scoring": [
    { ...CVEEntry fields..., "predicted_score": 7.32 }
  ],
  "network_findings": "# Network Security Assessment Report\n..."  # markdown
}
```

`dashboard_data.json` (written by `cvss_scoring.py`):
```json
[{
  "id": "1", "ip": "10.10.163.109",
  "severity": "low", "description": "Unknown device",
  "deviceType": "idk", "hostname": "idk",
  "cvss": 0.0, "cve": "none",
  "vulnerability_description": "none", "status": "up"
}]
```

Note: `deviceType` and `hostname` are hardcoded as `"idk"` in the real run output from `dashboard_payload.py:101-102`. This is a known gap.

**Existing API surface:** None. No FastAPI, no Flask, no HTTP server of any kind.

**No database usage.** All persistence is flat files: timestamped `report/` directories, raw `scan_results/` XML files, log files.

**Environment variables** (`.env`):
```
TAILSCALE_URL=http://100.92.185.108:11435/v1
OPENROUTER_API_KEY=sk-or-v1-...
USE_ONLINE=1
```

**LLM configuration** (`config/constants.py`):
- Fast tier: `gpt-oss:20b` via Tailscale/Ollama (local, for recon decisions and formatting)
- Analysis tier: `z-ai/glm-5` via OpenRouter (for heavy reasoning: vuln analysis, OS analysis, report generation)

**Complications for adding a FastAPI layer:**
- `graph.invoke()` is blocking and can run for hours (`RECON_CONVERGENCE` allows 2-hour budget + up to 10 iterations). FastAPI cannot run it in a request thread. Needs `asyncio` + background task or `ProcessPoolExecutor`.
- `build_initial_target_lists()` in `execution/address_grab.py` auto-detects the local network via ARP/Scapy. On the server this must be replaced with explicit target input from the API request.
- All file paths in `config/constants.py` are relative (`./report/`, `./log/`, `./scan_results/`). FastAPI must run with a fixed CWD or paths need to be made absolute/configurable.
- LangGraph's `graph.stream()` yields node-by-node events and **is** available — this is the streaming hook for WebSocket output, but requires migrating from `graph.invoke()` to `graph.astream()`.

---

### Dashboard Repo (`web-page`)

**Top-level structure:**
```
web-page/
├── src/app/
│   ├── page.tsx              ← Root app, tab navigation (not App Router routes)
│   ├── layout.tsx
│   ├── globals.css
│   ├── _pages/
│   │   ├── Dashboard.tsx     ← Network graph + device list + activity + stats
│   │   ├── Scans.tsx         ← Scan launcher + history table
│   │   ├── Exploits.tsx      ← CVE queue + exploit detail + log
│   │   ├── Reports.tsx       ← Template picker + report preview + schedules
│   │   ├── Topology.tsx      ← Network topology view
│   │   └── Settings.tsx
│   └── _components/
│       ├── Navbar.tsx
│       ├── DeviceList.tsx
│       ├── NetworkGraphForce.tsx  ← D3-force simulation
│       ├── ActivityFeed.tsx
│       ├── StatCards.tsx
│       ├── VulnerabilityChart.tsx
│       ├── ExploitQueue.tsx
│       ├── types/
│       │   └── network-topology.ts  ← NetworkDevice, NetworkConnection, NetworkTopology types
│       ├── data/
│       │   ├── sample-topology.ts   ← Hardcoded mock topology
│       │   ├── rawData.json
│       │   └── raw-scan-parser.ts
│       └── utils/
│           ├── force-layout.ts
│           └── device-icons.tsx
├── package.json
├── next.config.ts
└── tsconfig.json
```

**App Router usage:** The app is a SPA with a single route (`page.tsx`). All "pages" are tab-switched React components. There are **no Next.js App Router API routes** (`app/api/`) and no `pages/api/` routes. Zero server-side code.

**How data is currently fetched:** All data is **100% hardcoded inline** in component files (`Scans.tsx`, `Exploits.tsx`, etc.) or imported from static files (`sample-topology.ts`). There are no `fetch()` calls, no `useEffect` data fetching hooks, no SWR/React Query, no WebSocket connections anywhere in the codebase.

**Existing TypeScript types relevant to integration:**
```typescript
// network-topology.ts
interface NetworkDevice {
  id: string; ip: string; severity: Severity;
  deviceType: DeviceType; hostname?: string; cvss?: number;
  status?: 'online' | 'offline' | 'scanning';
}

// inline in Scans.tsx
interface Scan {
  id: string; targetRange: string; type: 'Quick'|'Deep'|'Stealth';
  status: 'Running'|'Completed'|'Failed';
  devicesFound: number; vulnerabilities: number; duration: string; progress?: number;
}

// inline in Exploits.tsx
interface Vulnerability {
  id: string; cveId: string; device: {ip: string; hostname: string};
  cvss: number; exploitAvailability: 'Public'|'Private'|'None';
  status: 'Queued'|'In Progress'|'Exploited'|'Patched';
  description: string; affectedSoftware: string; mitreAttack: string; exploitNotes: string;
}
```

**No WebSocket or SSE** anywhere in the codebase.

**Dependencies:**
- `next@16.1.6`, `react@19.2.4`, `typescript@^5`, `tailwindcss@^4`
- `d3-force` — network graph physics
- `lucide-react` — icons
- `motion@^12` — animations
- `vitest` — testing (one layout test exists)
- No `socket.io-client`, no `ws`, no `axios`, no `swr`, no `react-query`

**Complications for consuming a Python API:**
- Currently a pure SPA with no fetch infrastructure at all — every page needs fetch logic added from scratch.
- No `.env` file for the API base URL — needs to be added.
- CORS must be configured on the FastAPI side to allow `localhost:3000`.
- The `NetworkGraphForce` component imports `sampleTopology` directly from `data/sample-topology.ts` — needs to be replaced with a state-managed data source.
- `sample-topology.ts` is very large (commented-out legacy data) and its active export is a parser path, not a static object — the file needs a rewrite to pull from the API.

---

## 2. Integration Points

### Data shapes that cross the boundary

| Dashboard Needs | Agent Produces | Gap |
|---|---|---|
| `scan_id` (string like "SCN-2847") | `run_dir` timestamp string | Format mismatch — need to generate/track a clean scan ID |
| `status: "running"\|"completed"\|"failed"` | No status tracking — graph either runs or errors | Need a scan job table in DB |
| `devicesFound: number` | `len(recon_results.discovered_hosts)` | Straightforward |
| `vulnerabilities: number` | `len(vuln_raw_results)` | Straightforward |
| `duration: string` | Start/end timestamps not persisted | Need to record in DB |
| `progress: number` (0–100) | No concept — blocking call | Can approximate via LangGraph node events (8 nodes) |
| `hostname` | `hostnames: list[str]` from xml_parse | Take `hostnames[0]` if available |
| `deviceType` | `os_info.device_type` from OS fingerprint | Map nmap device_type strings to dashboard enum |
| `cvss` | `predicted_score` from XGBoost | Direct |
| `exploitAvailability: "Public"\|"Private"` | `exploitable: bool` | CUT or simplify — agent has no exploit DB lookup |
| `mitreAttack` | Nothing | CUT — would require a full MITRE ATT&CK mapping table |
| `exploitNotes / exploitation_steps` | Nothing | CUT — no exploit agent exists |
| `exploit_success_rate` | Nothing | CUT — no exploit agent exists |
| Activity feed events | `surge_log.log` entries | Tail log file and parse, or emit LangGraph events |
| Report sections (executive_summary, scope, etc.) | `final_report.md` (monolithic markdown) | Parse markdown sections by `##` headings |
| `vulnerability_trends` (day-by-day counts) | No historical tracking | DEFER — needs multiple scan runs stored in DB |

### Naming mismatches

| Dashboard | Agent | Fix |
|---|---|---|
| `scan_type: "quick"\|"deep"\|"stealth"` | `scan_type: "low"\|"medium"\|"high"` | Map on API entry: quick→low, deep→high, stealth→medium |
| `agent_mode: "manual"\|"autonomous"` | No concept — always autonomous | Accept field, ignore for now |
| `cvss` (float, dashboard display) | `predicted_score` (XGBoost output) vs `cvss` (raw from CVE data) | Use `predicted_score` as the authoritative score |
| `affected_device_ip` / `affected_device_hostname` | `host` (IP only) | Map IP; hostname from parsed_network |

### The biggest structural seam

`workflow/runner.py:21` → `graph.invoke(initial_state)` is the single call that runs everything. **This is the primary integration point.** It needs to become:
1. A background task (not a blocking request handler)
2. Streaming-capable (using `graph.stream()` instead of `graph.invoke()`)
3. State-tracked in a database

### Shared concepts currently without formal definition

- **Scan job** — needs a `scan_id`, `status`, timestamps, `target`, `scan_type`, result references
- **Agent node event** — LangGraph emits events per node; needs a schema for WebSocket messages
- **Severity scale** — agent uses "Critical/High/Medium/Low" as strings; dashboard uses lowercase enum `Severity = 'low'|'medium'|'high'|'critical'`; the XGBoost `predicted_score` float needs a canonical mapping to this enum

---

## 3. Option 1 — Two Independent Repos: External API Bridge

### What FastAPI routes to add to `surge-ai`

Add a new top-level module `api/` to the agent repo:

```
surge-ai/
├── api/
│   ├── __init__.py
│   ├── main.py          ← FastAPI app, CORS, lifespan
│   ├── routes/
│   │   ├── scans.py     ← POST/GET /scans, WebSocket /ws/scans/{scan_id}
│   │   ├── devices.py   ← GET /devices
│   │   ├── vulns.py     ← GET /vulnerabilities
│   │   ├── reports.py   ← GET/POST /reports/*
│   │   ├── dashboard.py ← GET /dashboard/stats, /activity-feed
│   │   └── agents.py    ← GET /agents/status
│   ├── models.py        ← Pydantic request/response schemas
│   └── db.py            ← SQLAlchemy setup + scan job table
└── requirements-api.txt ← FastAPI, uvicorn, asyncpg, sqlalchemy
```

**Specific routes, grounded in what exists:**

```python
# POST /scans
# Body: { target: str, scan_type: "quick"|"deep"|"stealth", agent_mode: "manual"|"autonomous" }
# Maps: quick→"low", deep→"high", stealth→"medium"
# Action: INSERT scan_job into DB (status="running"), run graph.stream() in background thread
# Returns: { scan_id: str, status: "running" }

# GET /scans
# Reads from scan_jobs DB table
# Returns: [{ scan_id, target_range, type, status, devices_count, created_at, duration_s }]

# GET /agents/status
# Check how many scans have status="running" in DB
# Returns: { active_count: int }

# GET /scan-profiles
# Hardcoded or DB-stored profiles (same as dashboard mock)

# WebSocket /ws/scans/{scan_id}
# Uses graph.stream() events — each node completion emits an event
# Event schema: { progress: int, elapsed_seconds: float, events: [{node, message, timestamp}] }
# Node-to-progress mapping: recon=10%, recon_analyzer=25%, os_finder=30%, os_analyzer=45%,
#   vulnerability=65%, cvss_data_formatter=75%, cvss_scoring=85%, reporter=95%, done=100%

# GET /devices
# Reads dashboard_data.json from the latest completed run_dir
# Maps agent fields: deviceType "idk" → "unknown", hostname "idk" → null
# Returns: [{ ip, hostname, cvss_score, status, subnet, severity }]

# GET /vulnerabilities
# Reads vuln_raw_results from final_state_result.json of latest completed run
# Maps agent output to dashboard schema:
#   cve_id = cve_id, affected_device_ip = host,
#   cvss_score = cvss_score, description = summary,
#   affected_software = f"{product} {version}",
#   exploit_availability = "public" if exploitable else "none"  (simplified)
# Returns list of vulnerability objects

# GET /dashboard/stats
# Reads from DB + latest run:
#   devices_scanned = len(discovered_hosts) from latest run
#   vulnerabilities_found = len(vuln_raw_results)
#   avg_cvss = mean of predicted_scores
#   exploit_success_rate → OMIT (no exploit agent)

# GET /activity-feed
# Tail ./log/surge_log.log, parse lines by format:
#   "%(asctime)s [%(levelname)s] %(name)s/%(funcName)s >> %(message)s"
# Map levelname to event_type: ERROR→"critical", WARNING→"warning", INFO→"info"
# Return last N entries: [{ event_type, message, timestamp, ip? }]

# GET /reports/templates
# Return hardcoded list matching Reports.tsx templates array:
# [{ id: "executive", name: "Executive Summary", description: "..." }, ...]

# POST /reports/generate
# Body: { template_id: str, scan_id: str }
# Reads final_report.md from the run_dir for scan_id
# Parses markdown by ## headings into sections dict
# Stores in DB as generated report
# Returns: { id: str, status: "ready" }

# GET /reports/{id}
# Returns structured report:
# { id, scan_id, template_id, created_at,
#   sections: { executive_summary, scope, methodology, key_findings,
#               risk_matrix: { critical, high, medium, low }, recommendations } }
```

**Note:** The Exploits page routes (`POST /exploits/{cve_id}/run`, `WebSocket /ws/exploits/{cve_id}`) should **not** be built. There is no exploit agent. The Exploits page should be cut to a read-only CVE list — see the capability gap table in §2.

### WebSocket streaming strategy

LangGraph's `graph.stream()` (vs `graph.invoke()`) yields a dict per completed node:

```python
async def stream_scan(scan_id: str, initial_state: dict, websocket: WebSocket):
    graph = build_mas_graph()
    node_progress = {
        "recon": 15, "recon_analyzer": 30, "os_finder": 30,
        "os_analyzer": 45, "vulnerability": 65,
        "cvss_data_formatter": 75, "cvss_scoring": 85, "reporter": 100
    }
    start = time.time()
    async for event in graph.astream(initial_state):  # use async variant
        node_name = list(event.keys())[0]
        await websocket.send_json({
            "progress": node_progress.get(node_name, 0),
            "elapsed_seconds": round(time.time() - start, 1),
            "events": [{ "node": node_name, "message": f"{node_name} completed",
                          "timestamp": datetime.now().isoformat() }]
        })
```

This requires `langgraph>=0.2.0` (already in `requirements.txt`) and using `graph.astream()` with `asyncio`. The key change to `workflow/runner.py` is replacing `graph.invoke()` with `graph.astream()` in the API path. The CLI path in `main.py` can stay as-is.

### Dashboard changes required

1. Add `.env.local`:
   ```
   NEXT_PUBLIC_API_URL=http://localhost:8000
   NEXT_PUBLIC_WS_URL=ws://localhost:8000
   ```

2. Add a `lib/api.ts` fetch client — one file, all fetch calls go here.

3. Replace inline mock data in each page component with `useEffect` + `useState` + `fetch`:
   - `Scans.tsx`: replace `const scans = [...]` with state + fetch from `GET /scans`
   - `Dashboard.tsx`: fetch `/devices`, `/dashboard/stats`, `/activity-feed`
   - `Exploits.tsx`: fetch `/vulnerabilities`; remove "Run Exploit" button and log panel
   - `Reports.tsx`: fetch `/reports/templates` and `/reports/{id}`

4. Add WebSocket hook for scan progress in `Scans.tsx`:
   ```typescript
   useEffect(() => {
     if (!activeScanId) return;
     const ws = new WebSocket(`${process.env.NEXT_PUBLIC_WS_URL}/ws/scans/${activeScanId}`);
     ws.onmessage = (e) => setScanProgress(JSON.parse(e.data));
     return () => ws.close();
   }, [activeScanId]);
   ```

5. Replace `sampleTopology` import in `Dashboard.tsx` and `Topology.tsx` with fetched `/devices` data mapped to `NetworkTopology` shape.

### What would break or need changing

**Agent repo:**
- `main.py` CLI entry point: not broken, stays as-is for local testing
- `config/constants.py` file paths: must be relative to the agent repo root when running as a service (set `WorkingDirectory` in systemd service file)
- `agents/dashboard_payload.py`: `deviceType` and `hostname` are `"idk"` — not broken but produces poor dashboard data; needs to pull from `os_fingerprint_results` and `parsed_network`
- `workflow/runner.py`: needs an async variant for API use; the sync version stays for CLI

**Dashboard repo:**
- Every page component: mock data arrays must be replaced with fetch calls — significant but mechanical work
- `_components/data/sample-topology.ts`: replace hardcoded export with API-fetched `NetworkTopology`
- `NetworkGraphForce.tsx`: currently takes `topology` prop from `sampleTopology` — change prop source, not the component itself
- `Exploits.tsx`: remove "Run Exploit" button, exploitation log panel, and `mitreAttack` display

### Deployment on university server

**Two systemd services:**

`/etc/systemd/system/surge-api.service`:
```ini
[Unit]
Description=Surge Agent API
After=network.target postgresql.service

[Service]
User=surge
WorkingDirectory=/opt/surge/surge-ai
ExecStart=/opt/surge/surge-ai/.venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 1
EnvironmentFile=/opt/surge/surge-ai/.env
Restart=always
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/surge-dashboard.service`:
```ini
[Unit]
Description=Surge Dashboard
After=network.target surge-api.service

[Service]
User=surge
WorkingDirectory=/opt/surge/web-page
ExecStart=/usr/bin/node .next/standalone/server.js
Environment="PORT=3000"
Environment="NEXT_PUBLIC_API_URL=http://localhost:8000"
Environment="NEXT_PUBLIC_WS_URL=ws://localhost:8000"
Restart=always

[Install]
WantedBy=multi-user.target
```

Single uvicorn worker — scans are stateful; multi-worker would break scan job tracking without Redis.

**Or with Docker:**
```yaml
# docker-compose.yml
services:
  db:
    image: postgres:16
    volumes: [pg_data:/var/lib/postgresql/data]
    environment:
      POSTGRES_DB: surge
      POSTGRES_PASSWORD: ${DB_PASSWORD}

  agent-api:
    build: ./surge-ai
    ports: ["8000:8000"]
    depends_on: [db]
    environment:
      DATABASE_URL: postgresql://postgres:${DB_PASSWORD}@db:5432/surge
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
    volumes:
      - ./surge-ai/report:/app/report
      - ./surge-ai/scan_results:/app/scan_results
      - ./surge-ai/log:/app/log
      - ./surge-ai/model:/app/model
    cap_add: [NET_RAW, NET_ADMIN]  # nmap requires raw socket access

  dashboard:
    build: ./web-page
    ports: ["3000:3000"]
    environment:
      NEXT_PUBLIC_API_URL: http://agent-api:8000
    depends_on: [agent-api]

volumes:
  pg_data:
```

The `cap_add: NET_RAW` is critical — nmap requires raw socket privileges to run SYN scans.

### Main risks

1. **The blocking graph.invoke problem**: Converting to `graph.astream()` with asyncio is not trivial. If the async migration is botched, scans will block the FastAPI event loop and no other requests will be served. Use `run_in_executor` as a safe fallback while the async migration is in progress.
2. **`deviceType`/`hostname` are "idk"**: The real run output (`report/2026-02-25_18-46-14_hcu_fully_online/dashboard_data.json`) confirms this. The dashboard device list will show "idk" everywhere unless `dashboard_payload.py` is fixed to read from `os_fingerprint_results` and `recon_results.parsed_network`.
3. **Run time**: A full high-scan can take 2 hours per `RECON_CONVERGENCE` settings in `config/constants.py`. The WebSocket client needs to handle multi-hour connections or implement polling as a fallback.
4. **CORS**: FastAPI must explicitly allow `http://localhost:3000` (and the production domain). Add `CORSMiddleware` to `api/main.py`.
5. **nmap requires root/CAP_NET_RAW**: The systemd service or Docker container must run with elevated network privileges for `-sS` SYN scans.

---

## 4. Option 2 — Monorepo: Internal API with Shared Types

### Proposed directory structure

```
surge-monorepo/
├── apps/
│   ├── agent/              ← surge-ai (renamed)
│   │   ├── api/            ← new FastAPI layer (same as Option 1)
│   │   ├── agents/
│   │   ├── core/
│   │   ├── workflow/
│   │   ├── execution/
│   │   ├── config/
│   │   ├── governance/
│   │   ├── utils/
│   │   ├── main.py
│   │   └── requirements.txt
│   └── dashboard/          ← web-page (renamed)
│       ├── src/app/
│       ├── package.json
│       └── ...
├── packages/
│   └── shared-types/
│       ├── python/
│       │   └── surge_types.py    ← Pydantic models
│       └── typescript/
│           └── index.ts          ← TypeScript interfaces
├── docker-compose.yml
├── .gitignore
└── README.md
```

### Migration steps

1. Create new `surge-monorepo` git repo.
2. Use `git subtree add` to import both repos with their full history:
   ```bash
   git subtree add --prefix=apps/agent ../surge-ai main
   git subtree add --prefix=apps/dashboard ../web-page main
   ```
3. Create `packages/shared-types/` with the shared type package.
4. Update import paths — the agent imports from relative paths (`from core.state import AgentState`) which still work unchanged since it's self-contained. The dashboard's `tsconfig.json` would add a path alias to `../../packages/shared-types/typescript`.
5. Add root `docker-compose.yml` and `.env`.

**Git history concern**: `git subtree add` preserves both repos' commit histories. The downside is the monorepo's initial commit will be large and the combined `git log` is complex. For a one-month capstone this is acceptable.

### The shared types package

**Python (`packages/shared-types/python/surge_types.py`):**
```python
from pydantic import BaseModel
from typing import Literal, Optional

class ScanRequest(BaseModel):
    target: str
    scan_type: Literal["quick", "deep", "stealth"]
    agent_mode: Literal["manual", "autonomous"] = "autonomous"

class ScanRecord(BaseModel):
    scan_id: str
    target_range: str
    type: Literal["quick", "deep", "stealth"]
    status: Literal["running", "completed", "failed"]
    devices_count: int
    created_at: str
    duration_s: Optional[float]

class DeviceRecord(BaseModel):
    ip: str
    hostname: Optional[str]
    cvss_score: float
    status: Literal["online", "offline", "scanning"]
    severity: Literal["low", "medium", "high", "critical"]
    subnet: str

class VulnRecord(BaseModel):
    cve_id: str
    affected_device_ip: str
    affected_device_hostname: Optional[str]
    cvss_score: float
    exploit_availability: Literal["public", "private", "none"]
    status: Literal["queued", "in_progress", "exploited", "patched"]
    description: str
    affected_software: str

class AgentEvent(BaseModel):
    node: str
    message: str
    timestamp: str

class ScanProgressEvent(BaseModel):
    progress: int
    elapsed_seconds: float
    events: list[AgentEvent]
```

**TypeScript (`packages/shared-types/typescript/index.ts`):**
```typescript
export type ScanType = 'quick' | 'deep' | 'stealth';
export type ScanStatus = 'running' | 'completed' | 'failed';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type ExploitAvailability = 'public' | 'private' | 'none';

export interface ScanRecord {
  scan_id: string; target_range: string; type: ScanType;
  status: ScanStatus; devices_count: number; duration_s: number | null;
}
export interface DeviceRecord {
  ip: string; hostname: string | null; cvss_score: number;
  status: 'online' | 'offline' | 'scanning'; severity: Severity; subnet: string;
}
export interface VulnRecord {
  cve_id: string; affected_device_ip: string; affected_device_hostname: string | null;
  cvss_score: number; exploit_availability: ExploitAvailability;
  status: 'queued' | 'in_progress' | 'exploited' | 'patched';
  description: string; affected_software: string;
}
export interface ScanProgressEvent {
  progress: number; elapsed_seconds: number;
  events: { node: string; message: string; timestamp: string; }[];
}
```

### What Brianna (agent dev) changes vs Jonathan (dashboard dev)

**Brianna:**
- Add `apps/agent/api/` module (FastAPI layer) — same work as Option 1
- Fix `dashboard_payload.py` `deviceType`/`hostname` fields to use `os_fingerprint_results` and `parsed_network`
- Add `asyncio`-compatible scan runner (`graph.astream()`)
- Update `requirements.txt` to add FastAPI, uvicorn, asyncpg, SQLAlchemy

**Jonathan:**
- Replace hardcoded mock data in all page components with fetch hooks
- Add `.env.local` with API URL
- Import from `packages/shared-types/typescript` for type safety (instead of per-file inline interfaces)
- Wire up WebSocket in `Scans.tsx`
- Remove "Run Exploit", "Exploit Log", and `mitreAttack` display from `Exploits.tsx`
- Fix `VulnerabilityChart.tsx` to receive daily severity counts from API

### Docker Compose for monorepo

```yaml
# surge-monorepo/docker-compose.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: surge
      POSTGRES_USER: surge
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    volumes: [pg_data:/var/lib/postgresql/data]
    ports: ["5432:5432"]

  agent-api:
    build:
      context: ./apps/agent
      dockerfile: Dockerfile
    ports: ["8000:8000"]
    depends_on: [db]
    environment:
      DATABASE_URL: postgresql+asyncpg://surge:${DB_PASSWORD}@db:5432/surge
      OPENROUTER_API_KEY: ${OPENROUTER_API_KEY}
      TAILSCALE_URL: ${TAILSCALE_URL}
    volumes:
      - ./apps/agent/report:/app/report
      - ./apps/agent/scan_results:/app/scan_results
      - ./apps/agent/log:/app/log
      - ./apps/agent/model:/app/model
    cap_add: [NET_RAW, NET_ADMIN]
    network_mode: host  # nmap needs host networking for ARP scans

  dashboard:
    build:
      context: ./apps/dashboard
      dockerfile: Dockerfile
      args:
        NEXT_PUBLIC_API_URL: http://localhost:8000
        NEXT_PUBLIC_WS_URL: ws://localhost:8000
    ports: ["3000:3000"]
    depends_on: [agent-api]

volumes:
  pg_data:
```

### Main risks (Option 2)

1. **Monorepo setup time is non-zero**. Setting up `git subtree`, configuring the shared types package, updating TypeScript path aliases, and wiring Docker Compose takes 1–2 days minimum. With one month left, this is significant.
2. **Python and TypeScript cannot actually share code** — Pydantic models and TypeScript interfaces must be maintained in sync by hand. There is no code generation, no validation sharing. The "shared types" package is largely cosmetic.
3. **Both repos already have clean git histories** worth preserving separately for the capstone presentation. Merging them into a subtree makes individual contribution history harder to attribute.
4. **The `network_mode: host` requirement for nmap** conflicts with Docker networking defaults and may require running the agent container outside Docker entirely on the university server.

---

## 5. Recommendation

**Go with Option 1: Two Independent Repos with a FastAPI Bridge.**

Here's why, grounded specifically in what the code shows:

**The repos don't share runtime or language.** True code sharing in a monorepo means a shared library both services import. Python and TypeScript cannot import the same file. The "shared types" in Option 2 are two separate files you maintain in sync by hand — you get none of the DRY benefit that justifies monorepo complexity.

**The agent repo is already well-organized.** `surge-ai` has clean module boundaries: `core/`, `agents/`, `execution/`, `workflow/`. Adding an `api/` directory is purely additive and doesn't disturb anything Brianna is currently building in those modules.

**The dashboard has zero fetch infrastructure** — both options require the same amount of work on the Next.js side. Option 1 vs Option 2 makes no difference for Jonathan's workload.

**The single most important file to change** is `workflow/runner.py:21` (`graph.invoke()` → `graph.astream()`). This is true regardless of which option you pick. Option 1 scopes that change to one repo; Option 2 doesn't make it easier.

**With one month left, prioritize a working vertical slice** over architectural elegance. A smaller surface area that actually works is far better than a full monorepo that's half-configured.

### Recommended build order

**Week 1 — Brianna:**
- Add `api/main.py` with FastAPI + PostgreSQL
- Implement `POST /scans` (background task, sync `graph.invoke()` first — streaming comes later), `GET /scans`, `GET /devices`, `GET /dashboard/stats`, `GET /vulnerabilities`
- Fix `dashboard_payload.py` to populate `hostname` from `hostnames[0]` and `deviceType` from `os_info.device_type`

**Week 1 — Jonathan:**
- Add `.env.local`, create `lib/api.ts`
- Wire `Dashboard.tsx` and `Scans.tsx` to real data
- Cut the Exploits page to a read-only CVE list
- Remove all mock data

**Week 2 — Both:**
- WebSocket streaming for scan progress (`graph.astream()`)
- Connect `Topology.tsx` and `NetworkGraphForce` to live device data

**Week 3:**
- Report generation from `final_report.md`
- Activity feed from log file
- Polish

**Week 4:**
- Deployment on university server
- Integration testing end-to-end

---

## 6. Proposed PostgreSQL Schema

Based on the actual data shapes the agent produces:

```sql
-- Track scan jobs (maps to agent run_dirs)
CREATE TABLE scans (
    scan_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_range    TEXT NOT NULL,          -- e.g. "10.10.160.0/24"
    scan_type       TEXT NOT NULL           -- "quick", "deep", "stealth" (dashboard names)
                    CHECK (scan_type IN ('quick', 'deep', 'stealth')),
    agent_scan_type TEXT NOT NULL           -- "low", "medium", "high" (agent names)
                    CHECK (agent_scan_type IN ('low', 'medium', 'high')),
    agent_mode      TEXT NOT NULL DEFAULT 'autonomous',
    status          TEXT NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'completed', 'failed')),
    run_dir         TEXT,                   -- e.g. "./report/2026-02-25_18-46-14_..."
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    duration_s      FLOAT,
    error_message   TEXT,
    -- Aggregate stats (populated when completed)
    devices_count   INT DEFAULT 0,
    vulns_count     INT DEFAULT 0,
    avg_cvss        FLOAT
);

-- Devices discovered in a scan (from dashboard_data.json + xml_parse output)
CREATE TABLE devices (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip              INET NOT NULL,
    hostname        TEXT,                   -- from xml_parse hostnames[0], nullable
    mac_address     TEXT,
    mac_vendor      TEXT,
    device_type     TEXT,                   -- from os_info.device_type
    os_name         TEXT,                   -- from os_info.name
    os_accuracy     INT,
    description     TEXT,                   -- synthesized description from xml_parser
    status          TEXT DEFAULT 'online'
                    CHECK (status IN ('online', 'offline', 'scanning')),
    severity        TEXT DEFAULT 'low'
                    CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    cvss_score      FLOAT DEFAULT 0.0,      -- predicted_score from XGBoost
    subnet          TEXT,                   -- derived from IP + prefix
    raw_os_json     JSONB,                  -- full os_info dict for future use
    raw_services_json JSONB,                -- full services list from xml_parse
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_devices_scan_id ON devices(scan_id);
CREATE INDEX idx_devices_ip ON devices(ip);

-- Vulnerabilities found (from vuln_raw_results + vuln_scoring)
CREATE TABLE vulnerabilities (
    id                      BIGSERIAL PRIMARY KEY,
    scan_id                 UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    device_id               BIGINT REFERENCES devices(id) ON DELETE SET NULL,
    cve_id                  TEXT NOT NULL,          -- e.g. "CVE-2021-44228"
    affected_device_ip      INET NOT NULL,
    affected_device_hostname TEXT,
    product                 TEXT,
    version                 TEXT,
    cvss_score_raw          FLOAT,                  -- from CVE data (CIRCL)
    cvss_score_predicted    FLOAT,                  -- from XGBoost regressor
    severity                TEXT
                            CHECK (severity IN ('low', 'medium', 'high', 'critical', 'unknown')),
    summary                 TEXT,                   -- LLM-written one-liner
    exploitable             BOOLEAN,                -- LLM assessment
    remediation             TEXT,
    exploit_availability    TEXT DEFAULT 'none'
                            CHECK (exploit_availability IN ('public', 'private', 'none')),
    status                  TEXT DEFAULT 'queued'
                            CHECK (status IN ('queued', 'in_progress', 'exploited', 'patched')),
    -- XGBoost input features (for auditability)
    access_authentication   TEXT,
    access_complexity       TEXT,
    access_vector           TEXT,
    impact_availability     TEXT,
    impact_confidentiality  TEXT,
    impact_integrity        TEXT,
    cwe_code                TEXT,
    cwe_name                TEXT,
    pub_date                TIMESTAMPTZ,
    mod_date                TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_vulns_scan_id ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_cve_id ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_ip ON vulnerabilities(affected_device_ip);

-- Generated reports
CREATE TABLE reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id           UUID NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    template_id       TEXT NOT NULL,        -- "executive", "full", "chain", etc.
    raw_markdown      TEXT,                 -- final_report.md content
    -- Parsed sections (nullable; populated by markdown section parser)
    executive_summary TEXT,
    scope             TEXT,
    methodology       TEXT,
    key_findings      TEXT,
    recommendations   TEXT,
    -- Risk matrix counts (derived from vulnerabilities table)
    risk_critical     INT DEFAULT 0,
    risk_high         INT DEFAULT 0,
    risk_medium       INT DEFAULT 0,
    risk_low          INT DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Activity log (populated by parsing surge_log.log or direct API writes)
CREATE TABLE activity_events (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         UUID REFERENCES scans(scan_id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL
                    CHECK (event_type IN ('info', 'warning', 'critical', 'patch', 'exploit')),
    message         TEXT NOT NULL,
    detail          TEXT,
    ip              INET,
    agent_node      TEXT,                   -- which LangGraph node emitted this
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_events_scan_id ON activity_events(scan_id);
CREATE INDEX idx_events_created_at ON activity_events(created_at DESC);

-- Scan profiles (saved configurations from the UI)
CREATE TABLE scan_profiles (
    id              BIGSERIAL PRIMARY KEY,
    name            TEXT NOT NULL,
    target          TEXT NOT NULL,
    scan_type       TEXT NOT NULL
                    CHECK (scan_type IN ('quick', 'deep', 'stealth')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

**Schema notes:**
- `scans.run_dir` links the DB record to the filesystem output directory where `final_report.md`, `dashboard_data.json`, and `final_state_result.json` live. During the transition period you can read from files; eventually migrate to reading from DB.
- `vulnerabilities.cvss_score_predicted` maps to `vuln_scoring[n]["predicted_score"]` from `cvss_scoring.py`. `cvss_score_raw` is the `cvss` field from the `CVEEntry` (CIRCL data). Use `predicted_score` as the authoritative score for display.
- `devices.raw_services_json` stores the full `xml_parse` services list — enables future features (port history, service change detection) without schema migration.
- `activity_events.agent_node` lets you filter the activity feed by which LangGraph node generated the event.

---

## 7. Dashboard/Agent Capability Gap Summary

| Feature | Status | Decision |
|---|---|---|
| Device list (IP, severity, CVSS) | PRODUCIBLE | Agent already outputs `dashboard_data.json` |
| Hostname per device | BUILDABLE | `xml_parse` captures `hostnames[0]` — fix `dashboard_payload.py` |
| deviceType per device | BUILDABLE | `os_info.device_type` from OS fingerprint agent |
| Scan status (running/completed/failed) | BUILDABLE | Needs DB job tracking |
| Scan progress % | BUILDABLE | LangGraph node events → approximate % |
| CVE list with CVSS scores | PRODUCIBLE | `vuln_raw_results` + `vuln_scoring` |
| `exploit_availability` (Public/Private) | CUT | Agent has only `exploitable: bool`; simplify to "public" if true |
| `mitreAttack` technique | CUT | No MITRE mapping in agent — remove column from Exploits page |
| `exploitation_steps` / `exploitNotes` | CUT | No exploit agent exists |
| "Run Exploit" button | CUT | No exploit agent — make Exploits page read-only |
| `exploit_success_rate` stat card | CUT | Remove from `StatCards.tsx` |
| Activity feed | BUILDABLE | Parse `surge_log.log` + LangGraph node events |
| Vulnerability trends (daily) | DEFER | Needs multiple scan runs in DB; skip for now |
| Report generation from `final_report.md` | BUILDABLE | Parse `##` headings into sections |
| Report scheduling | CUT | No cron infrastructure; remove scheduled reports UI |
| Network topology graph | BUILDABLE | Feed `xml_parse` output as `NetworkTopology` |
| Avg CVSS stat | PRODUCIBLE | Mean of `predicted_scores` |
| Agents Active count | BUILDABLE | Count scans with `status="running"` in DB |

The Exploits page needs the most aggressive cutting — it is built around an exploit agent that does not exist. Reduce it to a read-only prioritized CVE table with CVSS scores and descriptions. That is still a strong capstone feature: the system identifies, scores, and ranks vulnerabilities automatically using a real ML model (XGBoost) trained on CVE data.
