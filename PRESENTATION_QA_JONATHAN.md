# Presentation Q&A — Jonathan (Frontend, Integration, Local LLM)

---

## Original Questions

**Why did we choose Next.js?**
Next.js gave us a React-based framework with a built-in dev server, file-based routing, and fast refresh out of the box. For a dashboard with multiple views (Dashboard, Scans, Topology, Exploits, Reports), the page/component model mapped naturally. It also has a large ecosystem and strong TypeScript support, which mattered since we knew we wanted typed code.

---

**Why did you choose this database? / What kind of database is it?**
We use SQLite — a lightweight, file-based relational database. There's no separate database server to run; it's just a `.db` file on disk. For a capstone with one machine and one active user at a time, that's the right call. It keeps setup to zero. The code is written with SQLAlchemy's async ORM, so swapping to PostgreSQL is a one-line `DATABASE_URL` change if we ever needed to scale.

---

**Why not use another framework for the frontend?**
The main alternatives were plain React (no routing/build tooling out of the box), Vue, or Svelte. Next.js gave us everything React offers plus structure we didn't have to invent ourselves. Vue and Svelte are solid but our team had more React familiarity, and the component ecosystem (shadcn/ui, D3 integrations) skewed React-heavy.

---

**Explain why we chose the models we did.**
We use two distinct "models" for different jobs. The local LLM drives the agent reasoning — summarizing scan results, writing the final report, making decisions inside the LangGraph graph. We chose it because it runs fully offline, which is a hard requirement for a network scanner that may be used on sensitive internal networks. The second model is XGBoost for CVSS scoring — a gradient-boosted tree trained on CVE features to predict a risk score. We chose XGBoost because it handles tabular numerical data well, trains fast, and is interpretable compared to a neural net.

---

**What language for the frontend? / Why TypeScript?**
TypeScript. It's a strict superset of JavaScript, so we get all of JS's flexibility but with compile-time type checking. In a project where the frontend is consuming a Python API, types are your safety net — if the backend changes a response shape, TypeScript will catch every broken callsite before it hits the browser. It also made the codebase easier to navigate as it grew.

---

**How exactly does the backend and frontend communicate with each other?**
Two mechanisms. First, REST — the frontend calls FastAPI endpoints (GET, POST) for things like fetching scans, starting a scan, or retrieving vulnerabilities. Second, WebSockets — when a scan is actively running, the frontend opens a WebSocket connection to `/scans/ws/{scan_id}` and receives real-time progress events as the agent graph executes. For live topology and vulnerability data during a scan, the frontend polls `GET /topology` every 5 seconds since that data is written to a JSON file incrementally by the agents.

---

**How does the force-directed D3 graph work?**
D3's force simulation models each network node (host) as a particle with physical forces applied to it. Nodes repel each other (charge force), edges between nodes act like springs pulling connected nodes together (link force), and a centering force keeps the whole graph from drifting off screen. On each animation tick, D3 recalculates positions and we update the SVG elements. Nodes are colored by CVE severity — we compute the worst CVE severity per IP from the vulnerabilities response and use that to color the node, because the severity field on the topology host itself can be stale.

---

## Frontend (UI/UX & Architecture)

**What state management approach did you use?**
We relied entirely on React's built-in `useState` and `useRef` hooks — no external state library like Redux or Zustand. The app is a single dashboard; state doesn't need to be shared across deeply nested unrelated trees. `useRef` was specifically useful for tracking previous values across renders (e.g., watching when `active_scans` drops from >0 to 0 to trigger the live→latest auto-switch).

---

**You poll every 5s for live data but also use WebSockets — why both?**
WebSockets are used for scan progress events — things like "Recon agent started" or "Scoring complete." Those are push events from the backend that don't have a predictable cadence. Polling is used for topology and vulnerability data because that data is written by agents to a file on disk, and we're reading it back via REST. A WebSocket would have required more backend plumbing to push file-change events; polling a REST endpoint was simpler and reliable enough at 5-second granularity.

---

**How do you handle partial data while a scan is still running?**
Every panel that depends on scan data has an explicit waiting state. Before `dashboard_data.json` is written by the scoring agent, the DeviceList shows "Waiting for scan data…", the VulnerabilityChart shows "Waiting for vulnerability scoring…", and topology nodes render as neutral grey instead of severity colors. Once the data arrives through polling, all panels populate progressively.

---

**What trade-offs did you consider between a SPA and a multi-page / server-rendered approach?**
A server-rendered approach would have made real-time updates harder — you'd be fighting against the page-reload model. Since the whole product is a live dashboard where data changes while you're looking at it, a SPA where we control all state and re-renders made more sense. The downside is a larger initial JS bundle, but for an internal tool that's not a concern.

---

**How did you structure your component hierarchy?**
Pages live in `_pages/` and own data fetching and state. Reusable display components live in `_components/` and receive data as props — they don't fetch anything themselves. That separation meant we could rewire data sources (switching from static mock data to live API) without touching the rendering logic.

---

**How do you prevent stale UI if the backend crashes mid-scan?**
Two things. On the backend, when the FastAPI server starts up, it finds any scans still marked `status='running'` from before the restart and marks them `failed` with an error message. So by the time the frontend reconnects, it gets accurate status. On the frontend, if polling fails or the WebSocket drops, the scan just stops showing live updates — the user sees the last known state and can manually refresh.

---

**What would you change about the frontend with more time?**
The main thing is replacing polling with server-sent events (SSE) for live data, which is cleaner than 5-second polling intervals. We'd also add proper authentication — right now any request reaches the API. And we'd push topology node severity coloring to the backend so the client isn't doing computation the server already has.

---

## Frontend ↔ Backend Communication

**Why FastAPI over Django REST Framework or Flask?**
FastAPI is async-native, which matters because our agent graph uses `asyncio`. Django is heavyweight and sync-first. Flask is lightweight but doesn't have built-in async support or automatic OpenAPI generation. FastAPI gave us async routes, Pydantic validation, and auto-generated docs with minimal boilerplate — exactly what we needed for a thin API layer over an existing Python codebase.

---

**How does the frontend detect that a scan has finished?**
The WebSocket connection sends node events as the graph executes. When the graph finishes, the connection closes from the server side, which the frontend detects as a close event. Separately, the Dashboard polls `GET /dashboard/stats` and watches the `active_scans` count. When it drops from >0 to 0, the dashboard automatically switches from live mode to latest mode.

---

**What happens if the server restarts mid-scan?**
The scan state is persisted to SQLite, so the record survives. On startup, the lifespan handler in `api/main.py` runs a cleanup pass — any scan still marked `running` gets flipped to `failed` with the message "Interrupted — server restarted." The frontend will see that on its next poll and update accordingly. We don't attempt to resume scans — the user would need to start a new one.

---

**How did you handle type safety across the TypeScript and Python boundary?**
We defined Pydantic models in Python for every request and response, and mirrored those as TypeScript interfaces in `src/lib/api.ts`. It's manual synchronization — if someone changes a Pydantic model without updating the TypeScript type, nothing breaks at compile time. In a larger project you'd use `openapi-typescript` to auto-generate the TS types from the FastAPI OpenAPI schema, which would close that gap entirely.

---

**Why separate repos instead of a monorepo?**
Python and TypeScript can't share a runtime. A monorepo would have added tooling overhead (Turborepo, Nx, or equivalent) for essentially zero benefit given our team size and timeline. The `surge-ai` repo already had clean module boundaries; adding an `api/` folder was purely additive. The repos communicate over HTTP, which is a stable interface.

---

**How does CORS work and what changes for production?**
CORS is a browser security mechanism that blocks a page on one origin from calling an API on a different origin unless the server explicitly allows it. Right now we use `allow_origins=["*"]`, which permits any origin — necessary in dev because the Next.js dev server runs on port 3000 and the API is on port 8000. For production we'd set `CORS_ORIGINS=https://our-actual-domain.com` and the FastAPI middleware would only allow that exact origin.

---

## Local LLM Setup

**Why run the LLM locally instead of a hosted API?**
Network security tools operate on sensitive data — scan results contain IP addresses, OS fingerprints, CVE exposures, and network topology. Sending that to a third-party cloud API is a non-starter in most real security environments. Running locally means the data never leaves the machine. It also eliminates API costs and rate limits, and the tool works air-gapped.

---

**What are the hardware requirements?**
It depends on the model size. A smaller quantized model (7B–13B parameters running via Ollama or llama.cpp) runs on a machine with 16GB RAM and no GPU required, just slower. For the report generation quality we wanted, a GPU speeds things up significantly. For enterprise deployment this is a real constraint — it's one of the known trade-offs of going local.

---

**How does LangGraph orchestrate the multi-agent graph?**
LangGraph treats the agent pipeline as a directed graph where each node is a function (agent) that reads from and writes to a shared `AgentState` object. Nodes are connected by edges; conditional edges let you branch. Our graph runs: recon → recon analyzer + OS finder (in parallel) → OS analyzer → vulnerability lookup → CVSS data formatter → CVSS scoring → reporter → END. If a node raises an exception, LangGraph surfaces it and the graph stops — the scan gets marked failed.

---

**How did you decide where to draw the agent boundaries?**
Each agent boundary corresponds to a meaningful data transformation where the output is consumed by multiple downstream agents or where the computation is expensive enough that isolation matters. For example, recon produces raw nmap data; the analyzer interprets it. Separating them means we can test and debug the analysis step independently of the actual network scan. It also mirrors how a real security team would divide the work.

---

**How does XGBoost CVSS scoring differ from just using the raw CVSS score?**
The official CVSS score is a static, manually-assigned severity rating based on the vulnerability's characteristics at time of publication. It doesn't account for your specific environment — whether the affected service is exposed, what OS it's running on, or whether the host is internet-facing. Our XGBoost model takes contextual features from the scan results and produces a score tuned to the actual deployment. A CVE rated 7.5 on a host with no network path to it is less critical than a 6.0 on your public-facing server.

---

**What data did you train on and how did you evaluate it?**
We trained on a labeled dataset of CVE records using CVSS base metrics (attack vector, complexity, privileges required, etc.) as features. Evaluation was cross-validation on held-out CVEs, comparing predicted severity buckets to the published NVD severity. The goal wasn't to beat NVD's scores — it was to produce a contextual re-ranking that helps a security analyst prioritize remediation for their specific network.

---

## Security & Ethics

**What prevents unauthorized scanning?**
Right now, nothing — the API has no authentication. That's an acknowledged gap appropriate for a local capstone demo. In a real deployment you'd wrap every endpoint in JWT or session auth, and ideally require the user to prove ownership of the target network before a scan is allowed.

---

**How current is your CVE data?**
We pull CVE data from the CIRCL CVE API at scan time, so it's as current as CIRCL's mirror of NVD, which is typically within 24 hours of publication. There's no local CVE cache that gets stale. The lag is CIRCL's ingestion delay, not ours.

---

**What auth would a real enterprise deployment need?**
At minimum: user authentication (login), role-based access control (admins can start scans, viewers can only read results), and audit logging of who ran what scan against what target. For a regulated environment you'd also need MFA, session expiry, and an approval workflow before a scan against a production subnet is allowed.

---

**Legal implications and safeguards?**
Running a network scanner against a network you don't own or have written permission to scan is illegal in most jurisdictions under computer fraud laws. The tool has no built-in scope enforcement, which means deployment requires organizational policy controls. In a real product you'd add a terms-of-use acknowledgment at scan creation and potentially block ranges outside the user's registered subnets.

---

## Scalability & Production Readiness

**What needs to change to move from SQLite to a production database?**
One environment variable: `DATABASE_URL=postgresql+asyncpg://user:pass@host/db`. SQLAlchemy's async ORM abstracts the dialect. You'd also run Alembic migrations instead of the startup `ALTER TABLE` we use to add columns. The rest of the code is unchanged.

---

**What are the performance bottlenecks?**
The scan itself — nmap on a large CIDR range is slow and we can't parallelize it beyond what nmap does internally. Deep scan mode runs full port enumeration, which can take many minutes. CVE lookups are network-bound (one API call per discovered service). CVSS scoring with XGBoost is fast. Report generation via LLM is the second-slowest step. The frontend has no bottlenecks — it's just polling REST endpoints.

---

**Containerization and nmap in Docker — what are the gotchas?**
The main gotcha is that nmap SYN scans require raw socket access, which Docker doesn't give containers by default. You need to add `cap_add: NET_RAW` and `cap_add: NET_ADMIN` to the Docker Compose service definition. Without those, nmap falls back to TCP connect scans, which are detectable and slower. You'd run two containers — one for the FastAPI/agents (with elevated capabilities) and one for the Next.js frontend.
